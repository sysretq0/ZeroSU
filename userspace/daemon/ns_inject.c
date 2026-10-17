// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - userspace/daemon/ns_inject.c
 *
 * Enter a target process's mount namespace, mount a read-only /system/bin
 * overlay whose upperdir holds the per-uid su stub, and get out again.
 *
 * The daemon is single threaded and never forks, so "enter someone else's
 * namespace" is safe: there is no second thread whose view of the world can
 * be disturbed, and no child that could inherit a half-modified namespace.
 *
 * unshare(CLONE_FS) - and only CLONE_FS - is taken once at init. That gives
 * this process a private fs_struct, so the root/cwd rewrites that setns() and
 * chdir() perform while we sit inside an app's namespace cannot leak back to
 * the init mount namespace. CLONE_NEWNS is never passed to unshare(): that
 * would create a brand new namespace, and the overlay has to land in the
 * app's, not in a fresh one.
 *
 * Only /system/bin is ever made private; "/" never is. Making / private would
 * detach the app's entire mount tree and the overlay would stop being a
 * surgical change.
 */


#include "zsu_daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/mount.h>

/* The init mount namespace, pinned before any setns() can move us. */
static int init_mnt_fd = -1;
static bool ns_initialized;

int ns_inject_init(void)
{
	int fd;

	if (ns_initialized)
		return 0;

	if (unshare(CLONE_FS)) {
		zsu_warn("unshare(CLONE_FS): %s", strerror(errno));
		return -errno;
	}

	/*
	 * Opened after the CLONE_FS unshare but before any setns(), so it is a
	 * handle on the init mount namespace. It is used to restore ourselves
	 * after each injection.
	 */
	fd = open("/proc/self/ns/mnt", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		zsu_warn("open /proc/self/ns/mnt: %s", strerror(errno));
		return -errno;
	}

	init_mnt_fd = fd;
	ns_initialized = true;
	return 0;
}

/*
 * @pid_dirfd is the pinned /proc/<pid> directory. Pinning it is what makes
 * the namespace entry race-free: the mount namespace cannot be swapped out
 * from under openat(dirfd, "ns/mnt") because dirfd holds the task's /proc
 * entry alive, and the caller has already checked its st_uid.
 */
int ns_inject(int pid_dirfd, uid_t uid)
{
	char upper[ZSU_PATH_MAX];
	char work[ZSU_PATH_MAX];
	/* "lowerdir=/system/bin,upperdir=,workdir=" plus two paths. */
	char opts[2 * ZSU_PATH_MAX + 64];
	int mnt_fd = -1;
	int rc = 0;
	bool entered = false;

	if (!ns_initialized) {
		zsu_warn("ns_inject: called before ns_inject_init()");
		return -EINVAL;
	}
	if (pid_dirfd < 0)
		return -EINVAL;

	/* 1. The mount namespace fd, through the pinned /proc directory. */
	mnt_fd = openat(pid_dirfd, "ns/mnt", O_RDONLY | O_CLOEXEC);
	if (mnt_fd < 0) {
		rc = -errno;
		goto out;
	}

	/* 2. Enter it. setns() resets root and cwd into the new namespace. */
	if (setns(mnt_fd, CLONE_NEWNS)) {
		rc = -errno;
		goto out;
	}
	entered = true;

	/* 3. Make ONLY /system/bin private: bind it to itself, then detach it
	 *    from any shared peer group so the overlay below cannot propagate
	 *    to another process sharing the same mount. */
	if (mount("/system/bin", "/system/bin", NULL, MS_BIND, NULL)) {
		rc = -errno;
		goto out;
	}
	if (mount(NULL, "/system/bin", NULL, MS_PRIVATE, NULL)) {
		rc = -errno;
		goto out;
	}

	/* 4. The overlay: stock /system/bin as the lower layer, the uid's
	 *    upper/work tree as the writable layers. */
	rc = policy_upper_path(uid, upper, sizeof(upper));
	if (rc)
		goto out;
	rc = policy_work_path(uid, work, sizeof(work));
	if (rc)
		goto out;

	snprintf(opts, sizeof(opts),
		 "lowerdir=/system/bin,upperdir=%s,workdir=%s", upper, work);

	/*
	 * MS_RDONLY: the app sees an immutable stub, never a writable overlay.
	 * EBUSY means the overlay is already on this mount point in this
	 * namespace, i.e. a previous injection landed - success, not failure.
	 */
	if (mount("overlay", "/system/bin", "overlay", MS_RDONLY, opts)) {
		if (errno != EBUSY)
			rc = -errno;
	}

out:
	/*
	 * Single exit: if we entered at all, always come back to the init
	 * mount namespace and re-root at "/". A failure here is logged but
	 * cannot be repaired, so it does not change rc.
	 */
	if (entered) {
		if (setns(init_mnt_fd, CLONE_NEWNS))
			zsu_warn("restore init mnt ns: %s", strerror(errno));
		if (chdir("/"))
			zsu_warn("chdir /: %s", strerror(errno));
	}
	if (mnt_fd >= 0)
		close(mnt_fd);
	return rc;
}
