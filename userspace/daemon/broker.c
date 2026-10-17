// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - userspace/daemon/broker.c
 *
 * Three jobs, all on the daemon's single thread:
 *
 *   1. the ctl.sock control server. zsu_ctl is the only client; the socket is
 *      0660 root:shell and labelled shell_data_file, so it is reachable by
 *      adb shell but not by untrusted apps.
 *
 *   2. the doorbell. When a granted app execs /system/bin/su, the stub inside
 *      it rings by opening its own binary; the inotify watch on the per-uid
 *      upper/su file carries the uid, and this file resolves that uid to live
 *      pids through /sys/fs/cgroup/uid_<uid> - never through /proc.
 *
 *   3. hot injection, used by `allow` for processes that are already running
 *      when the grant lands. Same cgroup index, same pinned-and-fstat'd
 *      /proc/<pid>, same ns_inject.
 *
 * The elevation carried on the doorbell is the kernel-side identity check:
 * the request magic proves the stub is real, /proc/<pid>/stat field 22 gives
 * the start-time token, and ELEVATE_TASK refuses if the pid was recycled.
 */


#include "zsu_daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#ifndef SO_PEERCRED
#define SO_PEERCRED 17
#endif

static int listen_fd = -1;

/* ------------------------------------------------------------------ */
/* control socket                                                      */
/* ------------------------------------------------------------------ */

/*
 * The socket inode has to be reachable and connectable by uid 2000. That is
 * arranged twice over: the fscreate context makes the inode shell_data_file
 * (which the shell domain may connect to), and the 0660 root:shell mode stops
 * everyone else. Both /data/adb and /data/adb/zerosu are 0711 so the path can
 * be traversed. Every step is best-effort: if the context write is denied the
 * daemon still runs, and the mode check remains.
 */
static void set_create_contexts(char *sock_save, size_t sock_len,
				char *fs_save, size_t fs_len)
{
	int n;

	sock_save[0] = '\0';
	fs_save[0] = '\0';

	n = zsu_read_attr("sockcreate", sock_save, sock_len);
	if (n < 0)
		sock_save[0] = '\0';
	n = zsu_read_attr("fscreate", fs_save, fs_len);
	if (n < 0)
		fs_save[0] = '\0';

	if (zsu_write_attr("sockcreate", "u:r:shell:s0"))
		zsu_warn("sockcreate: %s", strerror(errno));
	if (zsu_write_attr("fscreate", "u:object_r:shell_data_file:s0"))
		zsu_warn("fscreate: %s", strerror(errno));
}

static void restore_create_contexts(const char *sock_save,
				    const char *fs_save)
{
	if (zsu_write_attr("sockcreate", sock_save))
		zsu_warn("sockcreate restore");
	if (zsu_write_attr("fscreate", fs_save))
		zsu_warn("fscreate restore");
}

int broker_init(void)
{
	struct sockaddr_un sa;
	char sock_save[128], fs_save[128];
	gid_t shell_gid = 2000;
	struct group *gr;

	gr = getgrnam("shell");
	if (gr)
		shell_gid = gr->gr_gid;

	set_create_contexts(sock_save, sizeof(sock_save), fs_save,
			    sizeof(fs_save));

	unlink(ZSU_CTL_SOCK);

	listen_fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC,
			   0);
	if (listen_fd < 0) {
		zsu_warn("ctl socket: %s", strerror(errno));
		restore_create_contexts(sock_save, fs_save);
		return -errno;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	if (strlen(ZSU_CTL_SOCK) >= sizeof(sa.sun_path)) {
		close(listen_fd);
		listen_fd = -1;
		restore_create_contexts(sock_save, fs_save);
		return -ENAMETOOLONG;
	}
	strcpy(sa.sun_path, ZSU_CTL_SOCK);

	if (bind(listen_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int e = errno;

		close(listen_fd);
		listen_fd = -1;
		restore_create_contexts(sock_save, fs_save);
		return -e;
	}

	restore_create_contexts(sock_save, fs_save);

	if (chmod(ZSU_CTL_SOCK, 0660))
		zsu_warn("chmod ctl.sock: %s", strerror(errno));
	if (chown(ZSU_CTL_SOCK, 0, shell_gid))
		zsu_warn("chown ctl.sock: %s", strerror(errno));

	if (listen(listen_fd, 8) < 0) {
		int e = errno;

		close(listen_fd);
		listen_fd = -1;
		return -e;
	}

	zsu_log("ctl.sock ready (mode 0660 root:%u)", (unsigned)shell_gid);
	return 0;
}

int broker_listen_fd(void)
{
	return listen_fd;
}

int broker_accept(void)
{
	int fd = accept4(listen_fd, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);

	return fd < 0 ? -errno : fd;
}

static void reply_err(struct zsu_ctl_resp *r, int err, const char *msg)
{
	r->status = err;
	snprintf(r->msg, sizeof(r->msg), "%s", msg);
}

static int resolve_target(const struct zsu_ctl_req *req, uid_t *uid)
{
	if (req->pkg[0])
		return policy_pkg_uid(req->pkg, 0, uid);
	*uid = (uid_t)req->uid;
	return *uid ? 0 : -EINVAL;
}

static void handle_status(struct zsu_ctl_resp *r)
{
	int fd, rc;

	snprintf(r->msg, sizeof(r->msg),
		 "zerosud pid=%d abi=%d packages=%zu grants=%zu",
		 (int)getpid(), ZSU_ABI_VERSION, policy_pkg_count(),
		 policy_allowed_count());

	fd = session_su_fd();
	if (fd >= 0) {
		uint32_t abi = 0;

		rc = session_ping(fd, &abi);
		if (!rc)
			r->data = abi;
	}
}

struct list_ctx {
	struct zsu_ctl_resp *r;
	size_t off;
	uint32_t n;
};

static int list_cb(uid_t uid, void *arg)
{
	struct list_ctx *c = arg;

	if (c->off < sizeof(c->r->msg) - 16)
		c->off += (size_t)snprintf(c->r->msg + c->off,
					   sizeof(c->r->msg) - c->off,
					   "%u\n", (unsigned)uid);
	c->n++;
	return 0;
}

static void handle_list(struct zsu_ctl_resp *r)
{
	struct list_ctx c = { r, 0, 0 };

	r->msg[0] = '\0';
	policy_foreach_allowed(list_cb, &c);
	r->status = 0;
	r->count = c.n;
}

int broker_handle(int cfd)
{
	struct zsu_ctl_req req;
	struct zsu_ctl_resp resp;
	struct ucred cred;
	struct pollfd pfd;
	socklen_t clen = sizeof(cred);
	ssize_t n;
	uid_t uid;
	int rc = 0;

	memset(&req, 0, sizeof(req));
	memset(&resp, 0, sizeof(resp));

	/*
	 * The accepted socket is non-blocking, and a listening AF_UNIX socket
	 * becomes readable when connect() completes - possibly before the
	 * client's send() has run. Poll so that window cannot turn a valid
	 * request into a spurious -EINVAL.
	 */
	pfd.fd = cfd;
	pfd.events = POLLIN;
	if (poll(&pfd, 1, 2000) <= 0) {
		reply_err(&resp, -ETIMEDOUT, "no request");
		goto send;
	}

	n = recv(cfd, &req, sizeof(req), 0);
	if (n < (ssize_t)offsetof(struct zsu_ctl_req, pkg)) {
		reply_err(&resp, n < 0 ? -errno : -EINVAL, "malformed request");
		goto send;
	}
	/*
	 * The request is untrusted. A full-size datagram may leave pkg[]
	 * without a NUL, so terminate it before any string function sees it.
	 */
	req.pkg[sizeof(req.pkg) - 1] = '\0';
	if (req.flags != 0) {
		reply_err(&resp, -EINVAL, "reserved flags must be zero");
		goto send;
	}
	if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &clen)) {
		reply_err(&resp, -errno, "peer credentials unavailable");
		goto send;
	}

	switch (req.op) {
	case ZSU_CTL_PING:
		resp.status = 0;
		resp.data = ZSU_ABI_VERSION;
		snprintf(resp.msg, sizeof(resp.msg), "pong abi=%d", ZSU_ABI_VERSION);
		break;

	case ZSU_CTL_STATUS:
		handle_status(&resp);
		break;

	case ZSU_CTL_ALLOW:
		rc = resolve_target(&req, &uid);
		if (rc) {
			reply_err(&resp, rc, "cannot resolve package/uid");
			break;
		}
		rc = policy_allow_uid(uid);
		if (rc) {
			reply_err(&resp, rc, "allow failed");
			break;
		}
		resp.status = 0;
		resp.uid = (uint32_t)uid;
		/* Inject into whatever already runs as this uid. */
		broker_hot_inject(uid);
		snprintf(resp.msg, sizeof(resp.msg), "allowed uid %u",
			 (unsigned)uid);
		break;

	case ZSU_CTL_REVOKE:
		rc = resolve_target(&req, &uid);
		if (rc) {
			reply_err(&resp, rc, "cannot resolve package/uid");
			break;
		}
		rc = policy_revoke_uid(uid);
		resp.status = rc;
		resp.uid = (uint32_t)uid;
		snprintf(resp.msg, sizeof(resp.msg),
			 rc ? "revoke: no such grant" : "revoked uid %u",
			 (unsigned)uid);
		break;

	case ZSU_CTL_LIST:
		handle_list(&resp);
		break;

	case ZSU_CTL_SHELL:
		/*
		 * The caller may only elevate itself: the pid must be the one
		 * SO_PEERCRED reports. The start-time token is then read from
		 * the live task's own /proc entry rather than trusted from the
		 * request, so a recycled pid cannot be substituted.
		 */
		if (req.pid == 0 || (pid_t)req.pid != cred.pid) {
			reply_err(&resp, -EPERM, "shell: pid must be your own");
			break;
		}
		{
			bool ok = false;

			/* The boolean is the verdict; the errno is only context. */
			(void)session_verify_plain(req.key, &ok);
			if (!ok) {
				reply_err(&resp, -EACCES, "shell: bad SuperKey");
				break;
			}
		}
		{
			char dir[64];
			struct stat st;
			uint64_t start;
			int dfd;

			snprintf(dir, sizeof(dir), "/proc/%d", (int)cred.pid);
			dfd = open(dir, O_DIRECTORY | O_CLOEXEC);
			if (dfd < 0) {
				reply_err(&resp, -errno, "shell: no such process");
				break;
			}
			/*
			 * Pin the task's /proc entry and confirm it still belongs
			 * to the peer. A pid recycled between SO_PEERCRED and here
			 * would otherwise let the caller elevate a stranger; the
			 * start-time token closes whatever race remains.
			 */
			if (fstat(dfd, &st) || (uid_t)st.st_uid != cred.uid) {
				close(dfd);
				reply_err(&resp, -EPERM, "shell: process changed");
				break;
			}
			rc = zsu_proc_start_time_fd(dfd, &start);
			close(dfd);
			if (rc) {
				reply_err(&resp, rc, "shell: no such process");
				break;
			}
			rc = session_elevate_task(cred.pid, start);
			if (rc) {
				reply_err(&resp, rc, "shell: elevate failed");
				break;
			}
		}
		resp.status = 0;
		resp.uid = 0;
		snprintf(resp.msg, sizeof(resp.msg), "OK");
		break;

	default:
		reply_err(&resp, -EINVAL, "unknown op");
		break;
	}

send:
	if (send(cfd, &resp, sizeof(resp), 0) < 0)
		zsu_warn("ctl reply: %s", strerror(errno));
	return 0;
}

void broker_close(int cfd)
{
	if (cfd >= 0)
		close(cfd);
}

/* ------------------------------------------------------------------ */
/* doorbell                                                            */
/* ------------------------------------------------------------------ */

static int doorbell_cb(pid_t pid, void *arg)
{
	uid_t uid = *(uid_t *)arg;
	char path[64];
	struct stat st;
	uint64_t start;
	char magic[ZSU_STUB_REQ_MAGIC_LEN];
	int dfd, fd, rc;
	ssize_t r;

	snprintf(path, sizeof(path), "/proc/%d", (int)pid);
	dfd = open(path, O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		return 0;

	if (fstat(dfd, &st) || (uid_t)st.st_uid != uid) {
		close(dfd);
		return 0;
	}

	/* fd/3 is the stub's request pipe read end. */
	fd = openat(dfd, "fd/3", O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0) {
		close(dfd);
		return 0;
	}
	r = read(fd, magic, sizeof(magic));
	close(fd);
	if (r != (ssize_t)sizeof(magic) ||
	    memcmp(magic, ZSU_STUB_REQ_MAGIC, sizeof(magic))) {
		close(dfd);
		return 0;
	}

	if (zsu_proc_start_time_fd(dfd, &start)) {
		close(dfd);
		return 0;
	}

	rc = session_elevate_task(pid, start);
	if (rc) {
		if (zsu_verbose)
			zsu_warn("doorbell elevate pid %d: %d", (int)pid, rc);
		close(dfd);
		return 0;
	}

	/* fd/5 is the stub's ack pipe write end; the stub reads fd/4. */
	fd = openat(dfd, "fd/5", O_WRONLY | O_NONBLOCK | O_CLOEXEC);
	if (fd >= 0) {
		const uint8_t ack = ZSU_RDV_OK;

		(void)zsu_write_all(fd, &ack, 1);
		close(fd);
	}

	if (zsu_verbose)
		zsu_log("doorbell: elevated pid %d uid %u", (int)pid,
			(unsigned)uid);
	close(dfd);
	return 0;
}

int broker_doorbell(uid_t uid)
{
	return zsu_cgroup_for_each_pid(uid, doorbell_cb, &uid);
}

/* ------------------------------------------------------------------ */
/* hot injection                                                       */
/* ------------------------------------------------------------------ */

static int inject_cb(pid_t pid, void *arg)
{
	uid_t uid = *(uid_t *)arg;
	char path[64];
	struct stat st;
	int dfd;

	snprintf(path, sizeof(path), "/proc/%d", (int)pid);
	dfd = open(path, O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		return 0;
	if (fstat(dfd, &st) || (uid_t)st.st_uid != uid) {
		close(dfd);
		return 0;
	}
	(void)ns_inject(dfd, uid);
	close(dfd);
	return 0;
}

int broker_hot_inject(uid_t uid)
{
	return zsu_cgroup_for_each_pid(uid, inject_cb, &uid);
}
