// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - userspace/daemon/policy.c
 *
 * Everything the grant hot path needs, kept in RAM and kept square:
 *
 *   - a packages.list hash table (name -> uid), rebuilt whenever the file
 *     changes, so am_proc_bound can turn a process name into a uid with no
 *     disk access and no /proc walk;
 *   - the allowed-UID bitmap, the only authority the monitor consults before
 *     it makes a single syscall;
 *   - the per-uid staging directory tree (upper/work + the su stub), with the
 *     SELinux labels the overlay needs;
 *   - a single inotify fd carrying both the packages.list watch and one
 *     doorbell watch per granted uid, keyed by watch descriptor in O(1).
 *
 * Grants survive a daemon restart through a plain uid list in
 * /data/adb/zerosu/grants. That file is not a secret and is not a key; it is
 * just the answer to "which uids were granted", and the ZSU_UIDS_DIR it
 * points at is 0700 root:root.
 */


#include "zsu_daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------ */
/* tables                                                              */
/* ------------------------------------------------------------------ */

#define ZSU_LOAD_NUM	7
#define ZSU_LOAD_DEN	10

struct pkg_ent {
	char     name[ZSU_PKG_MAX];
	uint32_t uid;
	bool     used;
};

struct uid_ent {
	uint32_t uid;
	bool     used;
};

struct wd_ent {
	int      wd;
	uint32_t uid;
	bool     used;
};

static struct pkg_ent *pkg_tab;
static size_t pkg_cap, pkg_count;

static struct uid_ent *uid_tab;
static size_t uid_cap, uid_count;

static struct wd_ent *wd_tab;
static size_t wd_cap, wd_count;

static int inotify_fd = -1;
static int package_wd = -1;

static uint32_t hash_str(const char *s)
{
	uint32_t h = 2166136261u;

	while (*s) {
		h ^= (uint8_t)*s++;
		h *= 16777619u;
	}
	return h;
}

static uint32_t hash_u32(uint32_t v)
{
	v ^= v >> 16;
	v *= 0x7feb352du;
	v ^= v >> 15;
	v *= 0x846ca68bu;
	v ^= v >> 16;
	return v;
}

/* ------------------------------------------------------------------ */
/* package table                                                       */
/* ------------------------------------------------------------------ */

static void pkg_rehash(size_t cap)
{
	struct pkg_ent *old = pkg_tab;
	size_t old_cap = pkg_cap;
	size_t i;

	pkg_tab = calloc(cap, sizeof(*pkg_tab));
	if (!pkg_tab) {
		pkg_tab = old;
		return;
	}
	pkg_cap = cap;
	pkg_count = 0;

	for (i = 0; i < old_cap; i++) {
		if (old && old[i].used) {
			size_t j = hash_str(old[i].name) & (cap - 1);

			while (pkg_tab[j].used)
				j = (j + 1) & (cap - 1);
			pkg_tab[j] = old[i];
			pkg_count++;
		}
	}
	free(old);
}

static void pkg_insert(const char *name, uint32_t uid)
{
	size_t j;

	if (!pkg_tab)
		pkg_rehash(4096);
	if (!pkg_tab)
		return;

	if ((pkg_count + 1) * ZSU_LOAD_DEN >= pkg_cap * ZSU_LOAD_NUM)
		pkg_rehash(pkg_cap * 2);

	j = hash_str(name) & (pkg_cap - 1);
	while (pkg_tab[j].used && strcmp(pkg_tab[j].name, name))
		j = (j + 1) & (pkg_cap - 1);

	if (!pkg_tab[j].used) {
		snprintf(pkg_tab[j].name, sizeof(pkg_tab[j].name), "%s", name);
		pkg_tab[j].used = true;
		pkg_count++;
	}
	pkg_tab[j].uid = uid;
}

static struct pkg_ent *pkg_lookup(const char *name)
{
	size_t j;

	if (!pkg_tab)
		return NULL;
	j = hash_str(name) & (pkg_cap - 1);
	while (pkg_tab[j].used) {
		if (!strcmp(pkg_tab[j].name, name))
			return &pkg_tab[j];
		j = (j + 1) & (pkg_cap - 1);
	}
	return NULL;
}

int policy_pkg_appid(const char *pkg, uint32_t *appid)
{
	struct pkg_ent *e = pkg_lookup(pkg);

	if (!e)
		return -ENOENT;
	*appid = e->uid % 100000u;
	return 0;
}

int policy_pkg_uid(const char *pkg, uint32_t user, uid_t *uid)
{
	struct pkg_ent *e = pkg_lookup(pkg);
	uint64_t v;

	if (!e)
		return -ENOENT;
	v = (uint64_t)user * 100000u + (e->uid % 100000u);
	if (v > 0xffffffffu)
		return -ERANGE;
	*uid = (uid_t)v;
	return 0;
}

size_t policy_pkg_count(void)
{
	return pkg_count;
}

/*
 * Rebuild the table from /data/system/packages.list. Line format:
 *
 *   <package> <uid> <debuggable> <dataDir> <seinfo> <gids...>
 *
 * Only the first two fields matter. A partial read is not an error: the file
 * is rewritten in place by PackageManager, and a torn generation is corrected
 * by the next inotify event.
 */
int policy_refresh_packages(void)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	int seen = 0;

	f = fopen(ZSU_PACKAGES_LIST, "re");
	if (!f)
		return -errno;

	/*
	 * A refresh is a full replacement, not a merge: a revoked package must
	 * not survive in the table just because its name was not re-inserted.
	 */
	free(pkg_tab);
	pkg_tab = NULL;
	pkg_cap = 0;
	pkg_count = 0;

	for (;;) {
		char *save = NULL;
		char *name, *uid, *end;
		unsigned long v;

		if (getline(&line, &cap, f) <= 0)
			break;
		name = strtok_r(line, " \t\n", &save);
		uid = strtok_r(NULL, " \t\n", &save);
		if (!name || !uid)
			continue;
		errno = 0;
		v = strtoul(uid, &end, 10);
		if (end == uid || errno || v == 0 || v > 0xfffffffful ||
		    uid[0] == '-')
			continue;
		pkg_insert(name, (uint32_t)v);
		seen++;
	}

	free(line);
	fclose(f);
	zsu_log("packages.list: %d entries, %zu in table", seen, pkg_count);
	return 0;
}

/* ------------------------------------------------------------------ */
/* allowed-uid bitmap                                                  */
/* ------------------------------------------------------------------ */

static void uid_rehash(size_t cap)
{
	struct uid_ent *old = uid_tab;
	size_t old_cap = uid_cap;
	size_t i;

	uid_tab = calloc(cap, sizeof(*uid_tab));
	if (!uid_tab) {
		uid_tab = old;
		return;
	}
	uid_cap = cap;
	uid_count = 0;

	for (i = 0; i < old_cap; i++) {
		if (old && old[i].used) {
			size_t j = hash_u32(old[i].uid) & (cap - 1);

			while (uid_tab[j].used)
				j = (j + 1) & (cap - 1);
			uid_tab[j] = old[i];
			uid_count++;
		}
	}
	free(old);
}

int policy_uid_allowed(uid_t uid)
{
	size_t j;

	if (!uid_tab)
		return 0;
	j = hash_u32((uint32_t)uid) & (uid_cap - 1);
	while (uid_tab[j].used) {
		if (uid_tab[j].uid == (uint32_t)uid)
			return 1;
		j = (j + 1) & (uid_cap - 1);
	}
	return 0;
}

static void uid_insert(uid_t uid)
{
	size_t j;

	if (!uid_tab)
		uid_rehash(64);
	if (!uid_tab)
		return;
	if ((uid_count + 1) * ZSU_LOAD_DEN >= uid_cap * ZSU_LOAD_NUM)
		uid_rehash(uid_cap * 2);

	j = hash_u32((uint32_t)uid) & (uid_cap - 1);
	while (uid_tab[j].used && uid_tab[j].uid != (uint32_t)uid)
		j = (j + 1) & (uid_cap - 1);
	if (!uid_tab[j].used) {
		uid_tab[j].uid = (uint32_t)uid;
		uid_tab[j].used = true;
		uid_count++;
	}
}

static void uid_remove(uid_t uid)
{
	uint32_t *keep;
	size_t keep_n = 0, i, cap;

	if (!uid_tab || !policy_uid_allowed(uid))
		return;

	/*
	 * Open addressing means a cleared slot cannot simply be marked dead:
	 * later members of the same probe chain would become unreachable. The
	 * uid set is tiny, so rebuild it from the surviving entries.
	 */
	cap = uid_cap;
	keep = malloc(cap * sizeof(*keep));
	if (!keep) {
		size_t j = hash_u32((uint32_t)uid) & (cap - 1);

		while (uid_tab[j].used && uid_tab[j].uid != (uint32_t)uid)
			j = (j + 1) & (cap - 1);
		if (uid_tab[j].used) {
			uid_tab[j].used = false;
			uid_count--;
		}
		return;
	}

	for (i = 0; i < cap; i++)
		if (uid_tab[i].used && uid_tab[i].uid != (uint32_t)uid)
			keep[keep_n++] = uid_tab[i].uid;

	memset(uid_tab, 0, cap * sizeof(*uid_tab));
	uid_count = 0;
	for (i = 0; i < keep_n; i++)
		uid_insert((uid_t)keep[i]);
	free(keep);
}

size_t policy_allowed_count(void)
{
	return uid_count;
}

int policy_foreach_allowed(int (*cb)(uid_t, void *), void *arg)
{
	size_t i;

	for (i = 0; i < uid_cap; i++) {
		if (uid_tab[i].used) {
			int rc = cb((uid_t)uid_tab[i].uid, arg);

			if (rc)
				return rc;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* watch descriptor -> uid map                                         */
/* ------------------------------------------------------------------ */

static void wd_rehash(size_t cap)
{
	struct wd_ent *old = wd_tab;
	size_t old_cap = wd_cap;
	size_t i;

	wd_tab = calloc(cap, sizeof(*wd_tab));
	if (!wd_tab) {
		wd_tab = old;
		return;
	}
	wd_cap = cap;
	wd_count = 0;

	for (i = 0; i < old_cap; i++) {
		if (old && old[i].used) {
			size_t j = hash_u32((uint32_t)old[i].wd) & (cap - 1);

			while (wd_tab[j].used)
				j = (j + 1) & (cap - 1);
			wd_tab[j] = old[i];
			wd_count++;
		}
	}
	free(old);
}

static void wd_insert(int wd, uid_t uid)
{
	size_t j;

	if (!wd_tab)
		wd_rehash(64);
	if (!wd_tab)
		return;
	if ((wd_count + 1) * ZSU_LOAD_DEN >= wd_cap * ZSU_LOAD_NUM)
		wd_rehash(wd_cap * 2);

	j = hash_u32((uint32_t)wd) & (wd_cap - 1);
	while (wd_tab[j].used && wd_tab[j].wd != wd)
		j = (j + 1) & (wd_cap - 1);
	if (!wd_tab[j].used) {
		wd_tab[j].wd = wd;
		wd_tab[j].used = true;
		wd_count++;
	}
	wd_tab[j].uid = (uint32_t)uid;
}

static void wd_remove(int wd)
{
	struct wd_ent *keep;
	size_t keep_n = 0, i, cap;

	if (!wd_tab)
		return;

	/*
	 * Same reason as uid_remove(): open addressing means a cleared slot
	 * would orphan the rest of its probe chain. Rebuild instead.
	 */
	cap = wd_cap;
	keep = malloc(cap * sizeof(*keep));
	if (!keep) {
		size_t j = hash_u32((uint32_t)wd) & (cap - 1);

		while (wd_tab[j].used && wd_tab[j].wd != wd)
			j = (j + 1) & (cap - 1);
		if (wd_tab[j].used) {
			wd_tab[j].used = false;
			wd_count--;
		}
		return;
	}

	for (i = 0; i < cap; i++)
		if (wd_tab[i].used && wd_tab[i].wd != wd)
			keep[keep_n++] = wd_tab[i];

	memset(wd_tab, 0, cap * sizeof(*wd_tab));
	wd_count = 0;
	for (i = 0; i < keep_n; i++)
		wd_insert(keep[i].wd, (uid_t)keep[i].uid);
	free(keep);
}

int policy_doorbell_uid(int wd, uid_t *uid)
{
	size_t j;

	if (!wd_tab)
		return -ENOENT;
	j = hash_u32((uint32_t)wd) & (wd_cap - 1);
	while (wd_tab[j].used) {
		if (wd_tab[j].wd == wd) {
			*uid = (uid_t)wd_tab[j].uid;
			return 0;
		}
		j = (j + 1) & (wd_cap - 1);
	}
	return -ENOENT;
}

/* IN_IGNORED: the kernel dropped the watch (file replaced or unmounted). */
void policy_forget_wd(int wd)
{
	uid_t uid;

	/*
	 * IN_IGNORED can be the tail of our own revoke (inotify_rm_watch) or
	 * the kernel dropping a watch on its own. If the uid is still granted,
	 * re-arm it: the kernel may already have handed this same wd number to
	 * a re-allow, and merely removing it would leave a live grant with no
	 * doorbell (a fail-closed stall).
	 */
	if (policy_doorbell_uid(wd, &uid) == 0) {
		wd_remove(wd);
		if (policy_uid_allowed(uid))
			(void)policy_arm_doorbell(uid);
	}
}

/* ------------------------------------------------------------------ */
/* paths / staging                                                     */
/* ------------------------------------------------------------------ */

int policy_upper_path(uid_t uid, char *buf, size_t n)
{
	int r = snprintf(buf, n, ZSU_UIDS_DIR "/%u/upper", (unsigned)uid);

	return (r < 0 || (size_t)r >= n) ? -ENAMETOOLONG : 0;
}

int policy_work_path(uid_t uid, char *buf, size_t n)
{
	int r = snprintf(buf, n, ZSU_UIDS_DIR "/%u/work", (unsigned)uid);

	return (r < 0 || (size_t)r >= n) ? -ENAMETOOLONG : 0;
}

static int policy_stub_path(uid_t uid, char *buf, size_t n)
{
	int r = snprintf(buf, n, ZSU_UIDS_DIR "/%u/upper/su", (unsigned)uid);

	return (r < 0 || (size_t)r >= n) ? -ENAMETOOLONG : 0;
}

static int policy_uid_dir(uid_t uid, char *buf, size_t n)
{
	int r = snprintf(buf, n, ZSU_UIDS_DIR "/%u", (unsigned)uid);

	return (r < 0 || (size_t)r >= n) ? -ENAMETOOLONG : 0;
}

int policy_init_paths(void)
{
	int rc;

	/* /data/adb is 0700 on a stock device; adb shell needs to traverse it. */
	if (chmod("/data/adb", 0711) && errno != ENOENT)
		zsu_warn("/data/adb chmod 0711: %s", strerror(errno));

	rc = zsu_mkdir_p(ZSU_BASE_DIR, 0711);
	if (rc)
		return rc;
	rc = zsu_mkdir_p(ZSU_BIN_DIR, 0700);
	if (rc)
		return rc;
	rc = zsu_mkdir_p(ZSU_UIDS_DIR, 0700);
	if (rc)
		return rc;

	if (access(ZSU_STUB_BIN, X_OK))
		zsu_warn("stub template %s missing (install it 0700 root:root)",
			 ZSU_STUB_BIN);
	return 0;
}

/*
 * Build uids/<uid>/{upper,work} and drop the su stub into upper/su. The modes
 * are not cosmetic: upper is the overlay's writable layer and has to be
 * readable by the app's kernel mount, while work is scratch and stays 0700.
 * The labels are what actually let the app exec the stub under its own
 * SELinux domain.
 */
int policy_stage_uid(uid_t uid)
{
	char dir[ZSU_PATH_MAX], upper[ZSU_PATH_MAX], work[ZSU_PATH_MAX];
	char su[ZSU_PATH_MAX];
	int rc;

	rc = policy_uid_dir(uid, dir, sizeof(dir));
	if (rc)
		return rc;
	rc = policy_upper_path(uid, upper, sizeof(upper));
	if (rc)
		return rc;
	rc = policy_work_path(uid, work, sizeof(work));
	if (rc)
		return rc;
	rc = policy_stub_path(uid, su, sizeof(su));
	if (rc)
		return rc;

	rc = zsu_mkdir_p(dir, 0700);
	if (rc)
		return rc;
	rc = zsu_mkdir_p(upper, 0755);
	if (rc)
		return rc;
	rc = zsu_mkdir_p(work, 0700);
	if (rc)
		return rc;

	if (zsu_set_selinux_label(upper, "u:object_r:system_file:s0"))
		zsu_warn("label %s (continuing)", upper);

	/*
	 * Install the stub via a temp name + rename. Writing upper/su in place
	 * returns ETXTBSY while the stub is executing (re-staging a live grant)
	 * and a partial write would leave a truncated su. rename() is atomic and
	 * never disturbs the inode a running process already holds.
	 */
	{
		char tmp[ZSU_PATH_MAX];
		int n = snprintf(tmp, sizeof(tmp), "%s.tmp", su);

		if (n < 0 || (size_t)n >= sizeof(tmp))
			return -ENAMETOOLONG;

		rc = zsu_copy_file(ZSU_STUB_BIN, tmp, 0755);
		if (rc)
			return rc;

		if (chown(tmp, 0, 0))
			zsu_warn("chown %s: %s", tmp, strerror(errno));
		if (chmod(tmp, 0755)) {
			int e = errno;

			unlink(tmp);
			return -e;
		}
		if (zsu_set_selinux_label(tmp,
					  "u:object_r:system_linker_exec:s0"))
			zsu_warn("label %s (continuing)", tmp);
		if (rename(tmp, su)) {
			int e = errno;

			unlink(tmp);
			return -e;
		}
	}

	rc = policy_arm_doorbell(uid);
	if (rc)
		zsu_warn("doorbell watch for uid %u: %d", (unsigned)uid, rc);

	return 0;
}

int policy_arm_doorbell(uid_t uid)
{
	char su[ZSU_PATH_MAX];
	int rc, wd;

	if (inotify_fd < 0)
		return -EINVAL;
	rc = policy_stub_path(uid, su, sizeof(su));
	if (rc)
		return rc;

	/*
	 * IN_OPEN is the doorbell itself (the stub open()s its own binary
	 * before it has any other way to signal); IN_CLOSE_NOWRITE is the
	 * trailing close and is harmless if it fires too. wd -> uid is O(1).
	 */
	wd = inotify_add_watch(inotify_fd, su, IN_OPEN | IN_CLOSE_NOWRITE);
	if (wd < 0)
		return -errno;

	wd_insert(wd, uid);
	return 0;
}

void policy_disarm_doorbell(uid_t uid)
{
	size_t i;
	int wd = -1;

	if (inotify_fd < 0 || !wd_tab)
		return;
	for (i = 0; i < wd_cap; i++) {
		if (wd_tab[i].used && wd_tab[i].uid == (uint32_t)uid) {
			wd = wd_tab[i].wd;
			break;
		}
	}
	if (wd < 0)
		return;

	/* Collect first: wd_remove() rebuilds the table. */
	inotify_rm_watch(inotify_fd, wd);
	wd_remove(wd);
}

/* ------------------------------------------------------------------ */
/* grants persistence                                                  */
/* ------------------------------------------------------------------ */

static int policy_save_grants(void)
{
	char buf[16 * 4096];
	size_t off = 0;
	size_t i;

	for (i = 0; i < uid_cap && off < sizeof(buf) - 16; i++) {
		if (!uid_tab[i].used)
			continue;
		off += (size_t)snprintf(buf + off, sizeof(buf) - off, "%u\n",
					uid_tab[i].uid);
	}

	return zsu_write_file(ZSU_GRANTS_FILE, buf, off);
}

int policy_load_grants(void)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;

	f = fopen(ZSU_GRANTS_FILE, "re");
	if (!f)
		return 0;	/* first boot: no grants yet */

	for (;;) {
		char *end;
		unsigned long v;

		if (getline(&line, &cap, f) <= 0)
			break;
		v = strtoul(line, &end, 10);
		if (end != line)
			uid_insert((uid_t)v);
	}
	free(line);
	fclose(f);
	return 0;
}

/*
 * Re-stage every persisted grant. Separate from policy_load_grants() because
 * the stages need the inotify fd and the stub template to exist first.
 */
int policy_restage_all(void)
{
	size_t i;

	for (i = 0; i < uid_cap; i++) {
		if (!uid_tab[i].used)
			continue;
		if (policy_stage_uid((uid_t)uid_tab[i].uid))
			zsu_warn("restage uid %u failed", uid_tab[i].uid);
	}
	return 0;
}

int policy_allow_uid(uid_t uid)
{
	int rc;
	bool existed = policy_uid_allowed(uid) != 0;

	uid_insert(uid);
	rc = policy_stage_uid(uid);
	if (rc) {
		/* Only drop the grant if this call is what created it. */
		if (!existed)
			uid_remove(uid);
		return rc;
	}
	policy_save_grants();
	return 0;
}

int policy_revoke_uid(uid_t uid)
{
	/*
	 * Never act on a uid we never granted. ctl.sock is reachable by adb
	 * shell and REVOKE needs no SuperKey, so an unconditional
	 * zsu_cgroup_kill() would let the shell terminate any uid's cgroup -
	 * including system_server (uid 1000).
	 */
	if (!policy_uid_allowed(uid))
		return -ENOENT;

	uid_remove(uid);
	policy_disarm_doorbell(uid);
	policy_save_grants();

	/*
	 * A revoked uid must stop running now: the grant is gone from RAM, but
	 * any process that already holds the elevated cred would keep it until
	 * it exits. cgroup.kill (or per-pid signals) ends that immediately,
	 * and it is a direct cgroup index, never a /proc scan.
	 */
	return zsu_cgroup_kill(uid);
}

/* ------------------------------------------------------------------ */
/* inotify                                                             */
/* ------------------------------------------------------------------ */

int policy_inotify_init(void)
{
	inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (inotify_fd < 0)
		return -errno;

	/*
	 * packages.list is replaced by rename (IN_MOVED_TO) on some releases
	 * and rewritten in place (IN_CLOSE_WRITE) on others; both are watched,
	 * and the event name is checked in the caller.
	 */
	package_wd = inotify_add_watch(inotify_fd, "/data/system",
				       IN_MOVED_TO | IN_CLOSE_WRITE);
	if (package_wd < 0)
		zsu_warn("watch /data/system: %s", strerror(errno));

	return 0;
}

int policy_inotify_fd(void)
{
	return inotify_fd;
}

int policy_package_wd(void)
{
	return package_wd;
}
