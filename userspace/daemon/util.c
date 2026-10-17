// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - userspace/daemon/util.c
 *
 * Small, dependency-free helpers shared by the daemon (and reused by zsu_ctl,
 * which links this file too). Nothing here keeps mutable global state except
 * the log verbosity, so it is safe in both binaries.
 *
 * The two non-trivial pieces are:
 *
 *   - zsu_proc_start_time_*(): read /proc/<pid>/stat field 22. That field is
 *     nsec_to_clock_t(start_boottime) in fs/proc/array.c, which is exactly
 *     what SUPER_CMD ELEVATE_TASK recomputes on the kernel side, so the token
 *     userspace reads is the token the kernel compares.
 *
 *   - the SHA-256 used to turn the 64 byte SuperKey into the 32 byte digest
 *     AUTH_VERIFY expects. AUTH_SET_KEY hashes the raw key in the kernel; the
 *     daemon must produce the identical digest itself, and there is no
 *     libcrypto to lean on.
 */


#include "zsu_daemon.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/xattr.h>
#include <unistd.h>

int zsu_verbose;

/* Which binary is logging; both zerosud and zsu_ctl link this file. */
const char *zsu_prog = "zerosud";

void zsu_log(const char *fmt, ...)
{
	va_list ap;
	char buf[512];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	fprintf(stderr, "%s: %s\n", zsu_prog, buf);
}

void zsu_warn(const char *fmt, ...)
{
	va_list ap;
	char buf[512];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	fprintf(stderr, "%s: %s\n", zsu_prog, buf);
}

void zsu_die(const char *fmt, ...)
{
	va_list ap;
	char buf[512];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	fprintf(stderr, "%s: fatal: %s\n", zsu_prog, buf);
	exit(1);
}

/*
 * explicit_bzero() semantics, with a fallback for libcs that lack it. The
 * volatile pointer is what stops the compiler from proving the store dead;
 * AUTH_SET_KEY and the key slot both go through here.
 */
void zsu_wipe(void *p, size_t n)
{
#if defined(__GLIBC__) || defined(__BIONIC__)
	explicit_bzero(p, n);
#else
	volatile unsigned char *v = (volatile unsigned char *)p;

	while (n--)
		*v++ = 0;
#endif
}

/* ------------------------------------------------------------------ */
/* files                                                               */
/* ------------------------------------------------------------------ */

int zsu_mkdir_p(const char *path, mode_t mode)
{
	char tmp[ZSU_PATH_MAX];
	size_t len;
	char *p;

	if (strlen(path) >= sizeof(tmp))
		return -ENAMETOOLONG;
	strcpy(tmp, path);

	len = strlen(tmp);
	if (len && tmp[len - 1] == '/')
		tmp[len - 1] = '\0';

	for (p = tmp + 1; *p; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if (mkdir(tmp, mode | 0700) && errno != EEXIST)
			return -errno;
		*p = '/';
	}

	if (mkdir(tmp, mode | 0700) && errno != EEXIST)
		return -errno;

	/* umask must not decide the final mode of a security boundary. */
	return chmod(tmp, mode) ? -errno : 0;
}

int zsu_chmod(const char *path, mode_t mode)
{
	return chmod(path, mode) ? -errno : 0;
}

int zsu_write_all(int fd, const void *buf, size_t n)
{
	const char *p = buf;

	while (n) {
		ssize_t r = write(fd, p, n);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		if (r == 0)
			return -EIO;
		p += r;
		n -= (size_t)r;
	}
	return 0;
}

/*
 * Read a whole (small) file into buf. Returns the byte count, or a negative
 * errno. Not a general streaming reader: every caller here reads a procfs
 * line or a control file.
 */
int zsu_read_file(const char *path, void *buf, size_t n)
{
	int fd;
	ssize_t r;
	size_t off = 0;

	if (n == 0)
		return -EINVAL;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	while (off < n - 1) {
		r = read(fd, (char *)buf + off, n - 1 - off);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -errno;
		}
		if (r == 0)
			break;
		off += (size_t)r;
	}
	close(fd);
	((char *)buf)[off] = '\0';
	return (int)off;
}

int zsu_write_file(const char *path, const void *buf, size_t n)
{
	int fd, rc;

	fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (fd < 0)
		return -errno;
	rc = zsu_write_all(fd, buf, n);
	close(fd);
	return rc;
}

int zsu_copy_file(const char *src, const char *dst, mode_t mode)
{
	char buf[65536];
	int in, out = -1, rc = 0;

	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -errno;

	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (out < 0) {
		rc = -errno;
		goto out;
	}

	for (;;) {
		ssize_t r = read(in, buf, sizeof(buf));

		if (r < 0) {
			if (errno == EINTR)
				continue;
			rc = -errno;
			goto out;
		}
		if (r == 0)
			break;
		rc = zsu_write_all(out, buf, (size_t)r);
		if (rc)
			goto out;
	}

	if (fchmod(out, mode))
		rc = -errno;

out:
	if (out >= 0)
		close(out);
	close(in);
	return rc;
}

/* ------------------------------------------------------------------ */
/* SELinux attrs                                                       */
/* ------------------------------------------------------------------ */

int zsu_set_selinux_label(const char *path, const char *ctx)
{
	/* xattr values carry the trailing NUL. */
	if (lsetxattr(path, "security.selinux", ctx, strlen(ctx) + 1, 0))
		return -errno;
	return 0;
}

int zsu_write_attr(const char *attr, const char *ctx)
{
	char path[64];
	int fd, rc;

	snprintf(path, sizeof(path), "/proc/self/attr/%s", attr);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	rc = zsu_write_all(fd, ctx, strlen(ctx));
	close(fd);
	return rc;
}

int zsu_read_attr(const char *attr, char *buf, size_t n)
{
	char path[64];

	snprintf(path, sizeof(path), "/proc/self/attr/%s", attr);
	return zsu_read_file(path, buf, n);
}

/* ------------------------------------------------------------------ */
/* hex                                                                 */
/* ------------------------------------------------------------------ */

int zsu_hex_encode(const uint8_t *in, size_t n, char *out)
{
	static const char hexdig[] = "0123456789abcdef";
	size_t i;

	for (i = 0; i < n; i++) {
		out[i * 2] = hexdig[in[i] >> 4];
		out[i * 2 + 1] = hexdig[in[i] & 0xf];
	}
	out[n * 2] = '\0';
	return 0;
}

static int hexval(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int zsu_hex_decode(const char *in, uint8_t *out, size_t n)
{
	size_t i;

	if (strlen(in) != n * 2)
		return -EINVAL;
	for (i = 0; i < n; i++) {
		int hi = hexval(in[i * 2]);
		int lo = hexval(in[i * 2 + 1]);

		if (hi < 0 || lo < 0)
			return -EINVAL;
		out[i] = (uint8_t)((hi << 4) | lo);
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* /proc/<pid>/stat field 22                                           */
/* ------------------------------------------------------------------ */

/*
 * The comm field (field 2) is parenthesised and may itself contain spaces and
 * parentheses, so the only safe parse is to skip to the *last* ')' and count
 * whitespace-separated tokens from there. State is field 3, so starttime is
 * 22 - 3 = 19 tokens later.
 */
static int parse_starttime(const char *stat, uint64_t *out)
{
	const char *p = strrchr(stat, ')');
	int field;
	char *end;
	unsigned long long v;

	if (!p)
		return -EINVAL;
	p++;

	for (field = 3; field < 22; field++) {
		while (*p == ' ')
			p++;
		while (*p && *p != ' ' && *p != '\n')
			p++;
	}

	while (*p == ' ')
		p++;

	errno = 0;
	v = strtoull(p, &end, 10);
	if (end == p || errno)
		return -EINVAL;
	*out = (uint64_t)v;
	return 0;
}

int zsu_proc_start_time_fd(int pid_dirfd, uint64_t *out)
{
	char buf[1024];
	int fd;
	ssize_t r;
	size_t off = 0;

	fd = openat(pid_dirfd, "stat", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;

	while (off < sizeof(buf) - 1) {
		r = read(fd, buf + off, sizeof(buf) - 1 - off);
		if (r < 0) {
			if (errno == EINTR)
				continue;
			close(fd);
			return -errno;
		}
		if (r == 0)
			break;
		off += (size_t)r;
	}
	close(fd);
	buf[off] = '\0';

	return parse_starttime(buf, out);
}

int zsu_proc_start_time_path(const char *procdir, uint64_t *out)
{
	char path[ZSU_PATH_MAX];

	snprintf(path, sizeof(path), "%s/stat", procdir);
	{
		char buf[1024];
		int n = zsu_read_file(path, buf, sizeof(buf));

		if (n < 0)
			return n;
		return parse_starttime(buf, out);
	}
}

/* ------------------------------------------------------------------ */
/* pidfd                                                               */
/* ------------------------------------------------------------------ */

int zsu_pidfd_kill(pid_t pid, int sig)
{
#ifdef __NR_pidfd_open
	int fd = (int)syscall(__NR_pidfd_open, pid, 0);

	if (fd >= 0) {
		long r;
		int e;

#ifdef __NR_pidfd_send_signal
		r = syscall(__NR_pidfd_send_signal, fd, sig, NULL, 0);
#else
		r = -1;
		errno = ENOSYS;
#endif
		e = errno;
		close(fd);
		if (r == 0)
			return 0;
		return -e;
	}
#endif
	return kill(pid, sig) ? -errno : 0;
}

/* ------------------------------------------------------------------ */
/* cgroup indexing                                                     */
/* ------------------------------------------------------------------ */

/*
 * Read a cgroup.procs file and hand every pid to @cb. Returns 0 if the file
 * is absent (a layout variant), else the callback's first nonzero result.
 */
static int scan_procs(const char *dir, int (*cb)(pid_t, void *), void *arg)
{
	char path[ZSU_PATH_MAX * 2];
	char buf[8192];
	int fd, n;
	char *p;

	snprintf(path, sizeof(path), "%s/cgroup.procs", dir);
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return 0;	/* not this variant */

	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';

	p = buf;
	while (*p) {
		char *end;
		long v = strtol(p, &end, 10);

		if (end == p)
			break;
		if (v > 0) {
			int rc = cb((pid_t)v, arg);

			if (rc)
				return rc;
		}
		p = end;
		while (*p == '\n' || *p == ' ' || *p == '\t')
			p++;
	}
	return 0;
}

int zsu_cgroup_for_each_pid(uid_t uid, int (*cb)(pid_t, void *), void *arg)
{
	char dir[ZSU_PATH_MAX];
	DIR *d;
	struct dirent *de;
	int rc;

	/*
	 * Direct index: uid -> cgroup directory. No /proc walk, ever. This is
	 * the whole reason grants are keyed by uid rather than by pid.
	 */
	snprintf(dir, sizeof(dir), "%s/uid_%u", ZSU_CGROUP_ROOT, (unsigned)uid);

	rc = scan_procs(dir, cb, arg);
	if (rc)
		return rc;

	d = opendir(dir);
	if (!d)
		return -errno;

	while ((de = readdir(d))) {
		char sub[ZSU_PATH_MAX * 2];

		if (strncmp(de->d_name, "pid_", 4))
			continue;
		snprintf(sub, sizeof(sub), "%s/%s", dir, de->d_name);
		rc = scan_procs(sub, cb, arg);
		if (rc)
			break;
	}
	closedir(d);
	return rc;
}

struct kill_ctx {
	int sig;
};

static int proc_kill_cb(pid_t pid, void *arg)
{
	struct kill_ctx *c = arg;

	(void)zsu_pidfd_kill(pid, c->sig);
	return 0;
}

int zsu_cgroup_kill(uid_t uid)
{
	char path[ZSU_PATH_MAX];
	int fd, rc;

	/* cgroup v2's cgroup.kill: one write, no iteration. */
	snprintf(path, sizeof(path), "%s/uid_%u/cgroup.kill", ZSU_CGROUP_ROOT,
		 (unsigned)uid);
	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		rc = zsu_write_all(fd, "1", 1);
		close(fd);
		return rc;
	}

	/* v1 / older layouts: walk the uid's own pids and signal each. */
	{
		struct kill_ctx ctx = { SIGKILL };

		return zsu_cgroup_for_each_pid(uid, proc_kill_cb, &ctx);
	}
}

/* ------------------------------------------------------------------ */
/* SHA-256 (FIPS 180-4)                                                */
/* ------------------------------------------------------------------ */

struct sha256 {
	uint32_t h[8];
	uint64_t len;
	uint8_t buf[64];
	size_t used;
};

static const uint32_t sha256_k[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
	0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
	0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
	0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
	0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
	0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha256_block(struct sha256 *s, const uint8_t *p)
{
	uint32_t w[64], a, b, c, d, e, f, g, h;
	int i;

	for (i = 0; i < 16; i++)
		w[i] = ((uint32_t)p[i * 4] << 24) |
		       ((uint32_t)p[i * 4 + 1] << 16) |
		       ((uint32_t)p[i * 4 + 2] << 8) |
		       (uint32_t)p[i * 4 + 3];
	for (i = 16; i < 64; i++) {
		uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^
			      (w[i - 15] >> 3);
		uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^
			      (w[i - 2] >> 10);

		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = s->h[0]; b = s->h[1]; c = s->h[2]; d = s->h[3];
	e = s->h[4]; f = s->h[5]; g = s->h[6]; h = s->h[7];

	for (i = 0; i < 64; i++) {
		uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
		uint32_t ch = (e & f) ^ (~e & g);
		uint32_t t1 = h + S1 + ch + sha256_k[i] + w[i];
		uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
		uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
		uint32_t t2 = S0 + maj;

		h = g; g = f; f = e; e = d + t1;
		d = c; c = b; b = a; a = t1 + t2;
	}

	s->h[0] += a; s->h[1] += b; s->h[2] += c; s->h[3] += d;
	s->h[4] += e; s->h[5] += f; s->h[6] += g; s->h[7] += h;
}

static void sha256_init(struct sha256 *s)
{
	s->h[0] = 0x6a09e667; s->h[1] = 0xbb67ae85;
	s->h[2] = 0x3c6ef372; s->h[3] = 0xa54ff53a;
	s->h[4] = 0x510e527f; s->h[5] = 0x9b05688c;
	s->h[6] = 0x1f83d9ab; s->h[7] = 0x5be0cd19;
	s->len = 0;
	s->used = 0;
}

static void sha256_update(struct sha256 *s, const void *data, size_t len)
{
	const uint8_t *p = data;

	s->len += len;
	while (len) {
		size_t take = 64 - s->used;

		if (take > len)
			take = len;
		memcpy(s->buf + s->used, p, take);
		s->used += take;
		p += take;
		len -= take;
		if (s->used == 64) {
			sha256_block(s, s->buf);
			s->used = 0;
		}
	}
}

static void sha256_final(struct sha256 *s, uint8_t out[32])
{
	uint64_t bits = s->len * 8;
	uint8_t pad = 0x80;
	int i;

	sha256_update(s, &pad, 1);
	pad = 0;
	while (s->used != 56)
		sha256_update(s, &pad, 1);
	for (i = 7; i >= 0; i--) {
		uint8_t b = (uint8_t)(bits >> (i * 8));

		sha256_update(s, &b, 1);
	}
	for (i = 0; i < 8; i++) {
		out[i * 4] = (uint8_t)(s->h[i] >> 24);
		out[i * 4 + 1] = (uint8_t)(s->h[i] >> 16);
		out[i * 4 + 2] = (uint8_t)(s->h[i] >> 8);
		out[i * 4 + 3] = (uint8_t)s->h[i];
	}
}

void zsu_sha256(const void *data, size_t len, uint8_t out[32])
{
	struct sha256 s;

	sha256_init(&s);
	sha256_update(&s, data, len);
	sha256_final(&s, out);
	zsu_wipe(&s, sizeof(s));
}
