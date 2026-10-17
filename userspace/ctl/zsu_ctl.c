// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - userspace/ctl/zsu_ctl.c
 *
 * The orchestrator. One binary, one job per subcommand:
 *
 *   patch <zerosud> [hex]   offline: stamp the SuperKey into the daemon's ELF
 *                           slot and print the key once. No daemon, no kernel.
 *   allow <pkg|uid> [hex]   prove the SuperKey; then stage <uid>/upper/su,
 *                           register the doorbell and hot-inject anything
 *                           already in that uid's cgroup.
 *   revoke <pkg|uid> [hex]  prove the SuperKey; then drop the grant and kill
 *                           the uid's cgroup.
 *   list / status / ping    observe the daemon (no key needed).
 *   shell [hex]             prove the SuperKey, ask zerosud to ELEVATE_TASK
 *                           this very process, then exec /system/bin/sh.
 *
 * `patch` is the only command that has to understand an ELF, and it does so
 * without ever loading one: it looks for the one unpatched "ZSUKEY00" slot by
 * scanning the file image. "Unique" is enforced, not assumed - two matches is
 * an error, not a guess.
 */


#include "zsu_daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

static void usage(void)
{
	fprintf(stderr,
		"usage: zsu_ctl patch <zerosud_elf> [hex_key_128]\n"
		"       zsu_ctl allow <package|uid> [hex_key_128]\n"
		"       zsu_ctl revoke <package|uid> [hex_key_128]\n"
		"       zsu_ctl list | status | ping\n"
		"       zsu_ctl shell [hex_key_128]\n"
		"\n"
		"The SuperKey may also come from $ZSU_KEY, or from the slot in a\n"
		"readable daemon binary named by $ZSU_ZEROSUD.\n");
}

/* ------------------------------------------------------------------ */
/* control socket                                                      */
/* ------------------------------------------------------------------ */

static int ctl_call(struct zsu_ctl_req *req, struct zsu_ctl_resp *resp)
{
	struct sockaddr_un sa;
	int fd;

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	if (strlen(ZSU_CTL_SOCK) >= sizeof(sa.sun_path)) {
		close(fd);
		return -ENAMETOOLONG;
	}
	strcpy(sa.sun_path, ZSU_CTL_SOCK);

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int e = errno;

		close(fd);
		return -e;
	}

	{
		ssize_t n = send(fd, req, sizeof(*req), 0);

		if (n != (ssize_t)sizeof(*req)) {
			int e = n < 0 ? errno : EIO;

			close(fd);
			return -e;
		}
	}

	memset(resp, 0, sizeof(*resp));
	/*
	 * A SEQPACKET peer that closes without replying returns 0, not -1, and
	 * errno is left untouched. Treating that as a zeroed (successful) reply
	 * is exactly how "daemon died" would look like "command accepted", so a
	 * short read is always an I/O error.
	 */
	{
		ssize_t r = recv(fd, resp, sizeof(*resp), 0);

		if (r != (ssize_t)sizeof(*resp)) {
			int e = r < 0 ? errno : EIO;

			close(fd);
			return -e;
		}
	}

	close(fd);
	return 0;
}

static int is_numeric(const char *s)
{
	if (!*s)
		return 0;
	while (*s) {
		if (*s < '0' || *s > '9')
			return 0;
		s++;
	}
	return 1;
}

static int load_superkey(const char *hexarg, uint8_t key[ZSU_PATCH_KEY_LEN],
			 const char *what);

static int do_allow_revoke(const char *arg, const char *hex, uint32_t op)
{
	uint8_t key[ZSU_PATCH_KEY_LEN];
	struct zsu_ctl_req req;
	struct zsu_ctl_resp resp;
	const char *name = op == ZSU_CTL_ALLOW ? "allow" : "revoke";
	int rc;

	/* ALLOW writes a persistent grant and REVOKE kills a cgroup: both are
	 * at least as sensitive as SHELL, so both require the SuperKey. */
	rc = load_superkey(hex, key, name);
	if (rc)
		return rc;

	memset(&req, 0, sizeof(req));
	req.op = op;
	if (is_numeric(arg))
		req.uid = (uint32_t)strtoul(arg, NULL, 10);
	else
		snprintf(req.pkg, sizeof(req.pkg), "%s", arg);
	memcpy(req.key, key, sizeof(key));
	zsu_wipe(key, sizeof(key));

	rc = ctl_call(&req, &resp);
	if (rc) {
		fprintf(stderr, "zsu_ctl: %s: %s\n", name, strerror(-rc));
		return 1;
	}
	if (resp.status) {
		fprintf(stderr, "zsu_ctl: %s: %s\n", name,
			resp.msg[0] ? resp.msg : strerror(-resp.status));
		return 1;
	}
	printf("%s\n", resp.msg);
	return 0;
}

static int do_simple(uint32_t op)
{
	struct zsu_ctl_req req;
	struct zsu_ctl_resp resp;
	int rc;

	memset(&req, 0, sizeof(req));
	req.op = op;

	rc = ctl_call(&req, &resp);
	if (rc) {
		fprintf(stderr, "zsu_ctl: %s\n", strerror(-rc));
		return 1;
	}
	if (resp.status) {
		fprintf(stderr, "zsu_ctl: %s\n",
			resp.msg[0] ? resp.msg : strerror(-resp.status));
		return 1;
	}
	if (op == ZSU_CTL_LIST) {
		if (resp.msg[0])
			printf("%s", resp.msg);
		printf("count=%u\n", resp.count);
	} else {
		printf("%s\n", resp.msg);
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* shell                                                               */
/* ------------------------------------------------------------------ */

/*
 * Read a key back out of a patched ELF slot. Only used when the operator did
 * not pass one and the binary is readable (i.e. we are root); the key is
 * never written anywhere else.
 */
static int key_from_elf(const char *path, uint8_t key[ZSU_PATCH_KEY_LEN])
{
	struct stat st;
	uint8_t *img;
	off_t off = -1;
	int fd, i, count = 0;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	if (fstat(fd, &st) || st.st_size < 16) {
		close(fd);
		return -EINVAL;
	}
	img = malloc((size_t)st.st_size);
	if (!img) {
		close(fd);
		return -ENOMEM;
	}
	if (pread(fd, img, (size_t)st.st_size, 0) != st.st_size) {
		free(img);
		close(fd);
		return -EIO;
	}
	close(fd);

	for (i = 0; i + ZSU_PATCH_MAGIC_LEN + ZSU_PATCH_KEY_LEN <= st.st_size; i++) {
		if (!memcmp(img + i, ZSU_PATCH_MAGIC, ZSU_PATCH_MAGIC_LEN)) {
			off = i;
			count++;
		}
	}
	if (count != 1) {
		free(img);
		return -EINVAL;
	}

	memcpy(key, img + off + ZSU_PATCH_MAGIC_LEN, ZSU_PATCH_KEY_LEN);
	free(img);

	for (i = 0; i < ZSU_PATCH_KEY_LEN; i++)
		if (key[i])
			return 0;
	return -ENOKEY;
}

/*
 * Resolve the SuperKey, in precedence order: an explicit hex argument, the
 * ZSU_KEY environment variable, or the slot inside a readable daemon binary
 * named by ZSU_ZEROSUD. The hex argument is optional; NULL means "fall back to
 * the environment". Returns 0 on success, 2 for a usage/key-format error, and
 * 1 for an I/O error.
 */
static int load_superkey(const char *hexarg, uint8_t key[ZSU_PATCH_KEY_LEN],
			 const char *what)
{
	const char *envkey = getenv("ZSU_KEY");
	const char *elfpath = getenv("ZSU_ZEROSUD");
	int rc;

	if (hexarg) {
		if (zsu_hex_decode(hexarg, key, ZSU_PATCH_KEY_LEN)) {
			fprintf(stderr, "zsu_ctl: key must be %d hex chars\n",
				ZSU_PATCH_KEY_LEN * 2);
			return 2;
		}
		return 0;
	}
	if (envkey) {
		if (zsu_hex_decode(envkey, key, ZSU_PATCH_KEY_LEN)) {
			fprintf(stderr, "zsu_ctl: ZSU_KEY must be %d hex chars\n",
				ZSU_PATCH_KEY_LEN * 2);
			return 2;
		}
		return 0;
	}
	if (elfpath) {
		rc = key_from_elf(elfpath, key);
		if (rc) {
			fprintf(stderr, "zsu_ctl: cannot read key from %s: %s\n",
				elfpath, strerror(-rc));
			return 1;
		}
		return 0;
	}

	fprintf(stderr,
		"zsu_ctl: %s needs the SuperKey (argument or ZSU_KEY),"
		" or ZSU_ZEROSUD with a readable binary\n", what);
	return 2;
}

static int do_shell(int argc, char **argv)
{
	uint8_t key[ZSU_PATCH_KEY_LEN];
	struct zsu_ctl_req req;
	struct zsu_ctl_resp resp;
	uint64_t start;
	int rc;

	rc = load_superkey(argc > 0 ? argv[0] : NULL, key, "shell");
	if (rc)
		return rc;

	if (zsu_proc_start_time_path("/proc/self", &start)) {
		fprintf(stderr, "zsu_ctl: cannot read own start time\n");
		return 1;
	}

	memset(&req, 0, sizeof(req));
	req.op = ZSU_CTL_SHELL;
	req.pid = (uint32_t)getpid();
	req.start_time = start;
	memcpy(req.key, key, sizeof(key));
	zsu_wipe(key, sizeof(key));

	rc = ctl_call(&req, &resp);
	if (rc) {
		fprintf(stderr, "zsu_ctl: %s\n", strerror(-rc));
		return 1;
	}
	if (resp.status) {
		fprintf(stderr, "zsu_ctl: %s\n",
			resp.msg[0] ? resp.msg : strerror(-resp.status));
		return 1;
	}

	{
		char *shargv[] = { (char *)"sh", NULL };

		execv("/system/bin/sh", shargv);
		fprintf(stderr, "zsu_ctl: execv /system/bin/sh: %s\n",
			strerror(errno));
		return 1;
	}
}

/* ------------------------------------------------------------------ */
/* patch                                                               */
/* ------------------------------------------------------------------ */

static int fill_key(uint8_t key[ZSU_PATCH_KEY_LEN], const char *hex)
{
	if (hex) {
		if (zsu_hex_decode(hex, key, ZSU_PATCH_KEY_LEN))
			return -EINVAL;
		return 0;
	}

	if (getrandom(key, ZSU_PATCH_KEY_LEN, 0) != (ssize_t)ZSU_PATCH_KEY_LEN) {
		/* getrandom() can be short before the pool is ready; urandom. */
		int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);

		if (fd < 0)
			return -errno;
		if (read(fd, key, ZSU_PATCH_KEY_LEN) != ZSU_PATCH_KEY_LEN) {
			close(fd);
			return -EIO;
		}
		close(fd);
	}
	return 0;
}

static int do_patch(const char *path, const char *hex)
{
	struct stat st;
	uint8_t key[ZSU_PATCH_KEY_LEN];
	uint8_t *img;
	char hexout[ZSU_PATCH_KEY_LEN * 2 + 1];
	off_t off = -1;
	int fd, i, count = 0, nz = 0, rc;

	if (fill_key(key, hex)) {
		fprintf(stderr, "zsu_ctl: key must be %d hex chars\n",
			ZSU_PATCH_KEY_LEN * 2);
		return 2;
	}

	fd = open(path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "zsu_ctl: open %s: %s\n", path, strerror(errno));
		return 1;
	}
	if (fstat(fd, &st)) {
		fprintf(stderr, "zsu_ctl: stat %s: %s\n", path, strerror(errno));
		close(fd);
		return 1;
	}
	img = malloc((size_t)st.st_size);
	if (!img) {
		fprintf(stderr, "zsu_ctl: out of memory\n");
		close(fd);
		return 1;
	}
	if (pread(fd, img, (size_t)st.st_size, 0) != st.st_size) {
		fprintf(stderr, "zsu_ctl: short read on %s\n", path);
		free(img);
		close(fd);
		return 1;
	}

	if (st.st_size < 4 || memcmp(img, "\x7f" "ELF", 4)) {
		fprintf(stderr, "zsu_ctl: %s is not an ELF file\n", path);
		free(img);
		close(fd);
		return 1;
	}

	/* Accept only a slot whose magic and 64-byte key area both fit. */
	for (i = 0;
	     i + ZSU_PATCH_MAGIC_LEN + ZSU_PATCH_KEY_LEN <= st.st_size; i++) {
		if (!memcmp(img + i, ZSU_PATCH_MAGIC, ZSU_PATCH_MAGIC_LEN)) {
			off = i;
			count++;
		}
	}
	free(img);

	if (count != 1) {
		fprintf(stderr,
			"zsu_ctl: expected exactly one slot, found %d\n", count);
		close(fd);
		return 1;
	}

	for (i = 0; i < ZSU_PATCH_KEY_LEN; i++) {
		uint8_t b;

		if (pread(fd, &b, 1, off + ZSU_PATCH_MAGIC_LEN + i) != 1)
			break;
		nz += b != 0;
	}
	if (nz) {
		fprintf(stderr, "zsu_ctl: slot at %lld is already patched\n",
			(long long)off);
		close(fd);
		return 1;
	}

	rc = pwrite(fd, key, ZSU_PATCH_KEY_LEN, off + ZSU_PATCH_MAGIC_LEN);
	if (rc != ZSU_PATCH_KEY_LEN) {
		fprintf(stderr, "zsu_ctl: write failed: %s\n", strerror(errno));
		close(fd);
		return 1;
	}
	fsync(fd);
	close(fd);

	zsu_hex_encode(key, ZSU_PATCH_KEY_LEN, hexout);
	zsu_wipe(key, sizeof(key));

	/*
	 * Printed exactly once. This is the only copy the operator will ever
	 * see outside the binary itself; there is no key file.
	 */
	printf("%s\n", hexout);
	zsu_wipe(hexout, sizeof(hexout));

	fprintf(stderr, "zsu_ctl: patched %s (slot %lld)\n", path, (long long)off);
	return 0;
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
	const char *cmd;

	zsu_prog = "zsu_ctl";

	if (argc < 2) {
		usage();
		return 2;
	}
	cmd = argv[1];

	if (!strcmp(cmd, "patch")) {
		if (argc < 3) {
			usage();
			return 2;
		}
		return do_patch(argv[2], argc > 3 ? argv[3] : NULL);
	}
	if (!strcmp(cmd, "allow"))
		return argc >= 3 ?
			do_allow_revoke(argv[2], argc > 3 ? argv[3] : NULL,
					ZSU_CTL_ALLOW) : 2;
	if (!strcmp(cmd, "revoke"))
		return argc >= 3 ?
			do_allow_revoke(argv[2], argc > 3 ? argv[3] : NULL,
					ZSU_CTL_REVOKE) : 2;
	if (!strcmp(cmd, "list"))
		return do_simple(ZSU_CTL_LIST);
	if (!strcmp(cmd, "status"))
		return do_simple(ZSU_CTL_STATUS);
	if (!strcmp(cmd, "ping"))
		return do_simple(ZSU_CTL_PING);
	if (!strcmp(cmd, "shell"))
		return do_shell(argc - 2, argv + 2);

	usage();
	return 2;
}
