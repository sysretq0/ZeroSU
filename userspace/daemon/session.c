// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - userspace/daemon/session.c
 *
 * The only file that speaks the kernel ioctl ABI. Everything above it deals
 * in ordinary ints; the wire format, the reboot(2) gateway and the lock-free
 * one-buffer-per-call discipline live here.
 *
 * Two things about the gateway worth stating once:
 *
 *   - Opening a session is a raw syscall(__NR_reboot, MAGIC1, MAGIC2, type,
 *     &fd), NOT libc reboot(int cmd, int magic1, ...): the kernel's
 *     SYSCALL_DEFINE4(reboot, int magic1, int magic2, unsigned cmd, void *arg)
 *     takes the magics first. The syscall itself fails with -EINVAL/-EPERM on
 *     purpose; the fd is still delivered through the out pointer.
 *
 *   - AUTH_SET_KEY wants the 64 raw key bytes and hashes them kernel-side,
 *     while AUTH_VERIFY wants the 32 byte SHA-256 digest. The daemon computes
 *     that digest itself; getting these two payloads the wrong way round is
 *     the single easiest way to make the gate unusable, so they are separate
 *     wrappers rather than one generic "auth" call.
 */


#include "zsu_daemon.h"

#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Header plus the largest reply any command produces, in one allocation. */
#define ZSU_IO_REPLY_MAX	256

struct zsu_iobuf {
	struct zerosu_cmd hdr;
	union {
		uint8_t raw[ZSU_IO_REPLY_MAX];
		uint32_t abi;
		struct zerosu_info info;
		struct zerosu_profile profile;
		struct zerosu_status status;
		struct zerosu_event event;
		struct zerosu_elevate_task et;
	} u;
};

_Static_assert(sizeof(struct zerosu_info) <= ZSU_IO_REPLY_MAX,
	       "info must fit the reply buffer");
_Static_assert(sizeof(struct zerosu_profile) <= ZSU_IO_REPLY_MAX,
	       "profile must fit the reply buffer");
_Static_assert(sizeof(struct zerosu_status) <= ZSU_IO_REPLY_MAX,
	       "status must fit the reply buffer");
_Static_assert(sizeof(struct zerosu_event) <= ZSU_IO_REPLY_MAX,
	       "event must fit the reply buffer");
_Static_assert(sizeof(struct zerosu_elevate_task) <= ZSU_IO_REPLY_MAX,
	       "elevate payload must fit the request payload area");

/* The one long-lived [zerosu_su] session, authenticated at boot. */
static int su_fd = -1;

/*
 * One ioctl call. The buffer is always header-first, payload-second, exactly
 * as supercall.c reads it; the reply overwrites the payload area, so reply
 * and request-payload are deliberately the same bytes and are never both in
 * use for the same command.
 */
static int kernel_call(int fd, uint32_t opcode, uint32_t arg,
		       const void *payload, uint32_t inlen,
		       void *reply, size_t reply_len)
{
	struct zsu_iobuf io;

	if (fd < 0)
		return -EBADF;

	memset(&io, 0, sizeof(io));
	io.hdr.magic = ZSU_CMD_MAGIC;
	io.hdr.opcode = opcode;
	io.hdr.arg = arg;
	io.hdr.inlen = inlen;

	if (inlen) {
		if (inlen > sizeof(io.u.raw))
			return -EINVAL;
		memcpy(io.u.raw, payload, inlen);
	}

	if (ioctl(fd, ZSU_IO(ZSU_IOC_NR(opcode)), &io.hdr) < 0)
		return -errno;

	if (reply && reply_len) {
		if (reply_len > sizeof(io.u.raw))
			return -EINVAL;
		memcpy(reply, io.u.raw, reply_len);
	}
	return 0;
}

/*
 * Open a session through the reboot(2) gateway. The syscall's own return
 * value is meaningless here (it is expected to fail); only the fd the kernel
 * wrote to out_fd matters.
 */
static int session_open(uint32_t type, int *out_fd)
{
	int fd = -1;

	errno = 0;
	(void)syscall(__NR_reboot,
		      (unsigned long)ZSU_GATEWAY_MAGIC1,
		      (unsigned long)ZSU_GATEWAY_MAGIC2,
		      (unsigned long)type,
		      &fd);
	if (fd < 0)
		return -errno;

	*out_fd = fd;
	return 0;
}

int session_open_plain(int *out_fd)
{
	return session_open(ZSU_SESSION_PLAIN, out_fd);
}

int session_su_fd(void)
{
	return su_fd;
}

int session_ping(int fd, uint32_t *abi)
{
	return kernel_call(fd, ZSU_CMD_PING, 0, NULL, 0, abi, sizeof(*abi));
}

/*
 * Boot sequence. Order matters and each step is explained by supercall.c:
 *
 *   AUTH_SET_KEY   the one-time device enrollment; only uid 0 with no key
 *                  enrolled may do it. -EPERM here means the module was never
 *                  unloaded and a key is already enrolled, which is the
 *                  restart case and is not fatal.
 *   AUTH_VERIFY    proves the (already enrolled) key matches the slot. This
 *                  is what sets ctx->authenticated and therefore ZSU_PERM_KEY.
 *   ELEVATE        binds the session to an elevated cred and, more to the
 *                  point, leaves a live authenticated su session the daemon
 *                  reuses for every later ELEVATE_TASK.
 */
int session_boot(const uint8_t key[ZSU_PATCH_KEY_LEN])
{
	uint8_t digest[32];
	int fd = -1, rc;

	zsu_sha256(key, ZSU_PATCH_KEY_LEN, digest);

	rc = session_open(ZSU_SESSION_SU, &fd);
	if (rc) {
		zsu_wipe(digest, sizeof(digest));
		return rc;
	}

	rc = kernel_call(fd, ZSU_CMD_AUTH_SET_KEY, 0, key, ZSU_PAYLOAD_KEY,
			 NULL, 0);
	if (rc && rc != -EPERM) {
		zsu_warn("AUTH_SET_KEY failed: %d", rc);
		close(fd);
		zsu_wipe(digest, sizeof(digest));
		return rc;
	}
	if (rc == -EPERM)
		zsu_log("AUTH_SET_KEY: key already enrolled, continuing");

	rc = kernel_call(fd, ZSU_CMD_AUTH_VERIFY, 0, digest,
			 ZSU_PAYLOAD_DIGEST, NULL, 0);
	zsu_wipe(digest, sizeof(digest));
	if (rc) {
		zsu_warn("AUTH_VERIFY failed: %d", rc);
		close(fd);
		return rc;
	}

	rc = kernel_call(fd, ZSU_CMD_ELEVATE, ZSU_ELEVATE_MODE_SELF, NULL, 0,
			 NULL, 0);
	if (rc) {
		zsu_warn("ELEVATE failed: %d", rc);
		close(fd);
		return rc;
	}

	su_fd = fd;
	zsu_log("su session live, abi %d", ZSU_ABI_VERSION);
	return 0;
}

/*
 * Prove the caller's SuperKey on a throwaway plain [zerosu] session. Used by
 * the `shell` control op, which is the only place a key is required at
 * runtime and the only reason the key is ever accepted over a socket.
 */
int session_verify_plain(const uint8_t key[ZSU_PATCH_KEY_LEN], bool *ok)
{
	uint8_t digest[32];
	int fd = -1, rc;

	*ok = false;
	zsu_sha256(key, ZSU_PATCH_KEY_LEN, digest);

	rc = session_open(ZSU_SESSION_PLAIN, &fd);
	if (rc == 0) {
		rc = kernel_call(fd, ZSU_CMD_AUTH_VERIFY, 0, digest,
				 ZSU_PAYLOAD_DIGEST, NULL, 0);
		close(fd);
	}

	zsu_wipe(digest, sizeof(digest));
	if (rc == 0)
		*ok = true;
	/* -ENOKEY / -EACCES from the compare is a normal negative result. */
	return rc;
}

int session_elevate_task(pid_t pid, uint64_t start_time)
{
	struct zerosu_elevate_task et;

	if (su_fd < 0)
		return -EINVAL;

	et.start_time = start_time;
	return kernel_call(su_fd, ZSU_CMD_ELEVATE_TASK, (uint32_t)pid,
			   &et, sizeof(et), NULL, 0);
}
