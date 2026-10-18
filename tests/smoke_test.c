// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - tests/smoke_test.c
 *
 * The smallest thing that proves the userspace side of the ABI is real. Not
 * a product surface: this is a reference for how the wire format works, and a
 * compile-time proof that uapi/zerosu.h is usable from a plain host program.
 *
 * Build (no kernel tree needed):
 *   cc -Wall -Wextra -Werror -I kernel/include -o /tmp/zsu-smoke \
 *      tests/smoke_test.c
 *
 * Run (needs zerosu.ko loaded):
 *   sudo /tmp/zsu-smoke          # plain session, ping only
 *   sudo /tmp/zsu-smoke su key   # su session: enroll, verify, elevate
 *
 * Note the reboot() call uses the raw syscall, not the libc wrapper. The
 * kernel sees SYSCALL_DEFINE4(reboot, int, magic1, int, magic2, unsigned int,
 * cmd, void __user *, arg), so the magics come first; libc's
 * reboot(int cmd, int magic1, ...) reorders them and would not arrive.
 *
 * stdbool.h is included explicitly because bionic does not pull `bool` in
 * transitively the way glibc does; -Werror turns the difference into a
 * build failure.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "uapi/zerosu.h"

/*
 * One ioctl exchange: the 24-byte command header, immediately followed by
 * the payload and then the reply. The kernel writes the reply at offset
 * sizeof(struct zerosu_cmd), so this cannot be a flat union - a flat union
 * would alias the reply onto the header.
 */
struct zsu_msg {
	struct zerosu_cmd hdr;
	union {
		__u32 abi;			/* PING reply */
		struct zerosu_info info;	/* GET_INFO reply */
		struct zerosu_status status;	/* GET_STATUS reply */
		struct zerosu_event event;	/* NEXT_EVENT reply */
		struct zerosu_elevate_task elevate_task;
		__u8 key[ZSU_KEY_MAX];		/* AUTH_SET_KEY payload */
		__u8 digest[ZSU_DIGEST_LEN];	/* AUTH_VERIFY payload */
		__u8 raw[sizeof(struct zerosu_status) + ZSU_KEY_MAX];
	};
};

static const char *basename_of(const char *p)
{
	const char *s = strrchr(p, '/');

	return s ? s + 1 : p;
}

int main(int argc, char **argv)
{
	struct zsu_msg buf;
	const bool want_su = (argc > 1 && !strcmp(argv[1], "su"));
	const bool want_key = (argc > 2);
	int fd = -1;
	long r;

	if (want_key && !want_su) {
		fprintf(stderr, "usage: %s [su [key]]\n", basename_of(argv[0]));
		return 2;
	}

	/*
	 * Open the gateway. The syscall itself is expected to fail: reboot()
	 * rejects the magic pair with -EINVAL (or -EPERM when unprivileged)
	 * because ZSU_GATEWAY_MAGIC1 is not LINUX_REBOOT_MAGIC1. The fd is
	 * handed back through the out pointer regardless, which is the whole
	 * point of the arrangement.
	 */
	memset(&buf, 0, sizeof(buf));
	errno = 0;
	r = syscall(__NR_reboot, (unsigned long)ZSU_GATEWAY_MAGIC1,
		    (unsigned long)ZSU_GATEWAY_MAGIC2,
		    (unsigned long)(want_su ? ZSU_SESSION_SU : ZSU_SESSION_PLAIN),
		    &fd);
	printf("reboot() = %ld errno=%d (%s), fd=%d\n", r, errno,
	       strerror(errno), fd);
	if (fd < 0) {
		fprintf(stderr, "no session: is zerosu.ko loaded?\n");
		return 1;
	}

	/* PING: the reply overwrites the payload slot with the ABI version. */
	memset(&buf, 0, sizeof(buf));
	buf.hdr.magic = ZSU_CMD_MAGIC;
	buf.hdr.opcode = ZSU_CMD_PING;
	if (ioctl(fd, ZSU_IO(ZSU_IOC_NR(ZSU_CMD_PING)), &buf.hdr) < 0) {
		perror("PING");
		close(fd);
		return 1;
	}
	printf("abi = %u (expected %u)\n", buf.abi, (unsigned)ZSU_ABI_VERSION);
	if (buf.abi != ZSU_ABI_VERSION) {
		fprintf(stderr, "ABI mismatch\n");
		close(fd);
		return 1;
	}

	if (want_key) {
		memset(buf.key, 0x5a, sizeof(buf.key));
		buf.hdr.magic = ZSU_CMD_MAGIC;
		buf.hdr.opcode = ZSU_CMD_AUTH_SET_KEY;
			buf.hdr.inlen = ZSU_PAYLOAD_KEY;
		if (ioctl(fd, ZSU_IO(ZSU_IOC_NR(ZSU_CMD_AUTH_SET_KEY)), &buf.hdr) < 0) {
			perror("AUTH_SET_KEY");
			close(fd);
			return 1;
		}
		printf("key enrolled\n");
	}

	if (want_su) {
		/*
		 * AUTH_VERIFY expects the caller to prove it holds the key by
		 * sending the digest; the kernel only ever stores the digest,
		 * never the key, and compares in constant time.
		 */
		memset(buf.raw, 0, sizeof(buf.raw));
		buf.hdr.magic = ZSU_CMD_MAGIC;
		buf.hdr.opcode = ZSU_CMD_AUTH_VERIFY;
			buf.hdr.inlen = ZSU_PAYLOAD_DIGEST;
		if (ioctl(fd, ZSU_IO(ZSU_IOC_NR(ZSU_CMD_AUTH_VERIFY)), &buf.hdr) < 0) {
			perror("AUTH_VERIFY");
			close(fd);
			return 1;
		}

		memset(&buf, 0, sizeof(buf));
		buf.hdr.magic = ZSU_CMD_MAGIC;
		buf.hdr.opcode = ZSU_CMD_ELEVATE;
			buf.hdr.arg = ZSU_ELEVATE_MODE_SELF;
		if (ioctl(fd, ZSU_IO(ZSU_IOC_NR(ZSU_CMD_ELEVATE)), &buf.hdr) < 0) {
			perror("ELEVATE");
			close(fd);
			return 1;
		}
		printf("elevated: uid=%u gid=%u\n", getuid(), getgid());
	}

	/* Drain whatever the ring has; -EAGAIN just means "nothing pending". */
	for (;;) {
		memset(&buf, 0, sizeof(buf));
		buf.hdr.magic = ZSU_CMD_MAGIC;
		buf.hdr.opcode = ZSU_CMD_NEXT_EVENT;
		if (ioctl(fd, ZSU_IO(ZSU_IOC_NR(ZSU_CMD_NEXT_EVENT)), &buf.hdr) < 0) {
			if (errno == EAGAIN)
				break;
			perror("NEXT_EVENT");
			break;
		}
		printf("event seq=%llu type=%u payload=%s\n",
		       (unsigned long long)buf.event.seq, buf.event.type,
		       buf.event.payload);
	}

	close(fd);
	return 0;
}