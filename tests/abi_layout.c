/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ZeroSU - tests/abi_layout.c
 *
 * Locks the userspace/kernel contract down at compile time. If this file
 * fails to build, the ABI is broken and the module must not ship.
 *
 * It is deliberately a plain host program (no kernel headers): it includes
 * only the UAPI header, so tests/syntax-check.sh can build it for the host,
 * for 32 bit (-m32) and for every cross toolchain, on every host, without a
 * kernel tree.
 *
 * Build:
 *   cc -Wall -Wextra -Werror -I kernel/include -o /tmp/abi_layout \
 *      tests/abi_layout.c && /tmp/abi_layout
 */

#include <stddef.h>
#include <stdio.h>

#include "uapi/zerosu.h"

/* ---- struct zerosu_cmd: the 24 byte contract ------------------------- */
_Static_assert(sizeof(struct zerosu_cmd) == 24, "zerosu_cmd must be 24 bytes");
_Static_assert(offsetof(struct zerosu_cmd, magic) == 0, "magic @0");
_Static_assert(offsetof(struct zerosu_cmd, opcode) == 4, "opcode @4");
_Static_assert(offsetof(struct zerosu_cmd, flags) == 8, "flags @8");
_Static_assert(offsetof(struct zerosu_cmd, arg) == 12, "arg @12");
_Static_assert(offsetof(struct zerosu_cmd, inlen) == 16, "inlen @16");
_Static_assert(offsetof(struct zerosu_cmd, __reserved) == 20, "reserved @20");
_Static_assert(sizeof(struct zerosu_cmd) % 8 == 0, "zerosu_cmd must be 8-aligned");
_Static_assert(_Alignof(struct zerosu_cmd) >= 4, "natural alignment");

/*
 * The whole point of the explicit pad: a 32 bit task and a 64 bit kernel must
 * derive the same ioctl number. _IOC_* encodes the direction, size, type and
 * nr, so identical size plus identical field offsets means compat_ioctl() can
 * copy the command with no fixups at all.
 */
_Static_assert(sizeof(struct zerosu_cmd) == 24,
	       "ioctl encoding must match between 32 and 64 bit userspace");

/* ---- every other struct: 8 byte sized, and internally aligned --------- */
_Static_assert(sizeof(struct zerosu_info) % 8 == 0, "info 8-aligned size");
_Static_assert(offsetof(struct zerosu_info, abi_version) == 0, "info @0");
_Static_assert(offsetof(struct zerosu_info, _pad) == 24, "info pad @24");
_Static_assert(offsetof(struct zerosu_info, sess_name) == 32, "info name @32");
_Static_assert(offsetof(struct zerosu_info, domain) == 48, "info domain @48");
_Static_assert(offsetof(struct zerosu_info, version) == 112, "info version @112");
_Static_assert(sizeof(struct zerosu_info) == 144, "info is 144 bytes");

_Static_assert(sizeof(struct zerosu_profile) % 8 == 0, "profile 8-aligned");
_Static_assert(offsetof(struct zerosu_profile, groups) == 24, "groups @24");
_Static_assert(sizeof(struct zerosu_profile) == 88, "profile is 88 bytes");

_Static_assert(sizeof(struct zerosu_status) % 8 == 0, "status 8-aligned");
_Static_assert(offsetof(struct zerosu_status, _pad) == 16, "status pad @16");
_Static_assert(offsetof(struct zerosu_status, events_sent) == 24, "sent @24");
_Static_assert(offsetof(struct zerosu_status, events_dropped) == 32, "dropped @32");
_Static_assert(offsetof(struct zerosu_status, grants) == 40, "grants @40");
_Static_assert(offsetof(struct zerosu_status, pending_events) == 48, "pending @48");
_Static_assert(sizeof(struct zerosu_status) == 56, "status is 56 bytes");

_Static_assert(sizeof(struct zerosu_event) % 8 == 0, "event 8-aligned");
_Static_assert(offsetof(struct zerosu_event, type) == 8, "event type @8");
_Static_assert(offsetof(struct zerosu_event, payload) == 16, "payload @16");
_Static_assert(sizeof(struct zerosu_event) == 80, "event is 80 bytes");

/* ---- constants ------------------------------------------------------- */
_Static_assert(ZSU_ABI_VERSION == 1, "abi version");
_Static_assert(ZSU_GATEWAY_MAGIC1 == 0x5A455255u, "magic1");
_Static_assert(ZSU_GATEWAY_MAGIC2 == 0x00005355u, "magic2");
_Static_assert(ZSU_SESSION_PLAIN == 0, "plain session");
_Static_assert(ZSU_SESSION_SU == 1, "su session");
_Static_assert(ZSU_MAX_SESSIONS == 8, "session cap");
_Static_assert(ZSU_PERM_ANY == 0x01u && ZSU_PERM_KEY == 0x02u &&
	       ZSU_PERM_ENROLL == 0x04u && ZSU_PERM_ROOT == 0x08u, "perm bits");

/* command ids must stay in the 0x8000..0x8008 block, in order */
_Static_assert(ZSU_CMD_PING == 0x8000, "cmd ping");
_Static_assert(ZSU_CMD_GET_INFO == 0x8001, "cmd info");
_Static_assert(ZSU_CMD_AUTH_VERIFY == 0x8002, "cmd verify");
_Static_assert(ZSU_CMD_AUTH_SET_KEY == 0x8003, "cmd setkey");
_Static_assert(ZSU_CMD_GET_PROFILE == 0x8004, "cmd profile");
_Static_assert(ZSU_CMD_ELEVATE == 0x8005, "cmd elevate");
_Static_assert(ZSU_CMD_ELEVATE_TASK == 0x8006, "cmd elevate_task");
_Static_assert(ZSU_CMD_GET_STATUS == 0x8007, "cmd status");
_Static_assert(ZSU_CMD_NEXT_EVENT == 0x8008, "cmd next_event");

int main(void)
{
	/*
	 * Runtime echo of the one number that actually has to agree across
	 * ABIs, so a mismatch shows up in CI logs and not just in the build.
	 */
	printf("zerosu abi %d: cmd=%zu info=%zu profile=%zu status=%zu event=%zu\n",
	       ZSU_ABI_VERSION,
	       sizeof(struct zerosu_cmd), sizeof(struct zerosu_info),
	       sizeof(struct zerosu_profile), sizeof(struct zerosu_status),
	       sizeof(struct zerosu_event));
	printf("zerosu ioctl(ping)=0x%08lx\n",
	       (unsigned long)ZSU_IO(ZSU_IOC_NR(ZSU_CMD_PING)));
	return 0;
}