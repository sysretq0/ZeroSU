/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ZeroSU - kernel/include/uapi/zerosu.h
 *
 * The single userspace/kernel contract. Mirrored verbatim by
 * userspace/include/zerosu.h, which includes this file.
 *
 * Layout rules, all enforced by tests/abi_layout.c:
 *   - every struct is padded to an 8 byte boundary,
 *   - struct zerosu_cmd is exactly 24 bytes and is all __u32,
 *   - therefore a 32 bit compat task and a 64 bit kernel agree on every
 *     field offset *and* on the _IOC encoding (which embeds sizeof), so
 *     compat_ioctl() can copy the command verbatim with no fixups.
 *
 * Rule 3 is the reason for the explicit __u32 reserved in zerosu_cmd: five
 * __u32 fields is 20 bytes, and 20 is neither 8 byte aligned nor a stable
 * size for a struct that also gets embedded in an ioctl number.
 */

#ifndef _UAPI_ZEROSU_H
#define _UAPI_ZEROSU_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <linux/types.h>
#include <linux/ioctl.h>
#endif

#define ZSU_ABI_VERSION		2

/* Gateway handshake. MAGIC1 is also the per command echo value. */
#define ZSU_GATEWAY_MAGIC1	0x5A455255u	/* "ZERU" */
#define ZSU_GATEWAY_MAGIC2	0x00005355u	/* "SU\0\0" */

#define ZSU_CMD_MAGIC		ZSU_GATEWAY_MAGIC1

/* Session flavours handed out by the gateway. */
#define ZSU_SESSION_PLAIN	0	/* [zerosu]      */
#define ZSU_SESSION_SU		1	/* [zerosu_su]   */
#define ZSU_MAX_SESSIONS	8

/*
 * The gateway is reached through reboot(2).
 *
 * Verified against SYSCALL_DEFINE4(reboot, int, magic1, int, magic2,
 * unsigned int, cmd, void __user *, arg) in kernel/reboot.c on 5.10 and
 * 6.18. That is the order the *kernel* sees, which is not the order of the
 * libc reboot(int cmd, int magic1, int magic2, ...) wrapper - that wrapper
 * reorders. Userspace must therefore issue the raw syscall:
 *
 *   syscall(__NR_reboot, ZSU_GATEWAY_MAGIC1, ZSU_GATEWAY_MAGIC2, mode, &out_fd)
 *
 * PARAM1 = magic1  = ZSU_GATEWAY_MAGIC1
 * PARAM2 = magic2  = ZSU_GATEWAY_MAGIC2
 * PARAM3 = mode    = ZSU_SESSION_PLAIN | ZSU_SESSION_SU
 * PARAM4 = out_fd  = int * , receives the session fd
 *
 * No extra safety net is needed in the kernel handler: reboot() rejects the
 * magic pair with -EINVAL before its switch(cmd), because ZSU_GATEWAY_MAGIC1
 * is not LINUX_REBOOT_MAGIC1 (0xfee1dead). An unprivileged caller gets
 * -EPERM even earlier. Nothing reaches pm_suspend().
 */
#define ZSU_GATEWAY_CMD		__NR_reboot

/* Command ids. 0x8000 keeps them clear of the < 0x8000 ioctl space. */
enum {
	ZSU_CMD_PING		= 0x8000,
	ZSU_CMD_GET_INFO	= 0x8001,
	ZSU_CMD_AUTH_VERIFY	= 0x8002,
	ZSU_CMD_AUTH_SET_KEY	= 0x8003,
	ZSU_CMD_GET_PROFILE	= 0x8004,
	ZSU_CMD_ELEVATE		= 0x8005,
	ZSU_CMD_ELEVATE_TASK	= 0x8006,
	ZSU_CMD_GET_STATUS	= 0x8007,
	ZSU_CMD_NEXT_EVENT	= 0x8008,
};

/* Permission classes, carried in zerosu_cmd.flags. */
#define ZSU_PERM_ANY		0x01u	/* plain session */
#define ZSU_PERM_KEY		0x02u	/* key enrolled on this session */
#define ZSU_PERM_ENROLL		0x04u	/* may (re)enroll a key */
#define ZSU_PERM_ROOT		0x08u	/* uid 0 only */

/*
 * Payload and reply sizes.
 *
 * The wire format is one zerosu_cmd header at arg, immediately followed by
 * the payload (hdr.inlen bytes) and then the reply (a fixed size per
 * command). The kernel validates hdr.inlen against the table below per
 * command and refuses anything else, and fetches every byte exactly once -
 * there is no second copy_from_user of the same payload.
 */
#define ZSU_KEY_MAX		64	/* AUTH_SET_KEY: raw key bytes */
#define ZSU_DIGEST_LEN		32	/* AUTH_VERIFY: digest bytes */

#define ZSU_PAYLOAD_NONE	0u
/*
 * These use __u32, not u32: this header is included from userspace too, and
 * u32 is a kernel-internal type that <linux/types.h> does not define outside
 * the kernel build. Every other type in this header is already in the __u*
 * namespace for the same reason.
 */
#define ZSU_PAYLOAD_KEY		((__u32)ZSU_KEY_MAX)
#define ZSU_PAYLOAD_DIGEST	((__u32)ZSU_DIGEST_LEN)

/* Capability bits reported by ZSU_CMD_GET_PROFILE. */
#define ZSU_CAP_ELEVATE		0x0001u
#define ZSU_CAP_ELEVATE_TASK	0x0002u
#define ZSU_CAP_KEY_ENROLL	0x0004u
#define ZSU_CAP_EVENTS		0x0008u
#define ZSU_CAP_INFO		0x0010u

/*
 * Elevation modes, carried in zerosu_cmd.arg for ELEVATE and ELEVATE_TASK.
 *
 * SELF is the calling thread. TASK names a pid in the caller's pid namespace
 * and is installed without commit_creds(), because that function may only
 * ever act on `current`.
 */
#define ZSU_ELEVATE_MODE_SELF	0u
#define ZSU_ELEVATE_MODE_TASK	1u

/* Event types delivered by ZSU_CMD_NEXT_EVENT. */
#define ZSU_EVENT_NONE		0u
#define ZSU_EVENT_AUTH_OK	1u
#define ZSU_EVENT_AUTH_FAIL	2u
#define ZSU_EVENT_ELEVATED	3u
#define ZSU_EVENT_ERROR		4u

/*
 * Per-session event ring depth. NEXT_EVENT is polled and pops one event at a
 * time; when the ring is full the newest event is dropped and counted in
 * zerosu_status.events_dropped rather than silently overwriting an older one.
 */
#define ZSU_EVENT_RING		16

/**
 * struct zerosu_cmd - the fixed size command header
 * @magic:  ZSU_CMD_MAGIC; the kernel rejects anything else
 * @opcode: ZSU_CMD_*
 * @flags:  RESERVED, must be 0. The kernel derives its own ZSU_PERM_*
 *          mask from session state; a non-zero value is -EINVAL.
 * @arg:    multiplexed by opcode: ZSU_ELEVATE_MODE_* for ZSU_CMD_ELEVATE,
 *          the target pid for ZSU_CMD_ELEVATE_TASK (whose mode follows from
 *          the opcode), unused elsewhere
 * @inlen:  payload bytes that follow this header, 0 for none
 * @__reserved: explicit pad, keeps sizeof at 24 on every architecture
 */
struct zerosu_cmd {
	__u32 magic;
	__u32 opcode;
	__u32 flags;
	__u32 arg;
	__u32 inlen;
	__u32 __reserved;
};

/** struct zerosu_info - reply to ZSU_CMD_GET_INFO */
struct zerosu_info {
	__u32 abi_version;
	__u32 session_type;
	__u32 max_sessions;
	__u32 features;
	__u32 kernel_version;
	__u64 _pad;		/* explicit: forces 8 byte alignment */
	char sess_name[16];
	char domain[64];
	char version[32];
};

/** struct zerosu_profile - reply to ZSU_CMD_GET_PROFILE */
struct zerosu_profile {
	__u32 caps;		/* ZSU_CAP_* */
	__u32 uid;
	__u32 gid;
	__u32 ngroups;
	__u64 _pad;		/* explicit: forces 8 byte alignment */
	__u32 groups[16];
};

/** struct zerosu_status - reply to ZSU_CMD_GET_STATUS */
struct zerosu_status {
	__u32 flags;
	__u32 session_type;
	__u32 elevated;
	__u32 last_error;	/* negative errno */
	__u64 _pad;		/* explicit: forces 8 byte alignment */
	__u64 events_sent;
	__u64 events_dropped;
	__u64 grants;			/* successful elevations */
	__u64 pending_events;		/* events still queued for NEXT_EVENT */
};

/** struct zerosu_event - reply to ZSU_CMD_NEXT_EVENT */
struct zerosu_event {
	__u64 seq;
	__u32 type;		/* ZSU_EVENT_* */
	__u32 flags;
	char payload[64];
};

#define ZSU_IOC_MAGIC	'Z'
#define ZSU_IOC_NR(cmd)	((cmd) - ZSU_CMD_PING)

/*
 * sizeof(struct zerosu_cmd) is part of the ioctl encoding. It is identical
 * for 32 and 64 bit tasks because the struct is 8 byte aligned and all
 * __u32, which is what lets compat_ioctl() do a verbatim copy.
 */
#define ZSU_IO(_nr)		_IOWR(ZSU_IOC_MAGIC, (_nr), struct zerosu_cmd)

#endif /* _UAPI_ZEROSU_H */