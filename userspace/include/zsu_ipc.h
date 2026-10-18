/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ZeroSU - userspace/include/zsu_ipc.h
 *
 * Every constant and struct that two separately-built components have to
 * agree on:
 *
 *   - the on-disk / runtime layout under /data/adb/zerosu,
 *   - the patch slot that turns a zerosud ELF into a key holder,
 *   - the fixed-descriptor self-pipe protocol between zsu_stub and zerosud,
 *   - the control-socket protocol between zsu_ctl and zerosud.
 *
 * It is deliberately header-only and dependency-free (no libc headers beyond
 * <stdint.h>), so zsu_stub, which is exec'd as an app and links nothing, can
 * use it too.
 */

#ifndef ZSU_IPC_H
#define ZSU_IPC_H

#include <stdint.h>

#include "zerosu.h"

/* ------------------------------------------------------------------ */
/* runtime layout                                                      */
/* ------------------------------------------------------------------ */

/*
 * Everything lives under one 0711 directory so adb shell (uid 2000, gid
 * shell) can traverse to ctl.sock, while untrusted apps are stopped by the
 * 0700 uids/ subdirectory and by the shell_data_file label on the socket
 * inode. The per-uid su stub is three levels down, behind that 0700.
 */
#define ZSU_BASE_DIR		"/data/adb/zerosu"
#define ZSU_BIN_DIR		ZSU_BASE_DIR "/bin"
#define ZSU_STUB_BIN		ZSU_BIN_DIR "/zsu_stub"
#define ZSU_CTL_SOCK		ZSU_BASE_DIR "/ctl.sock"
#define ZSU_UIDS_DIR		ZSU_BASE_DIR "/uids"
#define ZSU_GRANTS_FILE		ZSU_BASE_DIR "/grants"

#define ZSU_PACKAGES_LIST	"/data/system/packages.list"
#define ZSU_CGROUP_ROOT		"/sys/fs/cgroup"
#define ZSU_LOGDR_SOCK		"/dev/socket/logdr"

/* Longest path this tree can ever build: base + /uids/<uid>/upper/su. */
#define ZSU_PATH_MAX		512
#define ZSU_PKG_MAX		256
#define ZSU_CTL_MSG_MAX		512

/* ------------------------------------------------------------------ */
/* patch slot                                                          */
/* ------------------------------------------------------------------ */

/*
 * zerosud embeds exactly one of these, initialised to the magic followed by
 * 64 zero bytes and placed in .data (never .rodata: it is wiped at runtime
 * with explicit_bzero). zsu_ctl patch finds the unique unpatched slot in the
 * file image, writes 64 bytes of key material after the magic, and prints
 * the key once. There is no separate key file anywhere on disk.
 */
#define ZSU_PATCH_MAGIC		"ZSUKEY00"
#define ZSU_PATCH_MAGIC_LEN	8
#define ZSU_PATCH_KEY_LEN	64

struct zsu_patch_slot {
	char    magic[ZSU_PATCH_MAGIC_LEN];
	uint8_t key[ZSU_PATCH_KEY_LEN];
};

/* ------------------------------------------------------------------ */
/* zsu_stub <-> zerosud self-pipe protocol                             */
/* ------------------------------------------------------------------ */

/*
 * The stub is exec'd as /system/bin/su inside an app's mount namespace. It
 * cannot connect to any socket (there are none reachable from an app), so it
 * hands the daemon two anonymous pipes parked on fixed descriptors and rings
 * a doorbell by opening its own binary. The daemon reads the request out of
 * /proc/<pid>/fd/3 and writes the ack into /proc/<pid>/fd/5.
 */
#define ZSU_STUB_REQ_RD_FD	3	/* read end: contains "ZSU3" */
#define ZSU_STUB_ACK_RD_FD	4	/* read end of the ack pipe */
#define ZSU_STUB_ACK_WR_FD	5	/* write end of the ack pipe */

#define ZSU_STUB_REQ_MAGIC	"ZSU3"
#define ZSU_STUB_REQ_MAGIC_LEN	4

#define ZSU_RDV_OK		0x06	/* the one ack byte */
#define ZSU_STUB_ACK_TIMEOUT_MS	10000

/* ------------------------------------------------------------------ */
/* zsu_ctl <-> zerosud control socket protocol                         */
/* ------------------------------------------------------------------ */

enum zsu_ctl_op {
	ZSU_CTL_PING = 1,
	ZSU_CTL_STATUS,
	ZSU_CTL_ALLOW,
	ZSU_CTL_REVOKE,
	ZSU_CTL_LIST,
	ZSU_CTL_SHELL,
	ZSU_CTL_STOP,			/* SuperKey-gated: daemon exits cleanly */
};

struct zsu_ctl_req {
	uint32_t op;			/* ZSU_CTL_* */
	uint32_t uid;			/* allow/revoke target, 0 => resolve pkg */
	uint32_t pid;			/* shell: the caller's own pid */
	uint32_t flags;			/* reserved, must be 0 */
	uint64_t start_time;		/* shell: caller's /proc/self/stat #22 */
	uint8_t  key[ZSU_PATCH_KEY_LEN];	/* shell: SuperKey proof */
	char     pkg[ZSU_PKG_MAX];	/* allow/revoke: package name */
};

struct zsu_ctl_resp {
	int32_t  status;		/* 0 or a negative errno */
	uint32_t uid;			/* affected uid, if any */
	uint32_t count;			/* list size / affected count */
	uint32_t flags;
	uint64_t data;			/* abi version, session type, ... */
	char     msg[ZSU_CTL_MSG_MAX];	/* human-readable text / list body */
};

#endif /* ZSU_IPC_H */
