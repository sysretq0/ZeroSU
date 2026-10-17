// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - userspace/daemon/proc_monitor.c
 *
 * The spawn monitor. It subscribes to the binary events log through
 * /dev/socket/logdr and turns ActivityManager's am_proc_* records into
 * mount-namespace injections - before the new process can ever exec
 * /system/bin/su.
 *
 * Why the events log and not a /proc scan or a netlink proc connector:
 * am_proc_bound already carries (User, PID, ProcessName), and logdr is a
 * single SEQPACKET endpoint the daemon can sit on in its epoll loop. There is
 * no polling and no per-process directory walk anywhere in this file.
 *
 * The gate order is the security property. A process name is resolved against
 * the in-RAM packages.list table and the allowed-UID bitmap is consulted
 * *before* a single syscall is made. Only an allowed uid reaches the
 * open("/proc/<pid>") + fstat() + ns_inject sequence.
 *
 * Wire format (Android's, not ours): each SEQPACKET message is one
 * logger_entry_v4 followed by the event message. The header's hdr_size field
 * is authoritative for where the message starts; v4 added the uid field and
 * replaced the old __pad with hdr_size. The message begins with an int32 tag
 * and then the fields declared in EventLogTags.logtags, encoded little-endian:
 *
 *   30010 am_proc_bound  (User|1|5),(PID|1|5),(ProcessName|3)
 *   30014 am_proc_start  (User|1|5),(PID|1|5),(UID|1|5),(ProcessName|3),...
 *
 * am_proc_bound is the fast path. am_proc_start feeds a tiny (pid, uid) ring
 * used only as a fallback for process names that are not "<pkg>" or
 * "<pkg>:suffix" - a manifest can declare an arbitrary android:process, and
 * that name will never match packages.list.
 */


#include "zsu_daemon.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

/*
 * logd's reader protocol wants a comma separated list of log_id *indices*,
 * not a bitmask: for each one it does `logMask |= 1 << index`. LOG_ID_EVENTS
 * is index 2, so 2 is the number that selects the event log. Sending the
 * pre-shifted (1 << LOG_ID_EVENTS) value would silently subscribe to
 * LOG_ID_CRASH instead, and the daemon would never see a spawn event.
 */
#define ZSU_LOG_ID_EVENTS	2

#define TAG_AM_PROC_BOUND	30010
#define TAG_AM_PROC_START	30014

#define ZSU_RING		16

struct logger_entry_v4 {
	uint16_t len;		/* message length */
	uint16_t hdr_size;	/* header length, authoritative */
	int32_t  pid;
	int32_t  tid;
	int32_t  sec;
	int32_t  nsec;
	uint32_t lid;
	uint32_t uid;
};

static int logdr_fd = -1;

struct ring_ent {
	int32_t  pid;
	uint32_t uid;
};

static struct ring_ent ring[ZSU_RING];
static int ring_head;
static int ring_count;

static void ring_push(int32_t pid, uint32_t uid)
{
	ring[ring_head].pid = pid;
	ring[ring_head].uid = uid;
	ring_head = (ring_head + 1) % ZSU_RING;
	if (ring_count < ZSU_RING)
		ring_count++;
}

static int ring_lookup(int32_t pid, uint32_t *uid)
{
	int i;

	for (i = 0; i < ring_count; i++) {
		int idx = (ring_head - 1 - i + 2 * ZSU_RING) % ZSU_RING;

		if (ring[idx].pid == pid) {
			*uid = ring[idx].uid;
			return 1;
		}
	}
	return 0;
}

/* ------------------------------------------------------------------ */
/* field decoding                                                      */
/* ------------------------------------------------------------------ */

/*
 * Android's binary EventLog element types (private/android_logger.h). Each
 * element is one type byte followed by its value; a STRING's value is an int32
 * length followed by that many bytes, with no NUL terminator. A nested LIST is
 * rejected, which is safe because no am_* field is itself a list.
 */
#define EV_TYPE_INT	0
#define EV_TYPE_LONG	1
#define EV_TYPE_STRING	2
#define EV_TYPE_LIST	3
#define EV_TYPE_FLOAT	4

struct ev_elem {
	uint8_t	type;
	int32_t	i;	/* INT / FLOAT (bit pattern) */
	int64_t	l;	/* LONG */
	const char *s;	/* STRING: not NUL terminated */
	size_t	slen;
};

static int rd_u8(const uint8_t **p, size_t *rem, uint8_t *out)
{
	if (*rem < 1)
		return -1;
	*out = **p;
	(*p)++;
	(*rem)--;
	return 0;
}

static int rd_i32(const uint8_t **p, size_t *rem, int32_t *out)
{
	if (*rem < 4)
		return -1;
	memcpy(out, *p, 4);
	*p += 4;
	*rem -= 4;
	return 0;
}

/*
 * Decode exactly one element, type byte included. Every read is bounds
 * checked: the payload is attacker-influenced by whichever process logged it.
 * Returns 0 and fills *e, or -1 on a truncated, negative-length or nested
 * element.
 */
static int rd_elem(const uint8_t **p, size_t *rem, struct ev_elem *e)
{
	int32_t sl;

	memset(e, 0, sizeof(*e));
	if (rd_u8(p, rem, &e->type))
		return -1;

	switch (e->type) {
	case EV_TYPE_INT:
		return rd_i32(p, rem, &e->i);
	case EV_TYPE_FLOAT: {
		if (*rem < sizeof(e->i))
			return -1;
		memcpy(&e->i, *p, sizeof(e->i));
		*p += sizeof(e->i);
		*rem -= sizeof(e->i);
		return 0;
	}
	case EV_TYPE_LONG:
		if (*rem < sizeof(e->l))
			return -1;
		memcpy(&e->l, *p, sizeof(e->l));
		*p += sizeof(e->l);
		*rem -= sizeof(e->l);
		return 0;
	case EV_TYPE_STRING:
		if (rd_i32(p, rem, &sl) || sl < 0 || (size_t)sl > *rem)
			return -1;
		e->s = (const char *)*p;
		e->slen = (size_t)sl;
		*p += (size_t)sl;
		*rem -= (size_t)sl;
		return 0;
	default:
		return -1;	/* nested LIST or unknown type */
	}
}

/* An element as a 32 bit integer; LONG/FLOAT are folded down. */
static int ev_ival(const struct ev_elem *e, int32_t *out)
{
	switch (e->type) {
	case EV_TYPE_INT:
	case EV_TYPE_FLOAT:
		*out = e->i;
		return 0;
	case EV_TYPE_LONG:
		*out = (int32_t)e->l;
		return 0;
	default:
		return -1;
	}
}

/* ------------------------------------------------------------------ */
/* injection                                                           */
/* ------------------------------------------------------------------ */

static void inject_pid(int32_t pid, uid_t uid)
{
	char path[64];
	struct stat st;
	int dfd;

	snprintf(path, sizeof(path), "/proc/%d", (int)pid);
	dfd = open(path, O_DIRECTORY | O_CLOEXEC);
	if (dfd < 0)
		return;

	/*
	 * The pinned /proc directory must belong to the uid we decided on,
	 * not merely to a process that happened to reuse the pid between the
	 * event and this open. A mismatch is a silent skip: no injection and
	 * no elevation for an identity we did not verify.
	 */
	if (fstat(dfd, &st) || (uid_t)st.st_uid != uid) {
		close(dfd);
		return;
	}

	if (ns_inject(dfd, uid) == 0 && zsu_verbose)
		zsu_log("inject pid %d uid %u", (int)pid, (unsigned)uid);

	close(dfd);
}

static void strip_process_suffix(const char *name, size_t nlen, char *out,
				 size_t cap)
{
	size_t i = 0;

	while (i < nlen && name[i] != ':' && i + 1 < cap) {
		out[i] = name[i];
		i++;
	}
	out[i] = '\0';
}

static void handle_proc_bound(int32_t user, int32_t pid, const char *name,
			      size_t nlen)
{
	char base[ZSU_PKG_MAX];
	uint32_t appid, ruid;
	uid_t uid;
	int have = 0;

	/*
	 * Everything up to here is in RAM: strip, hash lookup, bitmap test.
	 * No syscall is made for a uid that is not granted.
	 */
	strip_process_suffix(name, nlen, base, sizeof(base));
	if (!policy_pkg_appid(base, &appid)) {
		uid = (uid_t)((uint32_t)user * 100000u + appid);
		have = 1;
	} else if (ring_lookup(pid, &ruid)) {
		uid = (uid_t)ruid;
		have = 1;
	}

	if (!have || !policy_uid_allowed(uid))
		return;

	inject_pid(pid, uid);
}

static void parse_event(const uint8_t *msg, size_t len)
{
	const uint8_t *p = msg;
	size_t rem = len;
	struct ev_elem e;
	int32_t tag;

	if (rd_i32(&p, &rem, &tag))
		return;

	/*
	 * The body is a LIST header [EVENT_TYPE_LIST][element_count]. The
	 * writer omits those two bytes when the event has fewer than two
	 * elements; am_proc_* has several, so the header is present there, but
	 * only consuming a leading LIST type byte (rather than assuming the
	 * count) also handles the stripped form.
	 */
	if (rem >= 1 && *p == EV_TYPE_LIST) {
		uint8_t count;

		p++;
		rem--;
		if (rd_u8(&p, &rem, &count))
			return;
	}

	switch (tag) {
	case TAG_AM_PROC_BOUND: {
		int32_t user, pid;

		if (rd_elem(&p, &rem, &e) || ev_ival(&e, &user))
			return;
		if (rd_elem(&p, &rem, &e) || ev_ival(&e, &pid))
			return;
		if (rd_elem(&p, &rem, &e) || e.type != EV_TYPE_STRING)
			return;
		handle_proc_bound(user, pid, e.s, e.slen);
		break;
	}
	case TAG_AM_PROC_START: {
		int32_t user, pid, uid;

		if (rd_elem(&p, &rem, &e) || ev_ival(&e, &user))
			return;
		if (rd_elem(&p, &rem, &e) || ev_ival(&e, &pid))
			return;
		if (rd_elem(&p, &rem, &e) || ev_ival(&e, &uid))
			return;
		(void)user;	/* recorded only for completeness */
		ring_push(pid, (uint32_t)uid);
		break;
	}
	default:
		break;
	}
}

static void handle_entry(const uint8_t *buf, size_t n)
{
	struct logger_entry_v4 e;
	size_t hdr;

	if (n < sizeof(e))
		return;

	/* The recv buffer has no alignment guarantee; copy the header out. */
	memcpy(&e, buf, sizeof(e));

	hdr = e.hdr_size;
	if (hdr < sizeof(e))
		hdr = sizeof(e);
	if (hdr + e.len > n)
		return;

	parse_event(buf + hdr, e.len);
}

/* ------------------------------------------------------------------ */
/* logdr                                                               */
/* ------------------------------------------------------------------ */

static int logdr_connect(void)
{
	struct sockaddr_un sa;
	char cmd[32];
	int fd, n;

	n = snprintf(cmd, sizeof(cmd), "stream lids=%d", ZSU_LOG_ID_EVENTS);
	if (n <= 0 || (size_t)n >= sizeof(cmd))
		return -EINVAL;

	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;

	memset(&sa, 0, sizeof(sa));
	sa.sun_family = AF_UNIX;
	if (strlen(ZSU_LOGDR_SOCK) >= sizeof(sa.sun_path)) {
		close(fd);
		return -ENAMETOOLONG;
	}
	strcpy(sa.sun_path, ZSU_LOGDR_SOCK);

	if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
		int e = errno;

		close(fd);
		return -e;
	}

	/* logd parses the command as a plain string; no length prefix. */
	if (send(fd, cmd, (size_t)n, 0) < 0) {
		int e = errno;

		close(fd);
		return -e;
	}

	if (logdr_fd >= 0)
		close(logdr_fd);
	logdr_fd = fd;
	return 0;
}

int proc_monitor_init(void)
{
	return logdr_connect();
}

int proc_monitor_fd(void)
{
	return logdr_fd;
}

void proc_monitor_drain(void)
{
	uint8_t buf[4096 + 256];

	if (logdr_fd < 0)
		return;

	for (;;) {
		ssize_t n = recv(logdr_fd, buf, sizeof(buf), 0);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EAGAIN || errno == EWOULDBLOCK)
				break;
			/* logd went away; a later timer tick reconnects. */
			close(logdr_fd);
			logdr_fd = -1;
			break;
		}
		if (n == 0) {
			close(logdr_fd);
			logdr_fd = -1;
			break;
		}
		handle_entry(buf, (size_t)n);
	}
}
