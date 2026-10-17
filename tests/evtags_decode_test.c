// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - tests/evtags_decode_test.c
 *
 * Regression test for the EventLog decoder in userspace/daemon/proc_monitor.c.
 *
 * The decoder is static, so this translation unit includes the .c directly and
 * supplies the handful of symbols proc_monitor.c links against. The payloads
 * are built exactly the way AOSP's liblog builds them:
 *
 *   __android_log_bwrite(tag, list, len) writes
 *     [int32 tag][EVENT_TYPE_LIST=3][element_count][elements...]
 *   and each element is [type byte][value], where a STRING is
 *     [EVENT_TYPE_STRING=2][int32 length][length bytes] with no NUL.
 *
 * Every case below is something the decoder got wrong before this test
 * existed: the 2-byte list header and the per-element type byte were skipped
 * blindly, and strings were treated as NUL terminated.
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>

/* ---- symbols proc_monitor.c depends on ---- */
int zsu_verbose;
void zsu_log(const char *fmt, ...) { (void)fmt; }

static int inject_calls;
static uid_t inject_uid;
int ns_inject(int pid_dirfd, uid_t uid)
{
	(void)pid_dirfd;
	inject_calls++;
	inject_uid = uid;
	return 0;
}

static int pkg_match;		/* 1 => policy_pkg_appid reports a match */
static uint32_t pkg_appid;	/* appid reported on a match */
static char seen_base[256];
int policy_pkg_appid(const char *pkg, uint32_t *appid)
{
	snprintf(seen_base, sizeof(seen_base), "%s", pkg);
	if (!pkg_match)
		return -1;
	*appid = pkg_appid;
	return 0;
}

static int allowed;
int policy_uid_allowed(uid_t uid) { (void)uid; return allowed; }

/* ---- the code under test (brings in the static decoder) ---- */
#include "proc_monitor.c"

/* ---- AOSP-style encoder ---- */
static uint8_t buf[4096];
static size_t pos;

static void put_u8(uint8_t v) { buf[pos++] = v; }
static void put_i32(int32_t v) { memcpy(buf + pos, &v, 4); pos += 4; }
static void put_int(int32_t v) { put_u8(EV_TYPE_INT); put_i32(v); }
static void put_string(const char *s)
{
	int32_t n = (int32_t)strlen(s);

	put_u8(EV_TYPE_STRING);
	put_i32(n);
	memcpy(buf + pos, s, (size_t)n);
	pos += (size_t)n;
}
static void begin(int32_t tag, uint8_t count)
{
	pos = 0;
	put_i32(tag);
	put_u8(EV_TYPE_LIST);
	put_u8(count);
}

static int failures;

static void check(int cond, const char *what)
{
	if (!cond) {
		printf("FAIL: %s\n", what);
		failures++;
	} else {
		printf("ok:   %s\n", what);
	}
}

int main(void)
{
	pid_t self = getpid();
	uid_t me = getuid();

	/* 1. am_proc_bound decodes user/pid/name and injects the right uid. */
	pkg_match = 1;
	pkg_appid = (uint32_t)(me % 100000u);
	allowed = 1;
	inject_calls = 0;
	seen_base[0] = '\0';

	begin(TAG_AM_PROC_BOUND, 3);
	put_int(0);			/* User */
	put_int((int32_t)self);		/* PID  */
	put_string("com.example.app:remote");
	parse_event(buf, pos);

	check(inject_calls == 1, "bound: injection attempted");
	check(inject_uid == me, "bound: uid reconstructed from user+appid");
	check(strcmp(seen_base, "com.example.app") == 0,
	      "bound: ':suffix' stripped");

	/* 2. A uid that is not allowed must not reach the /proc open. */
	allowed = 0;
	inject_calls = 0;
	begin(TAG_AM_PROC_BOUND, 3);
	put_int(0);
	put_int((int32_t)self);
	put_string("com.example.app");
	parse_event(buf, pos);
	check(inject_calls == 0, "bound: gated uid is not injected");

	/* 3. am_proc_start records (pid,uid) in the fallback ring. */
	ring_count = 0;
	ring_head = 0;
	allowed = 1;
	pkg_match = 0;			/* force the ring fallback path */
	begin(TAG_AM_PROC_START, 6);
	put_int(0);			/* User */
	put_int((int32_t)self);		/* PID  */
	put_int((int32_t)me);		/* UID  */
	put_string("com.custom");
	put_string("whatever");
	put_string("Component");
	parse_event(buf, pos);
	{
		uint32_t got = 0;

		check(ring_lookup((int32_t)self, &got) == 1 && got == me,
		      "start: uid recorded in ring");
	}

	/* 4. bound falls back to the ring for an unknown custom name. */
	inject_calls = 0;
	seen_base[0] = '\0';
	begin(TAG_AM_PROC_BOUND, 3);
	put_int(0);
	put_int((int32_t)self);
	put_string("com.custom");
	parse_event(buf, pos);
	check(inject_calls == 1 && inject_uid == me,
	      "bound: ring fallback injects recorded uid");

	/* 5. A string with no NUL terminator decodes to exactly its length. */
	{
		uint8_t raw[64];
		size_t p = 0;
		int32_t tag = TAG_AM_PROC_BOUND, user = 0, pid = (int32_t)self;
		int32_t slen = 2;

		memcpy(raw + p, &tag, 4); p += 4;
		raw[p++] = EV_TYPE_LIST; raw[p++] = 3;
		raw[p++] = EV_TYPE_INT; memcpy(raw + p, &user, 4); p += 4;
		raw[p++] = EV_TYPE_INT; memcpy(raw + p, &pid, 4); p += 4;
		raw[p++] = EV_TYPE_STRING; memcpy(raw + p, &slen, 4); p += 4;
		memcpy(raw + p, "AB", 2); p += 2;	/* declared length 2 */
		memcpy(raw + p, "ZZZZ", 4); p += 4;	/* a scanner would eat this */
		pkg_match = 1; pkg_appid = 0; allowed = 1;
		inject_calls = 0; seen_base[0] = '\0';
		parse_event(raw, p);
		check(strcmp(seen_base, "AB") == 0,
		      "bound: string length honoured, no NUL scan");
	}

	/* 6. A truncated payload is dropped, not misread. */
	allowed = 1;
	pkg_match = 1;
	inject_calls = 0;
	begin(TAG_AM_PROC_BOUND, 3);
	put_int(0);
	parse_event(buf, pos);		/* missing pid + name */
	check(inject_calls == 0, "truncated: no injection");

	printf("%s (%d failures)\n",
	       failures ? "RESULT: FAIL" : "RESULT: PASS", failures);
	return failures != 0;
}
