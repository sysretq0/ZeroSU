// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - kernel/supercall.c
 *
 * The ioctl surface behind the session fd. Everything privileged happens
 * here or in elevate.c; this file's own job is to authenticate the caller and
 * refuse everything else.
 *
 * Wire format: one struct zerosu_cmd at @arg, immediately followed by the
 * payload (hdr.inlen bytes) and then the reply (fixed size per command).
 * Because the UAPI structs are all __u32/__u64 and 8 byte aligned, a 32 bit
 * compat task and a 64 bit kernel see identical offsets and identical ioctl
 * numbers, which is why compat_ioctl can be a verbatim copy.
 *
 * Scope discipline, in order of importance:
 *   1. No double-fetch. Every payload byte is copied from user exactly once,
 *      into a kernel buffer that is then validated. Nothing is re-read after
 *      it has been used, so a userspace race cannot change it mid-check.
 *   2. Strict per-command payload sizes. A command that does not take a
 *      payload must arrive with inlen == 0, and one that does must match
 *      exactly. No ranges, no minimums.
 *   3. The key comparison is constant time, and there is no fallback to a
 *      variable-time compare if the kernel helper is missing: the command
 *      fails closed instead.
 *   4. No SHASH_DESC_ON_STACK. It expands to a VLA, which GKI builds with
 *      -Werror=vla. The descriptor is preallocated once, under a mutex.
 */

#include <crypto/hash.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>

#include "include/zerosu.h"

/*
 * Module wide crypto state.
 *
 * sha256_tfm is allocated once in zerosu_supercall_init() and freed in
 * zerosu_supercall_exit(); allocating a tfm per ioctl would be both slow and
 * unnecessary.
 *
 * sha256_desc is a single descriptor allocated as
 *   sizeof(struct shash_desc) + crypto_shash_descsize(tfm)
 * which is the documented way to get the per-transform context that follows
 * the descriptor. It is deliberately *not* a stack VLA.
 */
static struct crypto_shash *sha256_tfm;
static struct shash_desc *sha256_desc;
static DEFINE_MUTEX(sha_lock);

/*
 * Enrolled key material. Both fields live under key_lock: the ioctl can be
 * driven from any thread that holds a dup() of the session fd, so
 * "enrolled" and the digest are not per-task state.
 */
static DEFINE_MUTEX(key_lock);
static bool key_enrolled;
static u8 key_digest[ZSU_DIGEST_LEN];

/*
 * Constant-time digest comparison.
 *
 * No symbol lookup. The kernel's constant-time helper is a static inline
 * wrapper around __crypto_memneq, which is not exported, so resolving it by
 * name would have meant guessing both its spelling and its return type
 * (unsigned long, not int) - and an int (*) typedef against a
 * unsigned-long-returning target is exactly the kind of type mismatch that
 * makes kCFI abort the call on 6.1+.
 *
 * We only ever compare two 32 byte SHA-256 digests, so a fixed four word
 * XOR accumulator is both smaller and stronger than a byte loop: no early
 * exit, and no data-dependent branch anywhere in it. The loads go through
 * memcpy() so this stays free of alignment and strict-aliasing assumptions,
 * and OPTIMIZER_HIDE_VAR keeps the compiler from "optimising" the
 * accumulator away.
 */
static bool zerosu_digest_eq(const u8 *a, const u8 *b)
{
	u64 wa[4], wb[4];
	u64 diff = 0;
	unsigned int i;

	OPTIMIZER_HIDE_VAR(diff);

	memcpy(wa, a, sizeof(wa));
	memcpy(wb, b, sizeof(wb));

	for (i = 0; i < ARRAY_SIZE(wa); i++)
		diff |= wa[i] ^ wb[i];

	return diff == 0;
}

/*
 * Hash buf[0..len) into out[]. Returns 0 or a negative errno.
 *
 * Takes sha_lock itself: sha256_desc and the per-transform context that
 * follows it are shared module state, so two threads hashing at once would
 * interleave writes into the same context.
 */
static int zerosu_digest(const void *buf, size_t len, u8 *out)
{
	int rc;

	mutex_lock(&sha_lock);
	rc = crypto_shash_digest(sha256_desc, buf, len, out);
	mutex_unlock(&sha_lock);

	return rc ? -EFAULT : 0;
}

/* ---------------------------------------------------------------------- */
/* payload validation                                                      */
/* ---------------------------------------------------------------------- */

/*
 * Map a command to its exact payload size. Returns -EINVAL for an unknown
 * command, which is the only place a command id is trusted.
 */
static int zerosu_payload_len(u32 opcode, u32 *len)
{
	switch (opcode) {
	case ZSU_CMD_PING:
	case ZSU_CMD_GET_INFO:
	case ZSU_CMD_GET_PROFILE:
	case ZSU_CMD_GET_STATUS:
	case ZSU_CMD_NEXT_EVENT:
	case ZSU_CMD_ELEVATE:
		*len = ZSU_PAYLOAD_NONE;
		return 0;
	case ZSU_CMD_ELEVATE_TASK:
		*len = ZSU_PAYLOAD_ELEVATE_TASK;
		return 0;
	case ZSU_CMD_AUTH_SET_KEY:
		*len = ZSU_PAYLOAD_KEY;
		return 0;
	case ZSU_CMD_AUTH_VERIFY:
		*len = ZSU_PAYLOAD_DIGEST;
		return 0;
	default:
		return -EINVAL;
	}
}

/*
 * Authorization, derived entirely from kernel state.
 *
 * NOTHING in struct zerosu_cmd is trusted for authorization. The header is
 * caller-supplied, so reading a permission bit out of it is the equivalent of
 * a server honouring a client-supplied "X-Is-Admin: true" header: anyone
 * holding a session fd could set ZSU_PERM_KEY and skip AUTH_VERIFY outright.
 * The mask below is computed only from things the kernel knows:
 *
 *   ZSU_PERM_ENROLL  only while no master key exists *and* the caller is uid
 *                    0, so the privileged bootstrap that inserted the module
 *                    enrolls the device SuperKey once and nothing else can.
 *   ZSU_PERM_KEY     only after this session passed AUTH_VERIFY, i.e. the
 *                    constant-time compare in zerosu_cmd_verify_key().
 *                    ctx->authenticated is written in exactly one place and
 *                    is not reachable from userspace.
 *
 * Caller must hold key_lock.
 */
static u32 zerosu_session_perm(const struct zsu_session *ctx)
{
	u32 perm = ZSU_PERM_ANY;

	if (!key_enrolled && uid_eq(current_uid(), GLOBAL_ROOT_UID))
		perm |= ZSU_PERM_ENROLL;

	if (ctx->authenticated)
		perm |= ZSU_PERM_KEY;

	return perm;
}

/* What a command needs. 0 means "anyone may attempt it". */
static u32 zerosu_perm_required(u32 opcode)
{
	switch (opcode) {
	case ZSU_CMD_AUTH_SET_KEY:
		return ZSU_PERM_ENROLL;
	case ZSU_CMD_GET_PROFILE:
	case ZSU_CMD_ELEVATE:
	case ZSU_CMD_ELEVATE_TASK:
		return ZSU_PERM_KEY;
	case ZSU_CMD_PING:
	case ZSU_CMD_GET_INFO:
	case ZSU_CMD_GET_STATUS:
	case ZSU_CMD_NEXT_EVENT:
	case ZSU_CMD_AUTH_VERIFY:
	default:
		/*
		 * AUTH_VERIFY deliberately needs nothing: it *is* the
		 * authentication, so requiring a permission would be circular.
		 */
		return 0;
	}
}

/*
 * Session flavour is a *request*, not a grant: ctx->type comes from the
 * reboot(2) argument, which the caller also chooses. It is therefore policy,
 * not security - the actual gate on elevation is ZSU_PERM_KEY.
 */
static int zerosu_check_session_type(const struct zsu_session *ctx, u32 opcode)
{
	switch (opcode) {
	case ZSU_CMD_GET_PROFILE:
	case ZSU_CMD_ELEVATE:
	case ZSU_CMD_ELEVATE_TASK:
		if (ctx->type != ZSU_SESSION_SU)
			return -EPERM;
		return 0;
	default:
		return 0;
	}
}

/* ---------------------------------------------------------------------- */
/* individual commands                                                     */
/* ---------------------------------------------------------------------- */

static int zerosu_cmd_set_key(struct zsu_session *ctx, void __user *payload)
{
	u8 digest[ZSU_DIGEST_LEN];
	u8 key[ZSU_KEY_MAX];
	int rc;

	/* Single fetch: the payload is copied once and hashed from the stack. */
	if (copy_from_user(key, payload, ZSU_KEY_MAX))
		return -EFAULT;

	rc = zerosu_digest(key, sizeof(key), digest);
	/* Do not leave key material in a stack frame. */
	memset(key, 0, sizeof(key));
	if (rc)
		return rc;

	lockdep_assert_held(&key_lock);
	memcpy(key_digest, digest, ZSU_DIGEST_LEN);
	key_enrolled = true;

	return 0;
}

/*
 * Prove knowledge of the device master key.
 *
 * This is the only path that grants ZSU_PERM_KEY, so it is deliberately the
 * dullest function in the file.
 */
static long zerosu_cmd_verify_key(struct zsu_session *ctx, void __user *payload)
{
	u8 digest[ZSU_DIGEST_LEN];
	int rc;

	if (copy_from_user(digest, payload, ZSU_DIGEST_LEN))
		return -EFAULT;

	lockdep_assert_held(&key_lock);

	/*
	 * Refuse *before* comparing, and this ordering matters: with no key
	 * enrolled, key_digest is 32 zero bytes, so an attacker-supplied block
	 * of 32 zeros would otherwise match it and authenticate.
	 */
	if (!key_enrolled) {
		memset(digest, 0, sizeof(digest));
		return -ENOKEY;
	}

	rc = zerosu_digest_eq(key_digest, digest) ? 0 : -EACCES;
	memset(digest, 0, sizeof(digest));
	if (rc)
		return rc;

	/* The one and only transition from anonymous to authorized. */
	ctx->authenticated = true;
	ctx->flags |= ZSU_PERM_KEY;

	return 0;
}

/*
 * Push one event onto the session ring.
 *
 * Fixed capacity by design: a session is a short-lived fd, and a full ring
 * drops the newest event and counts it, so a consumer that only reads when it
 * feels like it can tell from events_dropped that it missed something. No
 * allocation, so this is safe from any context the ioctl path runs in.
 */
static void zerosu_push_event_locked(struct zsu_session *ctx, u32 type,
				     const char *text)
{
	struct zerosu_event *ev;

	ctx->event_seq++;

	if (ctx->ring_count >= ZSU_EVENT_RING) {
		ctx->events_dropped++;
		return;
	}

	ev = &ctx->ring[ctx->ring_head];
	memset(ev, 0, sizeof(*ev));
	ev->seq = ctx->event_seq;
	ev->type = type;
	if (text)
		strscpy(ev->payload, text, sizeof(ev->payload));

	ctx->ring_head = (ctx->ring_head + 1) % ZSU_EVENT_RING;
	ctx->ring_count++;
	ctx->events_sent++;
}

/*
 * Record a successful elevation against the session.
 *
 * Lives here rather than in elevate.c on purpose: elevate.c has no session
 * (it is handed a task_struct) and this is the only place that does, so this
 * is the natural point where "the cred was installed" and "the session
 * learned about it" meet.
 */
void zerosu_note_elevated(struct zsu_session *ctx, u32 mode)
{
	if (!ctx)
		return;

	lockdep_assert_held(&ctx->event_lock);

	ctx->elevated = true;
	ctx->grants++;
	ctx->last_grant_mode = mode;
	zerosu_push_event_locked(ctx, ZSU_EVENT_ELEVATED, "uid=0");
}

/*
 * Record an authentication outcome. Used by the AUTH_* handlers so the ring
 * carries the whole session history, not just elevation.
 */
void zerosu_note_auth(struct zsu_session *ctx, bool ok)
{
	if (!ctx)
		return;

	lockdep_assert_held(&ctx->event_lock);
	zerosu_push_event_locked(ctx, ok ? ZSU_EVENT_AUTH_OK :
				 ZSU_EVENT_AUTH_FAIL, ok ? "enrolled" : "denied");
}

/* ---------------------------------------------------------------------- */
/* dispatch                                                                */
/* ---------------------------------------------------------------------- */

long zerosu_supercall_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	struct zsu_session *ctx = file->private_data;
	struct zerosu_cmd hdr;
	void __user *payload;
	u32 want_len;
	long ret;

	if (!ctx)
		return -ENOTTY;

	/* The header is the only thing read before it is validated. */
	if (copy_from_user(&hdr, (void __user *)arg, sizeof(hdr)))
		return -EFAULT;
	if (hdr.magic != ZSU_CMD_MAGIC) {
		ctx->last_error = -EIO;
		return -EIO;
	}

	/*
	 * The request number and the verb have to agree.
	 *
	 * Each command has its own ioctl number (ZSU_IO(ZSU_IOC_NR(op)), which
	 * embeds ZSU_IOC_MAGIC and sizeof(struct zerosu_cmd)), and the same
	 * verb is also carried in hdr.opcode so a single compat_ioctl copy can
	 * serve both. Validating the number against the opcode - rather than
	 * against a fixed one - means the two encodings cannot disagree, and
	 * the payload-length table below remains the single authority on which
	 * opcodes exist. This must run after the header fetch because opcode
	 * lives in the header.
	 */
	if (cmd != ZSU_IO(ZSU_IOC_NR(hdr.opcode))) {
		ctx->last_error = -ENOTTY;
		return -ENOTTY;
	}
	if (hdr.__reserved != 0) {
		ctx->last_error = -EINVAL;
		return -EINVAL;
	}

	/*
	 * flags is reserved and MUST arrive as zero.
	 *
	 * It is not "currently unused, be nice": accepting a caller-supplied
	 * permission mask would hand every unprivileged process with a session
	 * fd the ability to claim ZSU_PERM_KEY and skip AUTH_VERIFY. The
	 * kernel derives the real mask in zerosu_session_perm(). Rejecting the
	 * field outright means a future regression that starts reading it again
	 * fails loudly instead of silently reopening the bypass.
	 */
	if (hdr.flags != 0) {
		ctx->last_error = -EINVAL;
		return -EINVAL;
	}

	/* Exact size or nothing. */
	if (zerosu_payload_len(hdr.opcode, &want_len)) {
		ctx->last_error = -EINVAL;
		return -EINVAL;
	}
	if (hdr.inlen != want_len) {
		ctx->last_error = -EINVAL;
		return -EINVAL;
	}

	payload = (void __user *)((char __user *)arg + sizeof(hdr));

	/*
	 * Two locks, taken in this order everywhere: event_lock nests inside
	 * key_lock nowhere and vice versa, so there is no cycle to deadlock
	 * on. key_lock is held for every command whose authorization depends on
	 * key_enrolled or on this session's authenticated bit.
	 */
	if (hdr.opcode == ZSU_CMD_AUTH_SET_KEY ||
	    hdr.opcode == ZSU_CMD_AUTH_VERIFY ||
	    hdr.opcode == ZSU_CMD_GET_PROFILE ||
	    hdr.opcode == ZSU_CMD_ELEVATE ||
	    hdr.opcode == ZSU_CMD_ELEVATE_TASK)
		mutex_lock(&key_lock);

	if (hdr.opcode == ZSU_CMD_NEXT_EVENT ||
	    hdr.opcode == ZSU_CMD_GET_STATUS)
		mutex_lock(&ctx->event_lock);

	/*
	 * Authorization: derive the caller's mask from kernel state and test
	 * the command's requirement against it. hdr.flags is not an input here
	 * and must never become one.
	 */
	if (zerosu_perm_required(hdr.opcode) & ~zerosu_session_perm(ctx)) {
		ret = -EPERM;
		goto out_perm;
	}

	ret = zerosu_check_session_type(ctx, hdr.opcode);
	if (ret)
		goto out_perm;

	switch (hdr.opcode) {
	case ZSU_CMD_PING: {
		__u32 abi = ZSU_ABI_VERSION;

		if (copy_to_user(payload, &abi, sizeof(abi)))
			ret = -EFAULT;
		break;
	}
	case ZSU_CMD_GET_INFO: {
		struct zerosu_info info;

		memset(&info, 0, sizeof(info));
		info.abi_version = ZSU_ABI_VERSION;
		info.session_type = ctx->type;
		info.max_sessions = ZSU_MAX_SESSIONS;
		info.features = ZSU_CAP_INFO | ZSU_CAP_KEY_ENROLL;
		strscpy(info.sess_name, ctx->type == ZSU_SESSION_SU ?
			"[zerosu_su]" : "[zerosu]", sizeof(info.sess_name));
		strscpy(info.domain, "u:r:zsu:s0", sizeof(info.domain));
		strscpy(info.version, ZSU_VERSION, sizeof(info.version));

		if (copy_to_user(payload, &info, sizeof(info)))
			ret = -EFAULT;
		break;
	}
	case ZSU_CMD_GET_STATUS: {
		struct zerosu_status st;

		memset(&st, 0, sizeof(st));
		st.flags = ctx->flags;
		st.session_type = ctx->type;
		st.elevated = ctx->elevated;
		st.last_error = ctx->last_error;
		st.events_sent = ctx->events_sent;
		st.events_dropped = ctx->events_dropped;
		st.grants = ctx->grants;
		st.pending_events = ctx->ring_count;

		if (copy_to_user(payload, &st, sizeof(st)))
			ret = -EFAULT;
		break;
	}
	case ZSU_CMD_GET_PROFILE: {
		struct zerosu_profile prof;
		const struct cred *cred = current_cred();

		memset(&prof, 0, sizeof(prof));
		prof.caps = ZSU_CAP_INFO | ZSU_CAP_KEY_ENROLL;
		if (cred) {
			prof.uid = __kuid_val(cred->uid);
			prof.gid = __kgid_val(cred->gid);
		}

		if (copy_to_user(payload, &prof, sizeof(prof)))
			ret = -EFAULT;
		break;
	}
	case ZSU_CMD_AUTH_SET_KEY:
		ret = zerosu_cmd_set_key(ctx, payload);
		if (!ret) {
			mutex_lock(&ctx->event_lock);
			zerosu_note_auth(ctx, true);
			mutex_unlock(&ctx->event_lock);
		}
		break;
	case ZSU_CMD_AUTH_VERIFY:
		ret = zerosu_cmd_verify_key(ctx, payload);
		mutex_lock(&ctx->event_lock);
		zerosu_note_auth(ctx, ret == 0);
		mutex_unlock(&ctx->event_lock);
		break;
	/*
	 * zerosu_cmd.arg is multiplexed by opcode: for ELEVATE it is the
	 * elevation mode, for ELEVATE_TASK it is the pid and the mode follows
	 * from the opcode. Documented in uapi/zerosu.h.
	 *
	 * ELEVATE is strictly self-elevation and ELEVATE_TASK is strictly
	 * target-pid elevation. Keeping the two disjoint means there is no
	 * argument value that makes one command do the other's job.
	 */
	case ZSU_CMD_ELEVATE:
		if (hdr.arg != ZSU_ELEVATE_MODE_SELF) {
			ret = -EINVAL;
			break;
		}
		ret = zerosu_elevate(hdr.arg);
		break;
	case ZSU_CMD_ELEVATE_TASK: {
		struct zerosu_elevate_task et;

		/*
		 * The payload is exactly one start-time token. It is fetched
		 * once, here, and never re-read; the pid stays in arg. A
		 * mismatch against the live task fails closed inside
		 * zerosu_elevate_task().
		 */
		if (copy_from_user(&et, payload, sizeof(et))) {
			ret = -EFAULT;
			break;
		}
		ret = zerosu_elevate_task((pid_t)hdr.arg, ZSU_ELEVATE_MODE_TASK,
					  et.start_time);
		break;
	}
	case ZSU_CMD_NEXT_EVENT: {
		struct zerosu_event ev;

		lockdep_assert_held(&ctx->event_lock);

		/*
		 * Polled API with a non-blocking contract: an empty ring is
		 * -EAGAIN, not a fabricated "no event" reply. A caller that
		 * loops on this gets a clean backoff and never has to guess
		 * whether a zeroed reply means "nothing happened" or
		 * "event type zero".
		 */
		if (!ctx->ring_count) {
			ret = -EAGAIN;
			break;
		}

		ev = ctx->ring[ctx->ring_tail];
		ctx->ring_tail = (ctx->ring_tail + 1) % ZSU_EVENT_RING;
		ctx->ring_count--;

		if (copy_to_user(payload, &ev, sizeof(ev)))
			ret = -EFAULT;
		break;
	}
	default:
		ret = -EINVAL;
		break;
	}

	if (!ret)
		ctx->last_error = 0;
	else
		ctx->last_error = (s32)ret;

out_perm:
	/* Elevation bookkeeping, only on a clean success. */
	if (!ret && (hdr.opcode == ZSU_CMD_ELEVATE ||
		     hdr.opcode == ZSU_CMD_ELEVATE_TASK)) {
		/*
		 * hdr.arg is the elevation mode for ELEVATE and the target pid
		 * for ELEVATE_TASK, so it is only a valid mode for the former.
		 */
		u32 grant_mode = (hdr.opcode == ZSU_CMD_ELEVATE) ?
			hdr.arg : ZSU_ELEVATE_MODE_TASK;

		mutex_lock(&ctx->event_lock);
		zerosu_note_elevated(ctx, grant_mode);
		mutex_unlock(&ctx->event_lock);
	}

	if (ret)
		ctx->last_error = (s32)ret;

	if (hdr.opcode == ZSU_CMD_NEXT_EVENT ||
	    hdr.opcode == ZSU_CMD_GET_STATUS)
		mutex_unlock(&ctx->event_lock);
	if (hdr.opcode == ZSU_CMD_AUTH_SET_KEY ||
	    hdr.opcode == ZSU_CMD_AUTH_VERIFY ||
	    hdr.opcode == ZSU_CMD_GET_PROFILE ||
	    hdr.opcode == ZSU_CMD_ELEVATE ||
	    hdr.opcode == ZSU_CMD_ELEVATE_TASK)
		mutex_unlock(&key_lock);

	return ret;
}

/* ---------------------------------------------------------------------- */

int zerosu_supercall_init(void)
{
	size_t sz;

	sha256_tfm = crypto_alloc_shash("sha256", 0, 0);
	if (IS_ERR(sha256_tfm)) {
		sha256_tfm = NULL;
		return -ENODEV;
	}

	/*
	 * struct shash_desc must be followed by crypto_shash_descsize() bytes
	 * of per-transform context. Allocated once: the alternative,
	 * SHASH_DESC_ON_STACK, is a VLA and GKI builds with -Werror=vla.
	 */
	sz = sizeof(struct shash_desc) + crypto_shash_descsize(sha256_tfm);
	sha256_desc = kzalloc(sz, GFP_KERNEL);
	if (!sha256_desc) {
		crypto_free_shash(sha256_tfm);
		sha256_tfm = NULL;
		return -ENOMEM;
	}
	sha256_desc->tfm = sha256_tfm;

	mutex_init(&key_lock);
	mutex_init(&sha_lock);
	key_enrolled = false;
	memset(key_digest, 0, sizeof(key_digest));

	pr_info(ZSU_LOG_PREFIX "supercall ready, sha256 descsize %zu\n",
		(size_t)crypto_shash_descsize(sha256_tfm));
	return 0;
}

void zerosu_supercall_exit(void)
{
	/*
	 * Clear the key before freeing it: the digest is the only secret
	 * material this file holds.
	 */
	mutex_lock(&key_lock);
	memset(key_digest, 0, sizeof(key_digest));
	key_enrolled = false;
	mutex_unlock(&key_lock);

	kfree(sha256_desc);
	sha256_desc = NULL;

	crypto_free_shash(sha256_tfm);
	sha256_tfm = NULL;
}