// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - kernel/selinux.c
 *
 * Everything between "the zsu type exists" (sepolicy.c) and "a cred carries
 * the zsu domain" (elevate.c).
 *
 * Two jobs, and deliberately nothing else:
 *
 *   1. Learn where SELinux's cred blob lives inside cred->security. That
 *      offset is published by the kernel as selinux_blob_sizes.lbs_cred, and
 *      it is not a constant: another LSM stacked ahead of SELinux moves it,
 *      and it is negative when no LSM claimed a cred blob at all.
 *   2. Resolve u:r:zsu:s0 to a SID once, and stamp that SID into a cred that
 *      is about to be committed.
 *
 * Scope discipline: this file never mutates a live cred. It only writes into
 * the private cred copy that elevate.c built and has not committed yet, so a
 * failure halfway through leaves the caller's old cred untouched.
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "include/zerosu.h"

#define ZSU_DEFAULT_DOMAIN	"u:r:zsu:s0"

/*
 * Both are written once during init and never again, so they live in
 * .ro_after_init from that point on: a stray write from anywhere else is a
 * kernel bug rather than something we have to defend against at runtime.
 */
static unsigned int zsu_lsm_cred_offset __ro_after_init;
static bool zsu_lsm_cred_usable __ro_after_init;
static u32 zsu_cached_sid __ro_after_init;

/*
 * This subsystem's symbols. security_context_str_to_sid moved here from
 * sepolicy.c: it is a cred/SID concern, not a policydb mutation concern.
 */
static struct zsu_symtab_ent selinux_syms[] = {
	{ "selinux_blob_sizes",		(void **)&zsu_selinux_blob_sizes,	true },
	{ "security_context_str_to_sid",	(void **)&zsu_security_context_str_to_sid, true },
};

int zsu_selinux_syms_init(void)
{
	return zsu_resolve_symtab(selinux_syms, ARRAY_SIZE(selinux_syms),
				  "selinux");
}

/*
 * Read lbs_cred out of selinux_blob_sizes.
 *
 * The value is an int and may be negative: lsm_hooks leaves it at -ENOENT
 * when no LSM requested a cred blob. A negative value therefore means
 * "there is no SELinux cred blob", not "offset -ENOENT". We normalise that
 * to offset 0 as specified, but we also refuse to treat the blob as usable,
 * because writing at +0 in that state would land in whatever LSM *did* get
 * the blob. Failing closed here is the difference between "no domain" and
 * "corrupted another LSM's state".
 */
static bool zsu_lsm_cred_probe(void)
{
	int off;

	if (!zsu_selinux_blob_sizes) {
		pr_warn(ZSU_LOG_PREFIX "selinux_blob_sizes unresolved, cred blob assumed at +0 and unusable\n");
		zsu_lsm_cred_offset = 0;
		zsu_lsm_cred_usable = false;
		return false;
	}

	off = zsu_selinux_blob_sizes[ZSU_LBS_CRED_OFFSET / sizeof(int)];

	if (off >= ZSU_LBS_CRED_MIN && off <= ZSU_LBS_CRED_MAX) {
		zsu_lsm_cred_offset = (unsigned int)off;
		zsu_lsm_cred_usable = true;
		pr_info(ZSU_LOG_PREFIX "selinux cred blob at cred->security+%d\n",
			off);
		return true;
	}

	pr_warn(ZSU_LOG_PREFIX "lbs_cred=%d out of range [%d,%d]; treating as unstacked\n",
		off, ZSU_LBS_CRED_MIN, ZSU_LBS_CRED_MAX);
	zsu_lsm_cred_offset = 0;
	zsu_lsm_cred_usable = false;
	return false;
}

int zerosu_selinux_init(void)
{
	u32 sid = 0;
	int rc;

	rc = zsu_selinux_syms_init();
	if (rc)
		return rc;

	rc = zsu_lsm_cred_probe();
	if (rc)
		return rc;

	/*
	 * The type has to exist before the context can be resolved, which is
	 * why main.c orders zsu_sepolicy_init() ahead of this call.
	 */
	rc = zsu_context_str_to_sid(ZSU_DEFAULT_DOMAIN, &sid);
	if (rc) {
		pr_err(ZSU_LOG_PREFIX "cannot resolve %s: %d\n",
		       ZSU_DEFAULT_DOMAIN, rc);
		return rc;
	}
	if (!sid) {
		/* SID 0 means the sidtab entry was never filled in. */
		pr_err(ZSU_LOG_PREFIX "%s resolved to SID 0\n",
		       ZSU_DEFAULT_DOMAIN);
		return -EINVAL;
	}

	zsu_cached_sid = sid;
	pr_info(ZSU_LOG_PREFIX "domain %s -> sid %u\n", ZSU_DEFAULT_DOMAIN, sid);
	return 0;
}

void zerosu_selinux_exit(void)
{
	/* Deliberately empty: the cred blob is stamped per commit_creds(),
	 * and the cached SID belongs to a sidtab entry we must not retract. */
}

u32 zsu_sid(void)
{
	return READ_ONCE(zsu_cached_sid);
}

/*
 * Stamp the zsu domain into a cred that is *not yet* live.
 *
 * @new_cred: a private cred copy (prepare_creds() output), never a shared one
 * @domain:   context to stamp, or NULL for the module default domain
 *
 * osid and sid both get the SID: osid is "SID prior to last execve" and
 * leaving it at 0 while sid is set is what makes a freshly committed cred
 * look like it is mid-execve. The four creation SIDs are zeroed because they
 * are cached transition decisions that belonged to the previous domain.
 */
int zerosu_setup_domain(struct cred *new_cred, const char *domain)
{
	struct zsu_cred_sec *sec;
	u32 sid;
	int rc;

	if (!new_cred || !new_cred->security)
		return -EINVAL;
	if (!zsu_lsm_cred_usable)
		return -EOPNOTSUPP;

	if (domain) {
		rc = zsu_context_str_to_sid(domain, &sid);
		if (rc) {
			pr_err(ZSU_LOG_PREFIX "cannot resolve %s: %d\n",
			       domain, rc);
			return rc;
		}
	} else {
		sid = READ_ONCE(zsu_cached_sid);
	}

	if (!sid)
		return -EINVAL;

	sec = (struct zsu_cred_sec *)((char *)new_cred->security +
				      zsu_lsm_cred_offset);

	sec->sid = sid;
	sec->osid = sid;
	sec->exec_sid = 0;
	sec->create_sid = 0;
	sec->keycreate_sid = 0;
	sec->sockcreate_sid = 0;

	return 0;
}