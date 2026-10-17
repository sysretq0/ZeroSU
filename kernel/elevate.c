// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - kernel/elevate.c
 *
 * Builds an elevated cred and installs it.
 *
 * The single most important rule in this file: commit_creds() only ever runs
 * against `current`. It swaps task->cred and task->real_cred of the calling
 * task and fires the LSM commit hooks, so calling it for some other task
 * would corrupt this one instead. For a remote task we reproduce exactly what
 * commit_creds() does to the pointers - rcu_assign_pointer() both cred fields
 * under task_lock() - and drop the old references afterwards, which is the
 * same sequence as kernel/cred.c:commit_creds().
 *
 * Why these symbols are resolved rather than called: on GKI 6.18
 * prepare_creds() lives in a mangled EXPORT_SYMBOL_NS() namespace and
 * CONFIG_TRIM_UNUSED_KSYMS=y is on, so a direct call would need a
 * MODULE_IMPORT_NS() we cannot name portably. Same policy as task_work_add.
 */

#include <linux/atomic.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/sched/user.h>
#include <linux/uidgid.h>

#include "include/zerosu.h"

/* Module parameter: keep PFA_NO_NEW_PRIVS set on the elevated task. */
static bool keep_no_new_privs;
module_param(keep_no_new_privs, bool, 0400);
MODULE_PARM_DESC(keep_no_new_privs,
		 "do not clear PFA_NO_NEW_PRIVS on the elevated task");

/* Target identity: what a su session asks for. */
#define ZSU_TARGET_UID	0u
#define ZSU_TARGET_GID	0u

/*
 * cred entry points that are internal, plus two optional helpers.
 *
 * alloc_uid() lives in kernel/user.c and is *not* exported on either branch,
 * so it has to be resolved. Its sibling free_uid() *is* EXPORT_SYMBOL_GPL and
 * is declared in <linux/sched/user.h>, so it is called directly below - no
 * lookup, and the compiler and kCFI check the call.
 */
/*
 * Storage for the resolved-symbol slots declared extern in compat.h. The
 * definitions sit next to the table that fills them.
 */
__typeof__(sym_prepare_creds) sym_prepare_creds;
__typeof__(sym_commit_creds) sym_commit_creds;
__typeof__(sym_alloc_uid) sym_alloc_uid;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
__typeof__(sym_set_cred_ucounts) sym_set_cred_ucounts;
#endif

static struct zsu_symtab_ent elevate_syms[] = {
	{ "prepare_creds",	(void **)&sym_prepare_creds,	true },
	{ "commit_creds",	(void **)&sym_commit_creds,	true },
	{ "alloc_uid",		(void **)&sym_alloc_uid,		true },
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	{ "set_cred_ucounts",	(void **)&sym_set_cred_ucounts,	true },
#endif
};

int zsu_elevate_syms_init(void)
{
	return zsu_resolve_symtab(elevate_syms, ARRAY_SIZE(elevate_syms),
				  "elevate");
}

/*
 * Supplementary groups.
 *
 * set_groups() takes its own reference on @gi, which is why the matching
 * put_group_info() is mandatory - omit it and every elevation leaks a
 * group_info. in_group_p() binary searches the group list, so it must be
 * sorted; with a single supplementary group there is nothing to reorder.
 */
static int zsu_setup_groups(struct cred *new_cred)
{
	struct group_info *gi;

	gi = groups_alloc(1);
	if (!gi)
		return -ENOMEM;

	gi->gid[0] = make_kgid(new_cred->user_ns, ZSU_TARGET_GID);

	set_groups(new_cred, gi);
	put_group_info(gi);	/* set_groups() took its own reference */

	return 0;
}

/*
 * Give the new cred root capabilities.
 *
 * All four sets are set, including the bounding set: cap_bset is a plain
 * kernel_cap_t embedded by value in struct cred (verified in cred.h on 5.10 and
 * 6.18 - it is not a refcounted pointer), so writing it is a plain
 * assignment. It has to be set, because the source cred is usually a zygote
 * whose bounding set is trimmed: exec of a setuid-root binary would otherwise
 * be masked by the *old* zygote bound and come back with fewer caps than the
 * cred claims.
 *
 * ambient is cleared rather than raised: ambient capabilities are additive on
 * top of permitted, and a stale ambient set inherited from the unelevated cred
 * is not something we want to carry into a uid 0 context.
 */
static void zsu_setup_caps(struct cred *new_cred)
{
	new_cred->cap_effective = CAP_FULL_SET;
	new_cred->cap_permitted = CAP_FULL_SET;
	new_cred->cap_inheritable = CAP_FULL_SET;
	new_cred->cap_bset = CAP_FULL_SET;
	new_cred->cap_ambient = CAP_EMPTY_SET;
}

/*
 * Swap in a private user_struct and set the target uid/gid.
 *
 * Sharing the old user_struct would keep the elevated process accounted
 * against the original uid's counters, and would make free_uid() drop a
 * refcount we never took.
 */
static int zsu_swap_user(struct cred *new_cred)
{
	struct user_struct *old_user, *new_user;
	kuid_t uid = make_kuid(new_cred->user_ns, ZSU_TARGET_UID);

	/*
	 * alloc_uid() takes the uid itself, not a namespace, and stamps it
	 * into the new user_struct. Passing a namespace pointer here would
	 * reinterpret it as a kuid_t.
	 */
	new_user = sym_alloc_uid(uid);
	if (!new_user)
		return -ENOMEM;

	new_cred->uid = uid;
	new_cred->gid = make_kgid(new_cred->user_ns, ZSU_TARGET_GID);

	old_user = new_cred->user;
	new_cred->user = new_user;
	if (old_user)
		free_uid(old_user);	/* EXPORT_SYMBOL_GPL, direct call */

	return 0;
}

/*
 * Build the elevated cred without installing it. Returns one reference, the
 * one prepare_creds() handed us.
 */
static struct cred *zsu_build_cred(void)
{
	struct cred *new_cred;
	int rc;

	new_cred = sym_prepare_creds();
	if (!new_cred)
		return NULL;

	rc = zsu_swap_user(new_cred);
	if (rc)
		goto fail;

	rc = zsu_setup_groups(new_cred);
	if (rc)
		goto fail;

	/* Must follow the uid change and precede making the cred visible. */
	rc = zsu_rebind_ucounts(new_cred);
	if (rc)
		goto fail;

	zsu_setup_caps(new_cred);

	/*
	 * Stamp the zsu domain last: it needs the resolved SID and the cred
	 * blob offset, and it must be in place before anything can observe
	 * the cred as uid 0.
	 */
	rc = zerosu_setup_domain(new_cred, NULL);
	if (rc)
		goto fail;

	return new_cred;

fail:
	put_cred(new_cred);
	return NULL;
}

/*
 * Install @new_cred on @tsk, consuming the reference built above.
 *
 * tsk == current : commit_creds() takes ownership and runs the LSM hooks.
 * tsk != current : never commit_creds(). Swap the two pointers under
 *                  task_lock() exactly as commit_creds() does, and put both
 *                  old references. Both new fields need a reference, so take
 *                  one before dropping the two we are replacing.
 */
static int zsu_install_cred(struct task_struct *tsk, struct cred *new_cred)
{
	const struct cred *old_cred, *old_real_cred;

	if (tsk == current)
		return sym_commit_creds(new_cred);

	get_cred(new_cred);	/* now 2: one for ->cred, one for ->real_cred */

	task_lock(tsk);
	old_cred = tsk->cred;
	old_real_cred = tsk->real_cred;
	rcu_assign_pointer(tsk->real_cred, new_cred);
	rcu_assign_pointer(tsk->cred, new_cred);
	task_unlock(tsk);

	if (old_cred)
		put_cred(old_cred);
	if (old_real_cred)
		put_cred(old_real_cred);

	return 0;
}

/* Clear the "cannot gain privileges" flag so the cred is actually usable. */
static void zsu_clear_nnp(struct task_struct *tsk)
{
	if (keep_no_new_privs)
		return;
	clear_bit(PFA_NO_NEW_PRIVS, &tsk->atomic_flags);
}

static int do_elevate(struct task_struct *tsk, u32 mode)
{
	struct cred *new_cred;
	int rc;

	if (!tsk || !tsk->signal)
		return -EINVAL;
	/*
	 * ELEVATE is strictly self-elevation and ELEVATE_TASK is strictly
	 * target-pid elevation; the ioctl layer already enforces the mapping,
	 * and this is the second gate.
	 */
	if (mode != ZSU_ELEVATE_MODE_SELF && mode != ZSU_ELEVATE_MODE_TASK)
		return -EINVAL;

	new_cred = zsu_build_cred();
	if (!new_cred)
		return -ENOMEM;

	rc = zsu_install_cred(tsk, new_cred);
	if (rc) {
		put_cred(new_cred);
		return rc;
	}

	/*
	 * seccomp is stripped after the cred lands, so there is no window in
	 * which the task is uid 0 with the old filter still attached.
	 */
	rc = zerosu_seccomp_strip(tsk);
	if (rc)
		pr_warn(ZSU_LOG_PREFIX "seccomp not stripped: %d\n", rc);

	zsu_clear_nnp(tsk);

	return 0;
}

int zerosu_elevate(u32 mode)
{
	return do_elevate(current, mode);
}

int zerosu_elevate_task(pid_t pid_nr, u32 mode, u64 start_time)
{
	struct task_struct *tsk;
	struct pid *kpid;
	int rc;

	if (mode != ZSU_ELEVATE_MODE_TASK)
		return -EINVAL;
	if (!pid_nr)
		return -EINVAL;

	/*
	 * start_time == 0 is refused rather than treated as "don't care".
	 *
	 * A zero token is what a caller that has not thought about identity
	 * would send, and it is exactly the value that would turn a reused pid
	 * into a free elevation. Failing closed here means the only way to
	 * reach ELEVATE_TASK is to have read field 22 out of the target's
	 * /proc/<pid>/stat, which the daemon does with the target's own /proc
	 * directory pinned.
	 */
	if (!start_time)
		return -EINVAL;

	/*
	 * find_get_pid() + get_pid_task() rather than find_task_by_vpid():
	 * the latter hands back a borrowed RCU pointer that could belong to an
	 * exiting thread by the time we touch it. This pair pins the pid and
	 * takes a real task reference, so the target cannot vanish underneath
	 * the swap. Both are exported.
	 */
	kpid = find_get_pid(pid_nr);
	if (!kpid)
		return -ESRCH;

	tsk = get_pid_task(kpid, PIDTYPE_PID);
	put_pid(kpid);
	if (!tsk)
		return -ESRCH;

	/*
	 * Identity check. nsec_to_clock_t() is the same transform
	 * fs/proc/array.c uses to render stat field 22, so a userspace token
	 * read from procfs compares equal here for exactly one task lifetime.
	 * A recycled pid fails this and the whole call fails -ESRCH; there is
	 * no retry, no fallback and no lock held across the comparison.
	 */
	if ((u64)nsec_to_clock_t(tsk->start_boottime) != start_time) {
		put_task_struct(tsk);
		return -ESRCH;
	}

	rc = do_elevate(tsk, mode);

	put_task_struct(tsk);
	return rc;
}