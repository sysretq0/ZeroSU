// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - kernel/seccomp.c
 *
 * Detaches a task's seccomp filter, if it has one.
 *
 * The trick is that we do not reimplement the release. seccomp_filter_release()
 * is the only thing that knows how to drop the filter's refcount, run the
 * RCU grace period, and clear the pending-install work, so we hand it a
 * throwaway task_struct that already points at the filter we detached from
 * the real one. The real task is left with mode DISABLED and no filter.
 *
 * Locking: the filter pointer is stolen under tsk->sighand->siglock, because
 * that is the lock seccomp itself uses (see seccomp_assign_mode()). The
 * allocation of the dummy task happens *before* the spinlock is taken: kzalloc
 * can sleep, and sleeping inside spin_lock_irqsave is a bug.
 *
 * struct seccomp is a public header, so there is no mirrored layout here even
 * though it changed shape between 5.10 (mode, filter_count, filter) and 6.18
 * (mode, filter) - the headers handle that.
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/slab.h>

#include "include/zerosu.h"

/*
 * Storage for the resolved-symbol slot that compat.h declares extern. The
 * definition lives next to the table that fills it in.
 */
__typeof__(sym_seccomp_filter_release) sym_seccomp_filter_release;

static struct zsu_symtab_ent seccomp_syms[] = {
	{ "seccomp_filter_release",	(void **)&sym_seccomp_filter_release, true },
};

int zsu_seccomp_syms_init(void)
{
	return zsu_resolve_symtab(seccomp_syms, ARRAY_SIZE(seccomp_syms),
				  "seccomp");
}

/*
 * Nothing to undo: seccomp_filter_release() has already done the RCU work by
 * the time any filter is detached, and the resolved pointer stays valid until
 * the module text goes away.
 */
void zerosu_seccomp_exit(void)
{
}

/*
 * Strip seccomp from @tsk. Returns 0 whether or not there was a filter, so
 * callers do not need to care; a task without seccomp is not an error.
 */
int zerosu_seccomp_strip(struct task_struct *tsk)
{
	struct seccomp_filter *orig;
	struct task_struct *fake;
	unsigned long flags;

	if (!tsk || !tsk->sighand)
		return -EINVAL;

	if (!sym_seccomp_filter_release)
		return -ENOENT;

	/*
	 * Sleeping allocation, deliberately outside the spinlock below. It is
	 * wasted when the task has no filter, which is the common case, but
	 * the alternative - allocating under a spinlock - is not an option.
	 */
	fake = kzalloc(sizeof(*fake), GFP_KERNEL);
	if (!fake)
		return -ENOMEM;

	spin_lock_irqsave(&tsk->sighand->siglock, flags);

	orig = tsk->seccomp.filter;
	zsu_clear_seccomp_work(tsk);
	WRITE_ONCE(tsk->seccomp.mode, SECCOMP_MODE_DISABLED);
	WRITE_ONCE(tsk->seccomp.filter, NULL);

	spin_unlock_irqrestore(&tsk->sighand->siglock, flags);

	if (orig) {
		zsu_prep_fake_seccomp_task(fake, orig);
		sym_seccomp_filter_release(fake);
	}

	kfree(fake);
	return 0;
}