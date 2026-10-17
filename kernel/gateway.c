// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - kernel/gateway.c
 *
 * The only entry point into the module. A userspace process calls
 *
 *     reboot(ZSU_GATEWAY_REBOOT_CMD, ZSU_GATEWAY_MAGIC1, ZSU_GATEWAY_MAGIC2, &fd)
 *
 * and a kprobe on the reboot syscall wrapper hands it a session fd.
 *
 * Scope discipline: reboot_pre() runs in atomic context (kprobe, before the
 * syscall does anything) so it validates, allocates with GFP_ATOMIC, and
 * queues a task_work. Everything else - anon_inode_getfile(), copy_to_user(),
 * fd_install() - happens in install_work() on the way back to userspace.
 * reboot_pre() always returns 0; it never blocks and it never allocates with
 * a sleeping allocator.
 *
 * Teardown hazard this file exists to get right: unregister_kprobe() plus
 * synchronize_rcu() only proves no CPU is inside reboot_pre(). A task_work
 * that was already queued may still be pending or mid-flight, and zerosu.ko
 * is about to unmap its own .text. The inflight_tw counter is what makes that
 * observable - the counter is incremented *before* task_work_add() and
 * decremented as the very last thing install_work() does.
 *
 * Calling convention, verified against SYSCALL_DEFINE4(reboot, ...) in
 * kernel/reboot.c on 5.10 and 6.18:
 *
 *   SYSCALL_DEFINE4(reboot, int, magic1, int, magic2,
 *                   unsigned int, cmd, void __user *, arg)
 *
 * so in *syscall* argument order - which is NOT the order of the libc
 * reboot(int cmd, int magic1, int magic2, ...) wrapper that reorders them:
 *
 *   PARAM1 = magic1  = ZSU_GATEWAY_MAGIC1
 *   PARAM2 = magic2  = ZSU_GATEWAY_MAGIC2
 *   PARAM3 = cmd     = session type (ZSU_SESSION_PLAIN | ZSU_SESSION_SU)
 *   PARAM4 = arg     = int __user * where the session fd is returned
 *
 * Nothing else is needed to make this safe. reboot() checks
 *   if (magic1 != LINUX_REBOOT_MAGIC1 || (magic2 != ...)) return -EINVAL;
 * before its switch(cmd), and ZSU_GATEWAY_MAGIC1 (0x5A455255) is not
 * LINUX_REBOOT_MAGIC1 (0xfee1dead), so the real handler returns -EINVAL
 * without ever reaching pm_suspend() or any other state change. An
 * unprivileged caller is rejected earlier still with -EPERM.
 */

#include <linux/anon_inodes.h>
#include <linux/atomic.h>
#include <linux/errno.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/kprobes.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "include/zerosu.h"
#include "include/arch.h"

/*
 * The task_work payload. cb *must* be the first member: install_work()
 * recovers the wrapper with container_of().
 */
struct zsu_tw {
	struct callback_head cb;
	void __user *out_fd;
	u32 mode;			/* ZSU_SESSION_PLAIN | ZSU_SESSION_SU */
};

/* Sessions with a live fd in some process's table. */
static atomic_t live_sessions;
/* Task works queued or running. Never zero while the module is text-mapped. */
static atomic_t inflight_tw;
static wait_queue_head_t zsu_tw_wait;

static struct kprobe reboot_kp;

/* task_work_add() is internal on 5.10/6.1 and EXPORT_SYMBOL_GPL by 6.18;
 * a lookup behaves the same either way, so it stays on the resolve path. */
static int (*sym_task_work_add)(struct task_struct *task,
				struct callback_head *work,
				enum task_work_notify_mode notify);

static struct zsu_symtab_ent gateway_syms[] = {
	{ "task_work_add", (void **)&sym_task_work_add, true },
};

int zsu_gateway_syms_init(void)
{
	return zsu_resolve_symtab(gateway_syms, ARRAY_SIZE(gateway_syms),
				  "gateway");
}

/*
 * Runs on the way back to userspace (TWA_RESUME), in the caller's own
 * address space, so tw->out_fd is directly usable.
 *
 * Ordering that matters:
 *   - copy_to_user() happens BEFORE fd_install(), so a bad userspace pointer
 *     leaves no orphaned fd behind. The failure path does put_unused_fd() +
 *     fput(), and that fput() runs zerosu_session_release(), which frees the
 *     session and drops live_sessions for us.
 *   - the inflight_tw decrement is the final statement, after kfree(tw), so
 *     the module can never be told "drained" while its own text is still
 *     running.
 */
static void zerosu_install_work(struct callback_head *work)
{
	struct zsu_tw *tw = container_of(work, struct zsu_tw, cb);
	struct zsu_session *ctx;
	struct file *file;
	long fd;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		goto out;

	/* Reserve the slot before the fd exists, so the count never dips. */
	if (atomic_fetch_add_unless(&live_sessions, 1, ZSU_MAX_SESSIONS) >=
	    ZSU_MAX_SESSIONS) {
		atomic_dec(&live_sessions);
		kfree(ctx);
		goto out;
	}

	mutex_init(&ctx->lock);
	mutex_init(&ctx->event_lock);
	ctx->type = tw->mode;
	ctx->last_error = 0;
	ctx->event_seq = 0;

	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		atomic_dec(&live_sessions);
		kfree(ctx);
		goto out;
	}

	file = anon_inode_getfile("[zerosu]", &zerosu_session_fops, ctx,
				  O_RDWR | O_CLOEXEC);
	if (IS_ERR(file)) {
		put_unused_fd(fd);
		atomic_dec(&live_sessions);
		kfree(ctx);
		goto out;
	}

	if (copy_to_user(tw->out_fd, &fd, sizeof(fd))) {
		/*
		 * fput() drops the only reference to file, which runs
		 * zerosu_session_release() -> kfree(ctx) and
		 * atomic_dec(&live_sessions). Do not free ctx here.
		 */
		put_unused_fd(fd);
		fput(file);
		goto out;
	}

	fd_install(fd, file);

out:
	kfree(tw);
	if (atomic_dec_and_test(&inflight_tw))
		wake_up(&zsu_tw_wait);
}

/*
 * Kprobe on the reboot syscall wrapper.
 *
 * MUST return 0. That is safe precisely because the magic arguments do not
 * match the kernel's: reboot() bails out with -EINVAL (or -EPERM when the
 * caller is unprivileged) before its switch(cmd), so no part of the real
 * reboot path runs. There is deliberately no argument stomping here - with
 * the correct parameter order there is nothing left to neutralise.
 *
 * This runs *before* sys_reboot's ns_capable(CAP_SYS_BOOT) check, and that is
 * intentional rather than incidental. The kernel capability check governs
 * rebooting the machine; it has nothing to do with handing out a session fd,
 * and a session fd grants nothing on its own. Keeping the kprobe ahead of it
 * is what lets an unprivileged process (the su CLI, the manager) open an
 * anonymous [zerosu] fd and then authenticate against the device master key
 * over ioctl. Authorization lives in supercall.c's zerosu_session_perm(); if
 * this handler required CAP_SYS_BOOT, the SuperKey flow would be pointless.
 */
static int zerosu_reboot_pre(struct kprobe *kp, struct pt_regs *kp_regs)
{
	struct zsu_tw *tw;
	struct pt_regs *real;
	unsigned long mode;
	void __user *out_fd;
	int rc;

	/* Kernel thread or a process with no address space: not our caller. */
	if (unlikely(current->flags & PF_KTHREAD) || !current->mm)
		return 0;

	real = ZSU_SYS_PT_REGS(kp_regs);

	/* PARAM1/PARAM2 are magic1/magic2 in *syscall* order, see the header. */
	if (ZSU_SYS_PARAM1(real) != ZSU_GATEWAY_MAGIC1 ||
	    ZSU_SYS_PARAM2(real) != ZSU_GATEWAY_MAGIC2)
		return 0;

	/* PARAM3 carries the requested session flavour, not a reboot flag. */
	mode = ZSU_SYS_PARAM3(real);
	if (mode != ZSU_SESSION_PLAIN && mode != ZSU_SESSION_SU)
		return 0;

	out_fd = (void __user *)ZSU_SYS_PARAM4(real);
	if (!out_fd)
		return 0;

	/* Cheap gate before we spend an allocation. */
	if (atomic_read(&live_sessions) >= ZSU_MAX_SESSIONS)
		return 0;

	tw = kmalloc(sizeof(*tw), GFP_ATOMIC);
	if (!tw)
		return 0;

	tw->out_fd = out_fd;
	tw->mode = (u32)mode;
	tw->cb.func = zerosu_install_work;

	/*
	 * Increment before queueing: task_work_add() may complete on another
	 * CPU before it even returns, so the counter has to be live first.
	 */
	atomic_inc(&inflight_tw);

	rc = sym_task_work_add(current, &tw->cb, TWA_RESUME);
	if (rc) {
		/* -ESRCH means the task is already dying: unwind fully. */
		if (atomic_dec_and_test(&inflight_tw))
			wake_up(&zsu_tw_wait);
		kfree(tw);
		return 0;
	}

	return 0;
}

const struct file_operations zerosu_session_fops = {
	.owner			= THIS_MODULE,
	.unlocked_ioctl		= zerosu_supercall_ioctl,
	.compat_ioctl		= ZSU_COMPAT_IOCTL_HANDLER,
	.release		= zerosu_session_release,
	.llseek			= no_llseek,
};

int zerosu_session_release(struct inode *inode, struct file *file)
{
	struct zsu_session *ctx = file->private_data;

	if (ctx) {
		mutex_destroy(&ctx->lock);
		kfree(ctx);
		file->private_data = NULL;
	}

	atomic_dec(&live_sessions);
	return 0;
}

int zerosu_gateway_init(void)
{
	int rc;

	init_waitqueue_head(&zsu_tw_wait);

	rc = zsu_gateway_syms_init();
	if (rc)
		return rc;

	memset(&reboot_kp, 0, sizeof(reboot_kp));
	reboot_kp.pre_handler = zerosu_reboot_pre;
	reboot_kp.symbol_name = ZSU_REBOOT_SYMBOL;

	rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err(ZSU_LOG_PREFIX "cannot kprobe %s: %d\n",
		       ZSU_REBOOT_SYMBOL, rc);
		return rc;
	}

	pr_info(ZSU_LOG_PREFIX "gateway armed on %s (%s), %d sessions max\n",
		ZSU_ARCH_NAME, ZSU_REBOOT_SYMBOL, ZSU_MAX_SESSIONS);
	return 0;
}

void zerosu_gateway_exit(void)
{
	/*
	 * Order matters and none of these steps is redundant:
	 *   unregister_kprobe()  - no new callers can appear
	 *   synchronize_rcu()    - no CPU is still inside reboot_pre()
	 *   wait_event()         - queued task works have finished running
	 * The last one is what stops zerosu.ko from unmapping .text while
	 * zerosu_install_work() is still executing inside it.
	 */
	unregister_kprobe(&reboot_kp);
	synchronize_rcu();
	wait_event(zsu_tw_wait, !atomic_read(&inflight_tw));
}