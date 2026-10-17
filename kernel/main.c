// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - kernel/main.c
 *
 * Module entry point and nothing else. Its whole job is to order the init
 * and exit sequences correctly and to refuse to load if any stage is not
 * fully up.
 *
 * Init order is a dependency chain, not a preference:
 *
 *   symbols   the kallsyms bootstrap; nothing else can resolve anything
 *   sepolicy  adds the zsu type, so u:r:zsu:s0 becomes a valid context
 *   selinux   resolves that context to a SID (needs the type) and learns
 *             where the cred blob lives
 *   supercall the ioctl surface and the sha256 tfm
 *   gateway   the kprobe, which is the only way in from userspace
 *
 * gateway comes last on purpose: until every earlier stage has succeeded
 * there is nothing worth opening a session for, and a half-armed gateway is
 * strictly worse than no gateway.
 *
 * Exit order is the exact reverse, and the kprobe is torn down first: after
 * zerosu_gateway_exit() returns, no new session can appear, so the subsystems
 * the existing sessions depend on can be torn down behind them.
 */

#include <linux/errno.h>
#include <linux/module.h>

#include "include/zerosu.h"
#include "include/arch.h"

static bool verbose;
module_param(verbose, bool, 0400);
MODULE_PARM_DESC(verbose, "log each init stage");

#define ZSU_STAGE(_name)						\
	do {								\
		if (verbose)						\
			pr_info(ZSU_LOG_PREFIX "init: %s\n", _name);	\
	} while (0)

static int __init zerosu_init(void)
{
	int rc;

	/*
	 * GPL: free_uid() and the crypto shash helpers are EXPORT_SYMBOL_GPL,
	 * and calling an exported symbol at all requires a GPL-compatible
	 * licence to avoid a taint-style warning on a tainted kernel.
	 */
	rc = zerosu_symbols_init();
	if (rc)
		return rc;
	ZSU_STAGE("symbols");

	rc = zsu_sepolicy_init();
	if (rc)
		goto err_symbols;
	ZSU_STAGE("sepolicy");

	rc = zerosu_selinux_init();
	if (rc)
		goto err_sepolicy;
	ZSU_STAGE("selinux");

	rc = zsu_elevate_syms_init();
	if (rc)
		goto err_selinux;
	ZSU_STAGE("elevate syms");

	rc = zsu_seccomp_syms_init();
	if (rc)
		goto err_elevate;
	ZSU_STAGE("seccomp syms");

	rc = zerosu_supercall_init();
	if (rc)
		goto err_seccomp;
	ZSU_STAGE("supercall");

	rc = zerosu_gateway_init();
	if (rc)
		goto err_supercall;
	ZSU_STAGE("gateway");

	pr_info(ZSU_LOG_PREFIX "ready: %s, abi %d, up to %d sessions\n",
		ZSU_ARCH_NAME, ZSU_ABI_VERSION, ZSU_MAX_SESSIONS);
	return 0;

	/*
	 * Each label undoes exactly the stages that succeeded, in reverse.
	 * Note that the SELinux type is deliberately *not* removed on the way
	 * out: see zsu_sepolicy_exit().
	 */
err_supercall:
	zerosu_supercall_exit();
err_seccomp:
	zerosu_seccomp_exit();
err_elevate:
	/* elevate only resolved symbols, so there is nothing of its own */
	zerosu_selinux_exit();
err_selinux:
	zsu_sepolicy_exit();
err_sepolicy:
	zerosu_symbols_exit();
err_symbols:
	pr_err(ZSU_LOG_PREFIX "init failed, nothing installed\n");
	return rc;
}

static void __exit zerosu_exit(void)
{
	/*
	 * zerosu_gateway_exit() drains in-flight task work and waits for it,
	 * which is what makes it safe to tear the rest down underneath.
	 */
	zerosu_gateway_exit();
	zerosu_supercall_exit();
	zerosu_seccomp_exit();
	zerosu_selinux_exit();
	zsu_sepolicy_exit();
	zerosu_symbols_exit();

	pr_info(ZSU_LOG_PREFIX "unloaded\n");
}

module_init(zerosu_init);
module_exit(zerosu_exit);

/*
 * CFI shim, non-CFI build path only.
 *
 * The device kernel is built with Clang CFI. When this module is built by the
 * KernelSU-style workflow (the DDK kdir, clang, the kernel's CFI config is
 * set), the compiler emits the CFI metadata itself: on the old CFI
 * (CONFIG_CFI_CLANG) clang emits "__cfi_check" and the kernel's module_init()/
 * module_exit() macros generate the "__cfi_jt_*" jump-table slots via
 * __CFI_ADDRESSABLE(); on kCFI (CONFIG_CFI, 6.18+) there is no __cfi_check at
 * all. So the shim must not be compiled there, or it would be a duplicate
 * symbol / a missing-prototype warning.
 *
 * When the module is instead built with plain gcc (neither config is set in
 * that kdir), none of that is emitted. cfi_init() on an old-CFI device still
 * looks up a module-supplied "__cfi_check" in the module's own kallsyms and
 * adopts it as the module's check function, and pins mod->init/mod->exit from
 * the "__cfi_jt_init_module"/"__cfi_jt_cleanup_module" jump-table slots. The
 * no-op check accepts every indirect call into the module; the kernel only
 * uses its return value to decide whether to panic.
 */
#if !defined(CONFIG_CFI_CLANG) && !defined(CONFIG_CFI)
void __cfi_check(u64 id, void *ptr, void *diag)
{
	(void)id;
	(void)ptr;
	(void)diag;
}

void *__refdata __cfi_jt_init_module = (void *)zerosu_init;
void *__refdata __cfi_jt_cleanup_module = (void *)zerosu_exit;
#endif /* !CONFIG_CFI_CLANG && !CONFIG_CFI */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ZeroSU");
MODULE_DESCRIPTION("ZeroSU: reboot-gateway based root session module");
MODULE_VERSION(ZSU_VERSION);
MODULE_INFO(abi, __stringify(ZSU_ABI_VERSION));
