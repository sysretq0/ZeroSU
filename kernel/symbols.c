// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - kernel/symbols.c
 *
 * The resolver engine, and nothing else. No subsystem symbol list lives
 * here: each subsystem .c owns a static struct zsu_symtab_ent table and its
 * own zsu_<subsys>_syms_init(), so adding a subsystem never means editing
 * this file.
 *
 * When to use this and when not to:
 *
 *   - Symbols that are EXPORT_SYMBOL/EXPORT_SYMBOL_GPL in GKI 5.10..6.18
 *     are called directly. The compiler emits the call, kCFI typechecks it,
 *     and modpost/Module.symvers checks it at load time. No lookup needed.
 *   - Only symbols that are genuinely not exported go through here. On the
 *     six GKI branches we checked that is the SELinux internals,
 *     alloc_uid/free_uid, set_cred_ucounts, seccomp_filter_release, and
 *     task_work_add on 5.10/6.1 (it did become EXPORT_SYMBOL_GPL by 6.18, so
 *     it stays on the lookup path for uniformity - a lookup works whether or
 *     not the symbol is also exported).
 *
 * Bootstrap rationale: kallsyms_lookup_name stopped being exported in 6.7,
 * so we cannot call it before we have it. We do not scan for it. Instead we
 * register a kprobe *by symbol name* - the kprobe core resolves names
 * through kallsyms internally (that is what CONFIG_KALLSYMS_ALL=y on every
 * GKI defconfig buys us) and hands the address back in kp.addr.
 */

#include <linux/errno.h>
#include <linux/kprobes.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "include/zerosu.h"

#define ZSU_CFI_JT_SUFFIX	".cfi_jt"

/*
 * Set by zerosu_symbols_init() and used by every lookup afterwards. Typed as
 * a function pointer rather than void * because that is what we call it as;
 * the address itself came from kp.addr.
 */
static unsigned long (*zsu_kallsyms_lookup_name)(const char *name);

/*
 * The bootstrap kprobe installs a real breakpoint, so give it a handler that
 * does nothing and lets the call proceed. It only ever exists for the few
 * hundred cycles of init, on a function that is not on any hot path.
 */
static int zsu_kp_nop(struct kprobe *kp, struct pt_regs *regs)
{
	return 0;
}

int zerosu_symbols_init(void)
{
	struct kprobe kp;
	int rc;

	memset(&kp, 0, sizeof(kp));
	kp.pre_handler = zsu_kp_nop;
	kp.symbol_name = "kallsyms_lookup_name";

	rc = register_kprobe(&kp);
	if (rc) {
		/* CFI jump table kernels expose a thunk with this name */
		memset(&kp, 0, sizeof(kp));
		kp.pre_handler = zsu_kp_nop;
		kp.symbol_name = "kallsyms_lookup_name" ZSU_CFI_JT_SUFFIX;
		rc = register_kprobe(&kp);
		if (rc) {
			pr_err(ZSU_LOG_PREFIX "kallsyms_lookup_name not reachable: %d\n",
			       rc);
			return rc;
		}
	}

	zsu_kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);

	/*
	 * The probe is gone before any lookup runs, but a breakpoint may
	 * still be draining on another CPU; the grace period makes that
	 * observable rather than merely unlikely.
	 */
	synchronize_rcu();

	/*
	 * Fail closed: prove the function pointer actually resolves before
	 * any subsystem trusts it. A NULL here is the difference between
	 * "module refused to load" and "silent NULL deref later".
	 */
	if (!zerosu_resolve_raw("linux_banner") || !zerosu_resolve_raw("printk")) {
		pr_err(ZSU_LOG_PREFIX "kallsyms lookup returned NULL for known symbols\n");
		zsu_kallsyms_lookup_name = NULL;
		return -ENOENT;
	}

	pr_info(ZSU_LOG_PREFIX "symbol resolver ready (%p)\n",
		(void *)zsu_kallsyms_lookup_name);
	return 0;
}

void zerosu_symbols_exit(void)
{
	zsu_kallsyms_lookup_name = NULL;
}

/*
 * Look a name up, transparently retrying the CFI jump table alias. Returns
 * NULL for "not found"; never a partially valid answer.
 */
void *zerosu_resolve_raw(const char *name)
{
	char alias[128];
	void *addr;

	if (!zsu_kallsyms_lookup_name || !name)
		return NULL;

	addr = (void *)zsu_kallsyms_lookup_name(name);
	if (addr)
		return addr;

	if (snprintf(alias, sizeof(alias), "%s%s", name, ZSU_CFI_JT_SUFFIX) <
	    (int)sizeof(alias))
		addr = (void *)zsu_kallsyms_lookup_name(alias);

	return addr;
}

int zerosu_resolve(const char *name, void **out)
{
	void *addr = zerosu_resolve_raw(name);

	if (!addr)
		return -ENOENT;
	if (out)
		*out = addr;

	return 0;
}

/*
 * Fill a subsystem symbol table.
 *
 * Required entries that do not resolve are counted and reported, and the
 * call fails: the caller turns that into a module load failure. Optional
 * entries are left NULL and the caller must check before use.
 */
int zsu_resolve_symtab(struct zsu_symtab_ent *tbl, unsigned int n,
		       const char *owner)
{
	unsigned int i;
	unsigned int missing = 0;

	if (!tbl || !owner)
		return -EINVAL;

	for (i = 0; i < n; i++) {
		void *addr = zerosu_resolve_raw(tbl[i].name);

		if (!addr) {
			if (tbl[i].required) {
				pr_err(ZSU_LOG_PREFIX "%s: required symbol '%s' unresolved\n",
				       owner, tbl[i].name);
				missing++;
			} else {
				pr_warn(ZSU_LOG_PREFIX "%s: optional symbol '%s' absent\n",
					owner, tbl[i].name);
			}
			continue;
		}

		if (tbl[i].slot)
			*tbl[i].slot = addr;
	}

	return missing ? -ENOENT : 0;
}