/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ZeroSU - kernel/include/compat.h
 *
 * Single place where every LINUX_VERSION_CODE / KMI difference between
 * Android GKI 5.10 .. 6.18 is isolated. No .c file in this module is
 * allowed to contain a version #ifdef.
 *
 * Every layout in the "mirrored ABI" section below was verified byte for
 * byte against these trees (selective file fetch, no clone):
 *
 *   sysretq0/android-kernel-common
 *     android12-5.10-lts   android13-5.15-lts   android14-6.1-lts
 *     android15-6.6-lts    android16-6.12-lts   android17-6.18-lts
 *
 * Sources of truth:
 *   security/selinux/ss/{hashtab,ebitmap,symtab,avtab,mls_types,context,
 *                        policydb}.h, security/selinux/ss/{policydb,services,
 *                        symtab,hashtab}.c,
 *   security/selinux/include/{security,policycap}.h
 */

#ifndef _ZSU_COMPAT_H
#define _ZSU_COMPAT_H

#include <linux/build_bug.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/thread_info.h>
#include <linux/uidgid.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/version.h>

/*
 * Without CONFIG_LOCKDEP the tree defines lockdep_is_held_type() but not
 * lockdep_is_held(). The check below is a sanity assertion on a mutex we hold,
 * so on a non-lockdep kernel it is vacuously true.
 */
#ifndef lockdep_is_held
#define lockdep_is_held(lock)	({ (void)(lock); 1; })
#endif

/*
 * The mirrored structs below are only valid because every Android GKI
 * gki_defconfig from 5.10 through 6.18 leaves CONFIG_RANDSTRUCT* off. All of
 * struct selinux_state, struct selinux_policy and struct policydb carry
 * __randomize_layout in all six branches, so one stray vendor config would
 * silently corrupt every offset we compute. Fail closed at build time.
 *
 * Note: CONFIG_RANDOMIZE_BASE / KASLR is deliberately NOT in this list. It
 * randomizes the kernel image base, not struct member order, and it is set
 * on every GKI kernel - guarding on it would reject every possible target.
 */
#if defined(CONFIG_RANDSTRUCT) || defined(CONFIG_RANDSTRUCT_FULL) || \
	defined(CONFIG_GCC_PLUGIN_RANDSTRUCT) || \
	defined(CONFIG_RANDSTRUCT_PLUGIN)
#error "ZeroSU: CONFIG_RANDSTRUCT* invalidates the mirrored SELinux ABI."
#endif

/* ========================================================================
 * Version anchors
 *
 * Anchor points that were verified, not guessed:
 *  - >= 6.6  security_context_str_to_sid() dropped its leading
 *            'struct selinux_state *state' argument.
 *  - >= 6.6  struct selinux_state lost 'checkreqprot' and 'avc'.
 *  - >= 6.18 struct selinux_state lost the android_netlink_* bools.
 *  - >= 6.12 __POLICYDB_CAP_MAX grew 8 -> 9, >= 6.18 grew to 14.
 *
 * Plain upstream 6.2..6.5 is not a GKI target; the 6.1/6.6 boundary is used
 * because those are the branches that actually ship.
 * ======================================================================== */

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
#define ZSU_SELINUX_STATE_HAS_CHECKREQPROT 1
#define ZSU_SELINUX_STATE_HAS_AVC           1
#define ZSU_SELINUX_STATE_HAS_ANDROID_BOOLS 1
#define ZSU_POLICYCAP_MAX                   8
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#define ZSU_SELINUX_STATE_HAS_ANDROID_BOOLS 1
#define ZSU_POLICYCAP_MAX                   8
#elif LINUX_VERSION_CODE < KERNEL_VERSION(6, 18, 0)
#define ZSU_SELINUX_STATE_HAS_ANDROID_BOOLS 1
#define ZSU_POLICYCAP_MAX                   9
#else
#define ZSU_POLICYCAP_MAX                  14
#endif

/* selinuxfs-era inlines dropped in 6.6 (see table in sepolicy.c). */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
#define ZSU_SECCTX_TO_SID_TAKES_STATE 1
#else
#define ZSU_SECCTX_TO_SID_TAKES_STATE 0
#endif

/*
 * compat_ptr_ioctl only exists on architectures with a 32 bit compat
 * personality (arm64, x86_64, riscv under CONFIG_COMPAT). On a native
 * 64-bit-only build the field has to be NULL, so the choice lives here
 * instead of in gateway.c.
 */
#ifdef CONFIG_COMPAT
#define ZSU_COMPAT_IOCTL_HANDLER	compat_ptr_ioctl
#else
#define ZSU_COMPAT_IOCTL_HANDLER	NULL
#endif

/*
 * no_llseek() was removed in 6.12. noop_llseek() exists on every branch and is
 * what the VFS wants for a file whose offset is never meaningful, so the
 * choice lives here instead of in gateway.c.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#define ZSU_NO_LLSEEK	no_llseek
#else
#define ZSU_NO_LLSEEK	noop_llseek
#endif

/* ========================================================================
 * Mirrored SELinux ABI
 *
 * Rules that were verified and that the code below depends on:
 *
 *  1. policydb->type_attr_map_array is indexed [type_value - 1], and the
 *     self bit stored *inside* that slot is also (type_value - 1):
 *         for (i = 0; i < nprim; i++) { e = &array[i]; ebitmap_read(e);
 *                                        ebitmap_set_bit(e, i, 1); }
 *     -> type_attr_map_array[v - 1] bit (v - 1)
 *
 *  2. role_datum->types is indexed (type_value - 1):
 *         policydb.c: if (!role || !ebitmap_get_bit(&role->types, c->type - 1))
 *     -> role->types bit (v - 1)
 *
 *  3. policydb->permissive_map is indexed by type_value, NOT value - 1:
 *         services.c: if (ebitmap_get_bit(&policydb->permissive_map,
 *                                         scontext->type))
 *     -> permissive_map bit v        <-- do not "normalize" this to v - 1
 *
 *  4. Both indexed arrays come from kvcalloc() and are released with
 *     kvfree(), so any resize must use the kvmalloc family and kvfree().
 *     krealloc() is wrong twice: it rejects vmalloc'ed memory (returns NULL)
 *     and policydb_destroy() would release the block through kvfree().
 *
 *  5. symtab_insert() does not touch nprim; the loader increments it. We
 *     must do the same, and it is the commit point of the whole operation.
 *
 *  6. sym_val_to_name[SYM_TYPES] must be grown as well: sym_name() has no
 *     bounds check at all (  return p->sym_val_to_name[sym_num][nr];  ) and
 *     context_struct_to_string() strlen()s the result on every
 *     /proc/self/attr/current read and every permissive-mode AVC audit.
 *
 *  7. Concurrent readers (security_compute_av() and friends) walk these
 *     arrays under rcu_read_lock() with no policy_mutex, so the old arrays
 *     must not be freed until after synchronize_rcu().
 *
 * Fields after permissive_map are deliberately not mirrored: they cannot
 * shift any offset we use.
 * ======================================================================== */

#define ZSU_SYM_TYPES 3
#define ZSU_SYM_ROLES 2
#define ZSU_SYM_NUM   8

/* --- security/selinux/ss/ebitmap.h --- */
struct zsu_ebitmap_node;
struct zsu_ebitmap {
	struct zsu_ebitmap_node *node;
	u32 highbit;
};

/* --- security/selinux/ss/hashtab.h --- */
struct zsu_hashtab_node {
	void *key;
	void *datum;
	struct zsu_hashtab_node *next;
};
struct zsu_hashtab {
	struct zsu_hashtab_node **htable;
	u32 size;
	u32 nel;
};

/* --- security/selinux/ss/symtab.h --- */
struct zsu_symtab {
	struct zsu_hashtab table;
	u32 nprim;
};

/* --- security/selinux/ss/policydb.h --- */
struct zsu_type_datum {
	u32 value;
	u32 bounds;
	unsigned char primary;
	unsigned char attribute;
};

struct zsu_role_datum {
	u32 value;
	u32 bounds;
	struct zsu_ebitmap dominates;
	struct zsu_ebitmap types;
};

struct zsu_mls_level {
	u32 sens;
	struct zsu_ebitmap cat;
};
struct zsu_mls_range {
	struct zsu_mls_level level[2];
};
struct zsu_user_datum {
	u32 value;
	u32 bounds;
	struct zsu_ebitmap roles;
	struct zsu_mls_range range;
	struct zsu_mls_level dfltlevel;
};
struct zsu_common_datum {
	u32 value;
	struct zsu_symtab permissions;
};
struct zsu_constraint_node;
struct zsu_class_datum {
	u32 value;
	char *comkey;
	struct zsu_common_datum *comdatum;
	struct zsu_symtab permissions;
	struct zsu_constraint_node *constraints;
	struct zsu_constraint_node *validatetrans;
	char default_user;
	char default_role;
	char default_type;
	char default_range;
};

struct zsu_avtab_node;
struct zsu_avtab {
	struct zsu_avtab_node **htable;
	u32 nel;
	u32 nslot;
	u32 mask;
};

struct zsu_cond_bool_datum {
	u32 value;
	int state;
};

struct zsu_policydb {
	int mls_enabled;

	/* symbol tables */
	struct zsu_symtab symtab[ZSU_SYM_NUM];
#define p_commons	symtab[0]
#define p_classes	symtab[1]
#define p_roles		symtab[2]
#define p_types		symtab[ZSU_SYM_TYPES]
#define p_users		symtab[4]

	/* symbol names indexed by (value - 1) */
	char **sym_val_to_name[ZSU_SYM_NUM];

	/* class, role, and user attributes indexed by (value - 1) */
	struct zsu_class_datum **class_val_to_struct;
	struct zsu_role_datum **role_val_to_struct;
	struct zsu_user_datum **user_val_to_struct;
	struct zsu_type_datum **type_val_to_struct;

	/* type enforcement access vectors and transitions */
	struct zsu_avtab te_avtab;

	/* role transitions */
	struct zsu_hashtab role_tr;

	struct zsu_ebitmap filename_trans_ttypes;
	struct zsu_hashtab filename_trans;
	u32 compat_filename_trans_count;

	struct zsu_cond_bool_datum **bool_val_to_struct;
	struct zsu_avtab te_cond_avtab;
	void *cond_list;
	u32 cond_list_len;

	void *role_allow;

	void *ocontexts[9];

	void *genfs;
	struct zsu_hashtab range_tr;

	/* type -> attribute reverse mapping, indexed by (value - 1) */
	struct zsu_ebitmap *type_attr_map_array;

	struct zsu_ebitmap policycaps;
	struct zsu_ebitmap permissive_map;
	/* 6.18 adds neveraudit_map here; unreachable from any offset above. */
};

/* --- security/selinux/include/objsec.h: the cred blob ---
 *
 * Upstream calls this struct task_security_struct up to 6.x and
 * cred_security_struct from 6.18 (where task_security_struct was reused for
 * the AVC dir cache). The *field order below is identical in both*, which is
 * all we need, because we mirror it instead of including the header.
 *
 * Note it carries __randomize_layout, so it is covered by the same
 * CONFIG_RANDSTRUCT guard as everything else above. Field order, not
 * declaration, is what matters here:
 *   osid, sid, exec_sid, create_sid, keycreate_sid, sockcreate_sid
 */
struct zsu_cred_sec {
	u32 osid;
	u32 sid;
	u32 exec_sid;
	u32 create_sid;
	u32 keycreate_sid;
	u32 sockcreate_sid;
};

/*
 * selinux_blob_sizes is a struct lsm_blob_sizes, and lbs_cred is the first
 * member in 5.10, 6.1 and 6.18 alike, so the offset is 0. It is read at
 * runtime anyway (another LSM stacked ahead of SELinux would move it), and
 * the value is an int that can legitimately be negative (-ENOENT) when no
 * LSM asked for a cred blob at all.
 */
#define ZSU_LBS_CRED_OFFSET	0
#define ZSU_LBS_CRED_MIN	0
#define ZSU_LBS_CRED_MAX	256

/* --- security/selinux/ss/services.h: struct selinux_policy --- */
struct zsu_selinux_policy {
	void *sidtab;			/* struct sidtab * */
	struct zsu_policydb policydb;
	void *map;			/* struct selinux_map * */
	u32 latest_granting;
};

/*
 * struct selinux_state prefix. policy is the second to last member and
 * policy_mutex the last one in every branch, but their *offset* depends on
 * the policycap[] length and on which Android bools still exist, hence the
 * four variants above.
 */
struct zsu_selinux_state {
#if defined(CONFIG_SECURITY_SELINUX_DISABLE)
	bool disabled;
#endif
#if defined(CONFIG_SECURITY_SELINUX_DEVELOP)
	bool enforcing;
#endif
#if defined(ZSU_SELINUX_STATE_HAS_CHECKREQPROT)
	bool checkreqprot;
#endif
	bool initialized;
	bool policycap[ZSU_POLICYCAP_MAX];
#if defined(ZSU_SELINUX_STATE_HAS_ANDROID_BOOLS)
	bool android_netlink_route;
	bool android_netlink_getneigh;
#endif
	struct page *status_page;
	struct mutex status_lock;
#if defined(ZSU_SELINUX_STATE_HAS_AVC)
	void *avc;
#endif
	struct zsu_selinux_policy *__rcu policy;
	struct mutex policy_mutex;
};

/* Compile-time tripwire: if a mirror field is edited or the kernel struct
 * gains a member, these fire instead of an OOB access at runtime. Sizes
 * below are the observed kernel values on all six GKI branches. */
static_assert(sizeof(struct zsu_ebitmap) == 16, "zsu: ebitmap layout drift");
static_assert(sizeof(struct zsu_hashtab) == 16, "zsu: hashtab layout drift");
static_assert(sizeof(struct zsu_symtab) == 24, "zsu: symtab layout drift");
static_assert(sizeof(struct zsu_type_datum) == 12, "zsu: type_datum drift");
static_assert(sizeof(struct zsu_avtab) == 24, "zsu: avtab layout drift");
static_assert(sizeof(struct zsu_mls_level) == 24, "zsu: mls_level drift");
static_assert(sizeof(struct zsu_mls_range) == 48, "zsu: mls_range drift");
static_assert(sizeof(struct zsu_role_datum) == 40, "zsu: role_datum drift");
static_assert(sizeof(struct zsu_user_datum) == 96, "zsu: user_datum drift");
static_assert(sizeof(struct zsu_common_datum) == 32, "zsu: common_datum drift");
static_assert(sizeof(struct zsu_class_datum) == 72, "zsu: class_datum drift");
static_assert(sizeof(struct zsu_cred_sec) == 24, "zsu: cred_sec drift");
static_assert(offsetof(struct zsu_cred_sec, osid) == 0, "zsu: osid @0");
static_assert(offsetof(struct zsu_cred_sec, sid) == 4, "zsu: sid @4");
static_assert(offsetof(struct zsu_cred_sec, exec_sid) == 8, "zsu: exec_sid @8");
static_assert(offsetof(struct zsu_cred_sec, create_sid) == 12, "zsu: create_sid @12");
static_assert(offsetof(struct zsu_cred_sec, keycreate_sid) == 16,
	      "zsu: keycreate_sid @16");
static_assert(offsetof(struct zsu_cred_sec, sockcreate_sid) == 20,
	      "zsu: sockcreate_sid @20");
static_assert(offsetof(struct zsu_selinux_policy, policydb) == 8,
	      "zsu: selinux_policy layout drift");

/* ========================================================================
 * Resolved kernel entry points
 *
 * None of these are exported to modules on GKI; symbols.c resolves them
 * through the kprobe-bootstrapped kallsyms and fills them in before any
 * ZeroSU init runs. Prototypes must match the kernel exactly or the
 * argument registers will not line up.
 * ======================================================================== */

/* ebitmap_set_bit() changed its bit parameter from unsigned long to u32 in
 * 6.x. On a 64-bit target those are different argument widths, so the
 * prototype is version split rather than cast. */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 0, 0)
extern int (*zsu_ebitmap_set_bit)(struct zsu_ebitmap *e, unsigned long bit,
				   int value);
extern int (*zsu_ebitmap_get_bit)(const struct zsu_ebitmap *e,
				   unsigned long bit);
#else
extern int (*zsu_ebitmap_set_bit)(struct zsu_ebitmap *e, u32 bit, int value);
extern int (*zsu_ebitmap_get_bit)(const struct zsu_ebitmap *e, u32 bit);
#endif
extern void (*zsu_ebitmap_destroy)(struct zsu_ebitmap *e);
extern int (*zsu_symtab_insert)(struct zsu_symtab *s, char *name, void *datum);
extern void *(*zsu_symtab_search)(struct zsu_symtab *s, const char *name);

#if ZSU_SECCTX_TO_SID_TAKES_STATE
extern int (*zsu_security_context_str_to_sid)(struct zsu_selinux_state *state,
					      const char *scontext, u32 *out_sid,
					      gfp_t gfp);
#else
extern int (*zsu_security_context_str_to_sid)(const char *scontext,
					      u32 *out_sid, gfp_t gfp);
#endif

/* Address of the exported selinux_state global. */
extern struct zsu_selinux_state *zsu_selinux_state;

/* selinux.c: struct lsm_blob_sizes *, lbs_cred is its first member */
extern int *zsu_selinux_blob_sizes;

/*
 * elevate.c: cred plumbing. All of these are resolved rather than called
 * directly, because Android GKI 6.18 moves prepare_creds() into a mangled
 * EXPORT_SYMBOL_NS() namespace and enables CONFIG_TRIM_UNUSED_KSYMS=y, so a
 * direct call would either need a MODULE_IMPORT_NS() we cannot name
 * reliably across releases, or would fail to link after symbol trimming.
 *
 * Prototypes verified against kernel/cred.c on 5.10 and 6.18:
 *   struct cred *prepare_creds(void);          <-- takes NO arguments
 *   int           commit_creds(struct cred *);
 *   void          __put_cred(struct cred *);   (EXPORT_SYMBOL, reached
 *                                           through the inline put_cred())
 *   int           set_cred_ucounts(struct cred *);   6.18, returns int
 */
extern struct cred *(*sym_prepare_creds)(void);
extern int (*sym_commit_creds)(struct cred *new);
/* verified in 6.18 cred.c: returns int, not void */
extern int (*sym_set_cred_ucounts)(struct cred *cred);

/*
 * alloc_uid() is in kernel/user.c and is NOT exported on 5.10 or 6.18, so it is
 * resolved. Signature verified in both branches:
 *
 *   struct user_struct *alloc_uid(kuid_t uid);
 *
 * It takes the uid itself, not a namespace, and stamps it into the new
 * user_struct. Its sibling free_uid() *is* EXPORT_SYMBOL_GPL and is declared
 * in <linux/sched/user.h>, so elevate.c calls that one directly.
 *
 * set_user() does not exist any more (removed in 2.6.29; zero hits in both
 * kernel/user.c and kernel/cred.c), so it is gone from here too.
 */
extern struct user_struct *(*sym_alloc_uid)(kuid_t uid);

/* seccomp.c */
extern void (*sym_seccomp_filter_release)(struct task_struct *tsk);


/*
 * Validated once at __init by zsu_selinux_discover() and then cached, so no
 * hot path pays for the probe.
 *
 * We cache the *slot* - the address of the pointer inside selinux_state -
 * not the value it happens to hold at that moment. Policies are replaced
 * under policy_mutex via rcu_replace_pointer(), so a cached
 * struct zsu_selinux_policy pointer would go stale after any selinuxfs
 * policy reload; the slot address is what stays valid.
 */
extern struct zsu_selinux_policy **zsu_policy_slot;
extern struct mutex *zsu_policy_mutex_cached;

/*
 * selinux_state.policy sits at an offset that depends on the length of the
 * policycap[] array, i.e. on the kernel version *and* on which POLICYDB_CAP_*
 * a vendor backported. The compile time mirror is right for the six GKI
 * branches we verified; the probe below covers a near miss without ever
 * trusting an unvalidated pointer.
 */
#define ZSU_POLICY_PROBE_STEP	((size_t)sizeof(void *))	/* 8 */
#define ZSU_POLICY_PROBE_SLOTS	4			/* +/- 32 bytes */

/* ========================================================================
 * Accessors and the version-split helper
 * ======================================================================== */

static inline struct zsu_selinux_state *zsu_state(void)
{
	return zsu_selinux_state;
}

/*
 * Derived, never probed independently: in every branch from 5.10 to 6.18
 *   offsetof(selinux_state, policy_mutex) == offsetof(..., policy) + 8
 * so once the policy pointer is validated the mutex address follows from it.
 */
static inline struct mutex *zsu_policy_mutex(void)
{
	return zsu_policy_mutex_cached;
}

/*
 * Caller must hold policy_mutex, which is what serializes policy
 * replacement (rcu_replace_pointer(state->policy, ...) is done under it).
 * Deliberately *not* wrapped in rcu_read_lock(): every resize in sepolicy.c
 * performs GFP_KERNEL allocations and sleeping is illegal inside an RCU
 * read-side critical section.
 */
static inline struct zsu_selinux_policy *zsu_policy(void)
{
	return rcu_dereference_protected(*zsu_policy_slot,
					 lockdep_is_held(zsu_policy_mutex()));
}

static inline struct zsu_policydb *zsu_policydb(void)
{
	return &zsu_policy()->policydb;
}

/*
 * Fail-closed runtime verification of the mirrored offsets. If any offset in
 * this file were wrong for a given kernel, these invariants are the first
 * thing that breaks; refuse to hand out a policydb rather than corrupt it.
 * Caller must hold policy_mutex.
 */
static inline bool zsu_selinux_layout_check(const struct zsu_policydb *p)
{
	u32 nprim, ncls, nrole;

	if (!p)
		return false;

	nprim = p->p_types.nprim;
	ncls = p->p_classes.nprim;
	nrole = p->p_roles.nprim;

	if (!nprim || nprim > 0xffff || ncls < 10 || ncls > 0x400 ||
	    nrole < 2 || nrole > 0x400)
		return false;
	/* loader invariant: the type symtab and nprim always agree */
	if (p->symtab[ZSU_SYM_TYPES].nprim != nprim)
		return false;
	/* every indexed array must exist before it is indexed */
	if (!p->type_val_to_struct || !p->type_attr_map_array ||
	    !p->sym_val_to_name[ZSU_SYM_TYPES] || !p->role_val_to_struct)
		return false;

	/*
	 * "kernel" is present in every Android policy (it is the base type
	 * the rest is declared against), and a name lookup cannot succeed on
	 * garbage that merely happens to look like plausible counters.
	 */
	if (!zsu_symtab_search((struct zsu_symtab *)&p->p_types, "kernel"))
		return false;

	return true;
}

static inline struct zsu_policydb *zsu_selinux_layout_sane(void)
{
	struct zsu_policydb *p;

	if (!zsu_policy_slot || !*zsu_policy_slot) {
		pr_err("zerosu: SELinux layout never discovered\n");
		return NULL;
	}
	if (!lockdep_is_held(zsu_policy_mutex())) {
		pr_err("zerosu: policydb touched without policy_mutex\n");
		return NULL;
	}

	p = &zsu_policy()->policydb;
	if (!zsu_selinux_layout_check(p)) {
		pr_err("zerosu: policydb failed sanity check\n");
		return NULL;
	}

	return p;
}

/*
 * One shot, at __init. Tries the compile time offset first, then a small
 * window either side of it for vendor kernels whose POLICYDB_CAP_* count
 * differs from the GKI default. A candidate only wins if the whole policydb
 * validates *and* "kernel" resolves as a type, so a false positive would
 * require landing exactly on another valid policy-shaped object.
 */
int zsu_selinux_discover(void);

/* Thin version-split wrapper so callers never see the ABI split. */
static inline int zsu_context_str_to_sid(const char *scontext, u32 *out_sid)
{
#if ZSU_SECCTX_TO_SID_TAKES_STATE
	return zsu_security_context_str_to_sid(zsu_state(), scontext, out_sid,
					       GFP_KERNEL);
#else
	return zsu_security_context_str_to_sid(scontext, out_sid, GFP_KERNEL);
#endif
}

/*
 * set_cred_ucounts() arrived in 5.14 with per-uid accounting; before that the
 * concept does not exist and there is nothing to rebind. commit_creds() does
 * *not* call it (verified in 6.18: the call inside cred.c belongs to
 * prepare_kernel_cred()), so this must happen before the cred is committed or
 * the new uid is billed to the old uid's ucounts.
 *
 * Safe to call twice: it early-returns when the namespace and uid are
 * unchanged.
 */
static inline int zsu_rebind_ucounts(struct cred *new_cred)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 14, 0)
	if (!sym_set_cred_ucounts)
		return -ENOENT;
	return sym_set_cred_ucounts(new_cred);
#else
	(void)new_cred;
	return 0;
#endif
}

/*
 * Stop the syscall path from consulting seccomp for this task.
 *
 * Two independent bits have to go, and they live in different places:
 *
 *   TIF_SECCOMP is what __secure_computing() gates on, so clearing it is
 *     what actually stops enforcement. clear_ti_thread_flag() is an inline in
 *     sched.h and is available on every kernel in range.
 *
 *   SYSCALL_WORK_SECCOMP is the *deferred work* bit: with CONFIG_GENERIC_ENTRY
 *     (x86_64) a pending seccomp filter installation is parked there and the
 *     syscall entry path picks it up. Clearing it needs the
 *     clear_task_syscall_work() helper, which is a MACRO in
 *     <linux/thread_info.h>, not a function:
 *
 *       #define clear_task_syscall_work(t, fl) \
 *               clear_bit(SYSCALL_WORK_BIT_##fl, &task_thread_info(t)->syscall_work)
 *
 *     There is therefore no symbol for kallsyms to find, and resolving one
 *     always came back NULL - the bit was never cleared. The macro also does
 *     not exist at all on 5.10 (include/linux/thread_info.h has no
 *     syscall_work references there), so the whole thing is guarded by
 *     SYSCALL_WORK_SECCOMP being defined.
 */
static inline void zsu_clear_seccomp_work(struct task_struct *tsk)
{
	clear_ti_thread_flag(task_thread_info(tsk), TIF_SECCOMP);

#ifdef SYSCALL_WORK_SECCOMP
	clear_task_syscall_work(tsk, SECCOMP);
#endif
}

/*
 * Turn a bare heap task_struct into something seccomp_filter_release() will
 * accept as the owner of a filter.
 *
 * seccomp_filter_release() reads tsk->seccomp.filter and releases the filter's
 * refcount. Handing it a real task is impossible (we are not allowed to steal
 * another task's state), so it gets a zeroed one that already points at the
 * detached filter.
 *
 * PF_EXITING is set because the release path treats an exiting task
 * specially. It lives in task_struct->flags on every kernel in range -
 * signal_struct, which used to carry it, was removed in 5.8 - so there is no
 * version split to maintain here.
 */
static inline void zsu_prep_fake_seccomp_task(struct task_struct *fake,
					      struct seccomp_filter *f)
{
	memset(&fake->seccomp, 0, sizeof(fake->seccomp));
	fake->seccomp.filter = f;
	fake->flags |= PF_EXITING;
}

#endif /* _ZSU_COMPAT_H */