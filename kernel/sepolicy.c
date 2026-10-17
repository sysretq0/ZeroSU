// SPDX-License-Identifier: GPL-2.0
/*
 * ZeroSU - kernel/sepolicy.c
 *
 * Synthesizes the "zsu" type into the *live* policydb so that u:r:zsu:s0 is
 * a valid security context, resolves its SID once, and hands that SID to the
 * credential elevation path (selinux.c).
 *
 * Scope discipline: this file only ever adds one type, once. It never
 * removes, never rewrites an existing type, and never touches te_avtab. If
 * anything about the running policy is unexpected we refuse to load rather
 * than guess, because a half-applied type insert is exactly what turns the
 * first AVC for u:r:zsu:s0 into an out-of-bounds slab read.
 *
 * Three indexing conventions are in play and they are NOT the same. Getting
 * any of them wrong is a security bug rather than a crash:
 *
 *   policydb->type_attr_map_array[v - 1]   bit (v - 1)   [self bit]
 *   role_datum->types                       bit (v - 1)
 *   policydb->permissive_map                bit v         <-- 1-based!
 *
 * Two allocation conventions are in play as well: type_val_to_struct,
 * sym_val_to_name and type_attr_map_array all come from kvcalloc() and are
 * released by policydb_destroy() through kvfree(), so they must be grown
 * with the kvmalloc family and retired with kvfree() - never krealloc(),
 * which rejects vmalloc'ed memory outright.
 *
 * Locking: policy_mutex serializes policy writers (rcu_replace_pointer of
 * state->policy happens under it). RCU readers - security_compute_av() and
 * friends - walk these arrays under rcu_read_lock() *without* the mutex, so a
 * replaced array may only be freed after synchronize_rcu(). Doing that inside
 * the mutex would stall every SELinux writer for a grace period, so
 * retirement happens after the unlock.
 */

#include <linux/errno.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "include/zerosu.h"

#define ZSU_TYPE_NAME	"zsu"
#define ZSU_ROLE_NAME	"r"

struct selinux_policy **zsu_policy_slot;
struct mutex *zsu_policy_mutex_cached;

/*
 * Resolve selinux_state.policy, tolerating a vendor policycap[] count that
 * differs from the compile time mirror. See compat.h for the rationale.
 *
 * Runs before policy_mutex can be locked, so it caches the slot address and
 * leaves the dereference to callers that hold the lock.
 */
int zsu_selinux_discover(void)
{
	const size_t home = offsetof(struct selinux_state, policy);
	struct selinux_state *state = zsu_selinux_state;
	struct selinux_policy **cand_slot;
	struct selinux_policy *pol;
	size_t off;
	int slot;

	if (!state) {
		pr_err(ZSU_LOG_PREFIX "selinux_state unresolved\n");
		return -ENODEV;
	}

	/* home first, then both directions one slot at a time */
	for (slot = -ZSU_POLICY_PROBE_SLOTS; slot <= ZSU_POLICY_PROBE_SLOTS; slot++) {
		if (slot == 0) {
			off = home;
		} else {
			off = (slot < 0) ? home - (size_t)(-slot) * ZSU_POLICY_PROBE_STEP
					 : home + (size_t)slot * ZSU_POLICY_PROBE_STEP;
			if (off > (size_t)(UINTPTR_MAX / 2))
				continue;
		}

		cand_slot = (struct selinux_policy **)((char *)state + off);
		pol = *cand_slot;
		if (!pol)
			continue;

		if (zsu_selinux_layout_check(&pol->policydb)) {
			zsu_policy_slot = cand_slot;
			/*
			 * Verified invariant: policy_mutex is the member
			 * immediately after policy in every branch from
			 * 5.10 to 6.18, so the mutex address follows from
			 * a validated slot. No second probe.
			 */
			zsu_policy_mutex_cached =
				(struct mutex *)((char *)state + off + sizeof(void *));

			pr_info(ZSU_LOG_PREFIX "selinux_state.policy at %s0x%zx (expected 0x%zx)\n",
				off == home ? "" : (off > home ? "+" : "-"),
				off > home ? off - home : home - off, home);
			return 0;
		}
	}

	pr_err(ZSU_LOG_PREFIX "cannot locate selinux_state.policy (tried 0x%zx +/-32)\n",
	       home);
	return -ENODEV;
}

/*
 * Grow one indexed array by one slot.
 *
 * The old array came from kvcalloc() and is released with kvfree(), and so
 * is this one. The tail slot is zero filled, which is all ebitmap_init()
 * does, so the new ebitmap is immediately valid.
 */
static void *zsu_grow_array(const void *old, size_t old_elems, size_t elemsize)
{
	void *neu;

	neu = kvcalloc(old_elems + 1, elemsize, GFP_KERNEL);
	if (!neu)
		return NULL;
	if (old)
		memcpy(neu, old, old_elems * elemsize);

	return neu;
}

/*
 * Mark an already present type usable again. ebitmap_set_bit(value=1) is
 * idempotent, so a second module load is a no-op. The permissive bit is only
 * ever set, never cleared, which is why there is no get_bit round trip.
 */
static int zsu_sepolicy_adopt(struct policydb *p, u32 val)
{
	/*
	 * permissive_map is indexed by the raw type value, unlike every other
	 * type bitmap:  services.c does
	 *     ebitmap_get_bit(&policydb->permissive_map, scontext->type)
	 */
	return zsu_ebitmap_set_bit(&p->permissive_map, val, 1);
}

/*
 * This subsystem's own symbol table. SELinux internals are not exported to
 * modules on any GKI branch, so all of these go through the resolver.
 *
 * The ebitmap entry points carry version split prototypes in compat.h
 * (unsigned long vs u32 bit index); the table stores void * so it does not
 * have to care, and the prototypes still get checked at the call sites.
 */
/*
 * Storage for the resolved-symbol slots declared extern in compat.h. The
 * definitions sit next to the table that fills them.
 */
__typeof__(zsu_selinux_state) zsu_selinux_state;
__typeof__(zsu_ebitmap_set_bit) zsu_ebitmap_set_bit;
__typeof__(zsu_ebitmap_destroy) zsu_ebitmap_destroy;
__typeof__(zsu_symtab_insert) zsu_symtab_insert;
__typeof__(zsu_symtab_search) zsu_symtab_search;

static struct zsu_symtab_ent sepolicy_syms[] = {
	{ "selinux_state",			(void **)&zsu_selinux_state,		true },
	{ "ebitmap_set_bit",			(void **)&zsu_ebitmap_set_bit,		true },
	{ "symtab_insert",			(void **)&zsu_symtab_insert,		true },
	{ "symtab_search",			(void **)&zsu_symtab_search,		true },
	/* only used on the rollback paths, hence optional */
	{ "ebitmap_destroy",			(void **)&zsu_ebitmap_destroy,		false },
};

int zsu_sepolicy_syms_init(void)
{
	return zsu_resolve_symtab(sepolicy_syms, ARRAY_SIZE(sepolicy_syms),
				  "sepolicy");
}

static int zsu_sepolicy_add(void)
{
	struct type_datum **old_tvs, **new_tvs;
	struct ebitmap *old_tam, *new_tam;
	char **old_svn, **new_svn;
	struct type_datum *td, *existing;
	struct role_datum *role;
	struct policydb *p;
	struct mutex *mtx;
	char *key;
	u32 old_nprim, val;
	int rc;

	mtx = zsu_policy_mutex();
	mutex_lock(mtx);

	p = zsu_selinux_layout_sane() ? &zsu_policy()->policydb : NULL;
	if (!p) {
		mutex_unlock(mtx);
		return -EINVAL;
	}

	/* Already there? Nothing to grow, nothing to free. */
	existing = zsu_symtab_search(&p->p_types, ZSU_TYPE_NAME);
	if (existing) {
		rc = zsu_sepolicy_adopt(p, existing->value);
		mutex_unlock(mtx);
		if (!rc)
			pr_info(ZSU_LOG_PREFIX "type %s present, reusing value %u\n",
			       ZSU_TYPE_NAME, existing->value);
		return rc;
	}

	/*
	 * Resolve the role *before* any mutation, so an unexpected policy
	 * leaves us with nothing to undo.
	 */
	existing = zsu_symtab_search(&p->p_roles, ZSU_ROLE_NAME);
	if (!existing) {
		pr_err(ZSU_LOG_PREFIX "role '%s' missing, cannot authorize %s\n",
		       ZSU_ROLE_NAME, ZSU_TYPE_NAME);
		rc = -ENOENT;
		goto out_unlock;
	}
	if (!existing->value || existing->value > p->p_roles.nprim ||
	    !p->role_val_to_struct[existing->value - 1]) {
		pr_err(ZSU_LOG_PREFIX "role '%s' datum out of range (value %u)\n",
		       ZSU_ROLE_NAME, existing->value);
		rc = -EINVAL;
		goto out_unlock;
	}
	role = p->role_val_to_struct[existing->value - 1];

	old_nprim = p->p_types.nprim;
	val = old_nprim + 1;

	td = kzalloc(sizeof(*td), GFP_KERNEL);
	if (!td) {
		rc = -ENOMEM;
		goto out_unlock;
	}
	td->value = val;
	td->bounds = 0;
	td->primary = 1;
	td->attribute = 0;

	/*
	 * symtab keys are owned by the symtab: policydb_destroy() kfree()s
	 * them (every *_destroy() callback starts with kfree(key)), so this
	 * must be a heap string that we never free ourselves.
	 */
	key = kstrdup(ZSU_TYPE_NAME, GFP_KERNEL);
	if (!key) {
		rc = -ENOMEM;
		goto out_free_key;
	}

	old_tvs = rcu_dereference_protected(p->type_val_to_struct,
					   lockdep_is_held(mtx));
	old_tam = rcu_dereference_protected(p->type_attr_map_array,
					   lockdep_is_held(mtx));
	old_svn = rcu_dereference_protected(p->sym_val_to_name[ZSU_SYM_TYPES],
					   lockdep_is_held(mtx));

	new_tvs = zsu_grow_array(old_tvs, old_nprim,
				 sizeof(*p->type_val_to_struct));
	new_tam = zsu_grow_array(old_tam, old_nprim,
				 sizeof(*p->type_attr_map_array));
	new_svn = zsu_grow_array(old_svn, old_nprim, sizeof(char *));
	if (!new_tvs || !new_tam || !new_svn) {
		rc = -ENOMEM;
		goto out_free_new;
	}

	/* Fill the new slot before anybody can observe the pointer. */
	new_tvs[val - 1] = td;
	new_svn[val - 1] = key;
	rc = zsu_ebitmap_set_bit(&new_tam[val - 1], val - 1, 1);
	if (rc)
		goto out_free_new;

	/*
	 * Publish all three arrays before nprim moves. Until nprim is bumped
	 * no reader can reach index val - 1, so this is the moment the new
	 * storage becomes observable.
	 */
	smp_store_release(&p->type_val_to_struct, new_tvs);
	smp_store_release(&p->type_attr_map_array, new_tam);
	smp_store_release(&p->sym_val_to_name[ZSU_SYM_TYPES], new_svn);

	/* symtab_insert() does not touch nprim, and it can still fail. */
	rc = zsu_symtab_insert(&p->p_types, key, td);
	if (rc) {
		pr_err(ZSU_LOG_PREFIX "symtab_insert(%s) failed: %d\n",
		       ZSU_TYPE_NAME, rc);
		smp_store_release(&p->type_val_to_struct, old_tvs);
		smp_store_release(&p->type_attr_map_array, old_tam);
		smp_store_release(&p->sym_val_to_name[ZSU_SYM_TYPES], old_svn);
		goto out_free_new_rcu;
	}

	/* Commit point: everything above is undoable, this is not. */
	smp_store_release(&p->p_types.nprim, val);

	/*
	 * Authorize the type for role r (indexed by value - 1) and mark it
	 * permissive (indexed by value). The role bit is mandatory:
	 * policydb_context_isvalid() rejects u:r:zsu:s0 without it, which
	 * would make the SID lookup below fail.
	 */
	rc = zsu_ebitmap_set_bit(&role->types, val - 1, 1);
	if (!rc)
		rc = zsu_ebitmap_set_bit(&p->permissive_map, val, 1);
	if (rc)
		pr_err(ZSU_LOG_PREFIX "authorizing %s failed: %d\n", ZSU_TYPE_NAME, rc);

	mutex_unlock(mtx);

	/* Grace period, then release arrays a reader may still hold. */
	synchronize_rcu();
	kvfree(old_tvs);
	kvfree(old_tam);
	kvfree(old_svn);

	return rc;

out_free_new_rcu:
	mutex_unlock(mtx);
	/* The published arrays may have been read: wait before freeing. */
	synchronize_rcu();
	/*
	 * We set one bit in new_tam[val - 1] before publishing, which may have
	 * allocated a node inside it. kvfree() on the array would leak that
	 * node, so unwind the ebitmap first. Safe to call unconditionally:
	 * ebitmap_destroy() on a zeroed ebitmap is a no-op, and by the time we
	 * reach the symtab_insert() failure the slot has been initialised.
	 */
	if (zsu_ebitmap_destroy)
		zsu_ebitmap_destroy(&new_tam[val - 1]);
out_free_new:
	kvfree(new_tvs);
	kvfree(new_tam);
	kvfree(new_svn);
out_free_key:
	kfree(td);
	kfree(key);
out_unlock:
	mutex_unlock(mtx);
	return rc;
}

int zsu_sepolicy_init(void)
{
	int rc;

	rc = zsu_sepolicy_syms_init();
	if (rc)
		return rc;

	/* Needs zsu_symtab_search from the table above. */
	rc = zsu_selinux_discover();
	if (rc)
		return rc;

	rc = zsu_sepolicy_add();
	if (rc)
		return rc;

	/*
	 * SID resolution deliberately does not happen here: the SID lives in
	 * selinux.c (zsu_cached_sid), because that is also where it is
	 * stamped. main.c orders zsu_sepolicy_init() before
	 * zerosu_selinux_init() for exactly that dependency.
	 */
	return 0;
}

void zsu_sepolicy_exit(void)
{
	/*
	 * The type stays behind on purpose: it is unreachable without this
	 * module's anon inode, and undoing it would mean shrinking
	 * type_val_to_struct again under live RCU readers, which is exactly
	 * the hazard this file exists to avoid.
	 */
}