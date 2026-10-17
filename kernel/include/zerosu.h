/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ZeroSU - kernel/include/zerosu.h
 *
 * Internal kernel side header. Pulls the two layers a .c file may need (the
 * UAPI contract and the compatibility/mirrored ABI layer) and declares the
 * handful of cross file entry points. Userspace never sees this file; it
 * includes uapi/zerosu.h instead.
 */

#ifndef _ZEROSU_H
#define _ZEROSU_H

#include <linux/module.h>
#include <linux/types.h>

struct cred;
struct file;
struct inode;
struct file_operations;

#include "uapi/zerosu.h"

#include "compat.h"

#define ZSU_LOG_PREFIX	"zerosu: "

#ifndef ZSU_VERSION
#define ZSU_VERSION	"0.1.0"
#endif

/* symbols.c: the resolver engine, and only the resolver engine.
 *
 * Subsystems do NOT put their symbol lists in symbols.c. Each owns a static
 * table plus a zsu_<subsys>_syms_init():
 *
 *   static struct zsu_symtab_ent foo_syms[] = {
 *       { "some_internal_fn", (void **)&zsu_some_internal_fn, true },
 *       { "maybe_fn",        (void **)&zsu_maybe_fn,        false },
 *   };
 *   int zsu_foo_syms_init(void) {
 *       return zsu_resolve_symtab(foo_syms, ARRAY_SIZE(foo_syms), "foo");
 *   }
 *
 * 'required' means the module refuses to load if it is missing; optional
 * entries are left NULL and the caller must check before dereferencing.
 *
 * Rule of thumb: if a symbol is EXPORT_SYMBOL/EXPORT_SYMBOL_GPL on GKI
 * 5.10..6.18, call it directly and let the compiler and kCFI handle it.
 * Only genuinely unexported symbols belong in a table like this.
 */
struct zsu_symtab_ent {
	const char *name;
	void **slot;
	bool required;
};

int zerosu_symbols_init(void);
void zerosu_symbols_exit(void);
void *zerosu_resolve_raw(const char *name);	/* NULL if not found */
int zerosu_resolve(const char *name, void **out); /* 0 or -ENOENT */
int zsu_resolve_symtab(struct zsu_symtab_ent *tbl, unsigned int n,
		       const char *owner);

/* sepolicy.c: add the zsu type to the live policydb */
int zsu_sepolicy_init(void);
void zsu_sepolicy_exit(void);
int zsu_sepolicy_syms_init(void);

/*
 * selinux.c: locate the cred blob, resolve the domain SID, stamp it.
 *
 * zerosu_selinux_init() must run *after* zsu_sepolicy_init(): resolving
 * u:r:zsu:s0 requires the type to already exist in the policydb.
 *
 * zerosu_setup_domain() takes a private, not-yet-committed cred (the output
 * of prepare_creds). It never mutates a live cred. @domain may be NULL to
 * mean "the module default domain".
 */
int zerosu_selinux_init(void);
void zerosu_selinux_exit(void);
int zerosu_setup_domain(struct cred *new_cred, const char *domain);
int zsu_selinux_syms_init(void);

/* the cached SID for the module default domain; 0 if init failed */
u32 zsu_sid(void);

/* symbols.c: kallsyms bootstrap, must run before anything else */

/* gateway.c: the reboot(2) entry point and the session anon inode */
struct file_operations;

/*
 * One session: the per-fd context handed to anon_inode_getfile() and carried
 * as file->private_data. Defined here rather than in gateway.c because
 * supercall.c needs the same layout.
 *
 * Locking: ->lock guards the scalar state, ->event_lock the event ring. A
 * session is single-owner (one fd, one task) in practice, but the ioctl path
 * can be driven from another thread holding a dup(), so both are taken.
 *
 * The ring is a fixed array rather than a list: a session is a short-lived
 * fd, so the point is a bounded, allocation-free push/pop rather than
 * unbounded history. ->ring_count is the authority on emptiness;
 * head/tail are indices into ring[].
 */
struct zsu_session {
	struct mutex lock;
	struct mutex event_lock;
	u32 type;			/* ZSU_SESSION_PLAIN | ZSU_SESSION_SU */
	u64 flags;
	bool elevated;
	/*
	 * Set in exactly one place - zerosu_cmd_verify_key() - after the
	 * constant-time digest compare succeeds. Never derived from anything in
	 * struct zerosu_cmd.
	 */
	bool authenticated;
	s32 last_error;			/* negative errno of the last failure */
	u64 grants;			/* successful elevations this session */
	u32 last_grant_mode;
	u64 event_seq;
	u64 events_sent;
	u64 events_dropped;
	struct zerosu_event ring[ZSU_EVENT_RING];
	u32 ring_head;			/* next slot to write */
	u32 ring_tail;			/* oldest unread slot */
	u32 ring_count;
};

int zerosu_gateway_init(void);
void zerosu_gateway_exit(void);
int zsu_gateway_syms_init(void);
int zerosu_session_release(struct inode *inode, struct file *file);
extern const struct file_operations zerosu_session_fops;

/* supercall.c */
int zerosu_supercall_init(void);
void zerosu_supercall_exit(void);
long zerosu_supercall_ioctl(struct file *file, unsigned int cmd,
			    unsigned long arg);
/* called by the ioctl layer after a successful elevation */
void zerosu_note_elevated(struct zsu_session *ctx, u32 mode);

/* seccomp.c */
int zsu_seccomp_syms_init(void);
int zerosu_seccomp_strip(struct task_struct *tsk);
void zerosu_seccomp_exit(void);

/* elevate.c */
int zsu_elevate_syms_init(void);
int zerosu_elevate(u32 mode);
int zerosu_elevate_task(pid_t pid_nr, u32 mode, u64 start_time);

/*
 * Fail closed helper: a NULL kernel pointer for an entry point we resolved
 * by name is always a load error, never a reason to continue with a
 * half-initialised subsystem.
 */
#define zsu_require(_sym) ({						\
	if (!(_sym)) {							\
		pr_err(ZSU_LOG_PREFIX "required symbol missing\n");	\
		return -ENOENT;						\
	}								\
	(0);								\
})

#endif /* _ZEROSU_H */