/* Minimal kernel-header stubs: SYNTAX/TYPE checking only.
 * Not a build environment. Used by /tmp/stubcheck.sh to compile
 * ZeroSU's compat.h + sepolicy.c with -fsyntax-only -Wall -Wextra
 * outside a kernel tree. */
#ifndef _ZSU_STUB_H
#define _ZSU_STUB_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t  u8;
typedef unsigned int gfp_t;
typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef signed char __s8;
typedef short __s16;
typedef int __s32;
typedef long long __s64;
typedef long long loff_t;
typedef unsigned long long u64;
typedef unsigned int __u;
typedef unsigned int kuid_t;
typedef unsigned int kgid_t;
#define INVALID_UID ((kuid_t)~0U)
#define make_kgid(_ns, _v) ((kgid_t)(_v))
#define make_kuid(_ns, _v) ((kuid_t)(_v))
#define GLOBAL_ROOT_UID ((kuid_t)0)
#define uid_eq(_a, _b) ((_a) == (_b))
static inline kuid_t current_uid(void) { return 0; }
#define sort(_a, _n, _s, _c, _x) do { (void)(_a); (void)(_n); } while (0)
typedef int s32;
#define __rcu
#define __init
#define __nocfi
#define GFP_KERNEL 0u
#define KERNEL_VERSION(a, b, c) (((a) << 16) + ((b) << 8) + (c))
#ifndef LINUX_VERSION_CODE
#define LINUX_VERSION_CODE KERNEL_VERSION(5, 10, 0)
#endif

#define static_assert(c, msg) _Static_assert(c, msg)

#define NULL ((void *)0)

#include <stdio.h>
#include <string.h>

#define ENOENT  2
#define EINVAL  22
#define ENOMEM  12
#define EEXIST  17
#define EAGAIN  11
#define ENODEV  19
#define EFAULT  14

/*
 * linux/ioctl.h subset, mirroring asm-generic/ioctl.h exactly (the size
 * field carries a raw sizeof, there is no >>2). Only needed so the UAPI
 * header typechecks in the userspace branch; the authoritative encoding is
 * proven by tests/abi_layout.c against the real host header.
 */
#define _IOC_NRBITS		8
#define _IOC_TYPEBITS		8
#define _IOC_SIZEBITS		14
#define _IOC_DIRBITS		2
#define _IOC_NRSHIFT		0
#define _IOC_TYPESHIFT		(_IOC_NRSHIFT + _IOC_NRBITS)
#define _IOC_SIZESHIFT		(_IOC_TYPESHIFT + _IOC_TYPEBITS)
#define _IOC_DIRSHIFT		(_IOC_SIZESHIFT + _IOC_SIZEBITS)
#define _IOC_NONE		0U
#define _IOC_WRITE		1U
#define _IOC_READ		2U
#define _IOC_TYPECHECK(t)	(sizeof(t))
#define _IOC(dir, type, nr, size)					\
	(((dir) << _IOC_DIRSHIFT) | ((type) << _IOC_TYPESHIFT) |	\
	 ((nr) << _IOC_NRSHIFT) | ((size) << _IOC_SIZESHIFT))
#define _IOR(type, nr, argtype)	_IOC(_IOC_READ, (type), (nr), _IOC_TYPECHECK(argtype))
#define _IOW(type, nr, argtype)	_IOC(_IOC_WRITE, (type), (nr), _IOC_TYPECHECK(argtype))
#define _IOWR(type, nr, argtype)	_IOC(_IOC_READ | _IOC_WRITE, (type), (nr), _IOC_TYPECHECK(argtype))

static inline void *memcpy_unused_(void *d, const void *s, size_t n)
{ (void)d; (void)s; (void)n; return NULL; }

#define pr_err(...)   do { } while (0)
#define pr_warn(...)  do { } while (0)
#define pr_info(...)  do { } while (0)
#define pr_debug(...) do { } while (0)

#define READ_ONCE(x)  (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, v) ((x) = (v))
#define smp_store_release(p, v) WRITE_ONCE(*(p), (v))
#define smp_load_acquire(p) (*(volatile typeof(*(p)) *)(p))

#define rcu_read_lock()  do { } while (0)
#define rcu_read_unlock() do { } while (0)
#define synchronize_rcu() do { } while (0)
/* kernel semantics: these take a *pointer to* the field, not the field */
#define rcu_dereference(p) (*(volatile typeof(p) *)&(p))
#define rcu_dereference_protected(p, c) rcu_dereference(p)

struct page { int x; };
struct mutex { int x; };
static inline void mutex_lock(struct mutex *m) { (void)m; }
static inline void mutex_unlock(struct mutex *m) { (void)m; }
static inline int lockdep_is_held(struct mutex *m) { (void)m; return 1; }

static inline void *kzalloc(size_t n, gfp_t f) { (void)n; (void)f; return NULL; }
static inline void *kmalloc(size_t n, gfp_t f) { (void)n; (void)f; return NULL; }
#define GFP_ATOMIC 0u
static inline void *kvcalloc_array(size_t n, size_t s, gfp_t f)
{ (void)n; (void)s; (void)f; return NULL; }
static inline void kvfree(const void *p) { (void)p; }
static inline void kfree(const void *p) { (void)p; }
static inline char *kstrdup(const char *s, gfp_t f)
{ (void)s; (void)f; return NULL; }

/* --- kprobes / pt_regs / cred, used by symbols.c and selinux.c --- */
/* All three arches' pt_regs layouts side by side: the arch.h branch under
 * test only ever reads the fields belonging to its own CONFIG_*. */
struct pt_regs {
	unsigned long regs[32];		/* arm64 */
	unsigned long parm1;		/* PT_REGS_PARM1 on x86/arm64/riscv */
	unsigned long di, si, dx, cx, r8, r9;		/* x86_64 */
	unsigned long a0, a1, a2, a3, a4, a5;		/* riscv */
};
#define PT_REGS_PARM1(_r)	((_r)->parm1)
struct kprobe {
	int (*pre_handler)(struct kprobe *, struct pt_regs *);
	unsigned long addr;
	const char *symbol_name;
};
static inline int register_kprobe(struct kprobe *kp) { (void)kp; return -EFAULT; }
static inline void unregister_kprobe(struct kprobe *kp) { (void)kp; }

#define ARRAY_SIZE(_a)	(sizeof(_a) / sizeof((_a)[0]))
#define __ro_after_init
#define EOPNOTSUPP 95
#define ENOKEY 126
#define EPERM 1
#define ENOTTY 25
#define EIO 5
#define module_param(_n, _t, _p)
#define module_init(_f)	static void *__zsu_modinit_##_f(void) { }
#define module_exit(_f)	static void *__zsu_modexit_##_f(void) { }
#define MODULE_LICENSE(_s)	MODULE_INFO_STR(_s)
#define MODULE_AUTHOR(_s)	MODULE_INFO_STR(_s)
#define MODULE_DESCRIPTION(_s)	MODULE_INFO_STR(_s)
#define MODULE_VERSION(_s)	MODULE_INFO_STR(_s)
#define MODULE_INFO(_a, _v)	MODULE_INFO_STR(#_v)
#define ZSU__CAT2(a, b)	a##b
#define ZSU__CAT(a, b)	ZSU__CAT2(a, b)
#define MODULE_INFO_STR(_s)	static const char ZSU__CAT(__modinfo_, __LINE__)[] __attribute__((unused)) = _s
#define __used_ __attribute__((used))
#define MODULE_PARM_DESC(_n, _d)
#define ENOTSUP 95
#define __exit
#define __init
#define ESRCH 3
#define EPERM_ 0
#define OPTIMIZER_HIDE_VAR(_x) do { } while (0)
struct mm_struct;
struct seccomp_filter;
struct seccomp { int mode; int filter_count; struct seccomp_filter *filter; };
struct sighand_struct { int siglock; };
struct task_struct {
	unsigned long flags;
	struct mm_struct *mm;
	struct sighand_struct *sighand;
	struct seccomp seccomp;
	struct signal_struct *signal;
	struct cred *cred, *real_cred;
	unsigned long atomic_flags;
	unsigned int __rcu *ptr;		/* lockdep_map stand-in */
};
struct signal_struct { int live; };
#define task_lock(_t)		do { } while (0)
#define task_unlock(_t)		do { } while (0)
#define rcu_assign_pointer(_p, _v) do { (_p) = (typeof(_p))(_v); } while (0)
#define TIF_SECCOMP	0
#define PF_EXITING	0x00000004
#define CAP_FULL_SET zsu_cap_full
#define CAP_EMPTY_SET zsu_cap_empty
extern const struct zsu_cap_t zsu_cap_full, zsu_cap_empty;
extern const struct zsu_cap_t zsu_cap_full;
#define PFA_NO_NEW_PRIVS 0x00000001
#define clear_bit(_b, _a)	do { } while (0)
#define set_bit(_b, _a)	do { } while (0)
#define SECCOMP_MODE_DISABLED 0
#define SECCOMP		0
#define spin_lock_irqsave(_l, _f)	do { (_f) = 0; } while (0)
#define spin_unlock_irqrestore(_l, _f)	do { (void)(_f); } while (0)
struct thread_info {
	unsigned long flags;
	unsigned long syscall_work;
};
#define SYSCALL_WORK_SECCOMP	BIT(1)
#define SYSCALL_WORK_BIT_SECCOMP	1
#define clear_task_syscall_work(_t, _fl)	clear_bit(SYSCALL_WORK_BIT_##_fl, \
						&task_thread_info(_t)->syscall_work)
static inline struct thread_info *task_thread_info(struct task_struct *t)
{ (void)t; return NULL; }
static inline void clear_ti_thread_flag(struct thread_info *ti, int f)
{ (void)ti; (void)f; }

/* --- creds, seccomp, capability: used by elevate.c and seccomp.c --- */
struct user_namespace;
struct user_struct;
struct pid;
struct zsu_cap_t { unsigned long low, high; };
struct seccomp_filter;
struct group_info;
struct cred {
	void *security;
	void *user, *user_ns;
	unsigned int uid, gid;
		struct zsu_cap_t cap_effective, cap_permitted, cap_inheritable;
	struct zsu_cap_t cap_bset, cap_ambient;
};
static inline void cap_raise(struct zsu_cap_t *c, const struct zsu_cap_t *s)
{ (void)c; (void)s; }
static inline void cap_clear(struct zsu_cap_t *c) { (void)c; }
static inline void free_uid(struct user_struct *u) { (void)u; }
static inline struct pid *find_get_pid(unsigned int nr)
{ (void)nr; return NULL; }
static inline void put_pid(struct pid *p) { (void)p; }
enum pid_type { PIDTYPE_PID, PIDTYPE_TGID, PIDTYPE_PGID, PIDTYPE_SID };
static inline struct task_struct *get_pid_task(struct pid *p, enum pid_type t)
{ (void)p; (void)t; return NULL; }
static inline struct cred *get_cred(struct cred *c) { return c; }
static inline void put_cred(struct cred *c) { (void)c; }
static inline void put_group_info(struct group_info *gi) { (void)gi; }
static inline struct group_info *groups_alloc(int n) { (void)n; return NULL; }
static inline int set_groups(struct cred *c, struct group_info *gi)
{ (void)c; (void)gi; return 0; }
static inline int cmp_kgid(const void *a, const void *b)
{ (void)a; (void)b; return 0; }
static inline struct task_struct *get_task_struct(struct task_struct *t)
{ return t; }
static inline void put_task_struct(struct task_struct *t) { (void)t; }
static inline int task_pid_nr_ns(struct task_struct *t, int ns)
{ (void)t; (void)ns; return 0; }
#define ENODEV_ 0
#define EACCES 13

/* --- crypto shash subset, used by supercall.c --- */
struct crypto_shash;
struct shash_desc {
	struct crypto_shash *tfm;
	u64 flags;
	void *ctx;
};
static inline struct crypto_shash *crypto_alloc_shash(const char *n, u32 t,
						       u32 m)
{ (void)n; (void)t; (void)m; return NULL; }
static inline void crypto_free_shash(struct crypto_shash *t) { (void)t; }
static inline unsigned int crypto_shash_descsize(struct crypto_shash *t)
{ (void)t; return 0; }
static inline int crypto_shash_digest(struct shash_desc *d, const void *b,
				      size_t n, void *o)
{ (void)d; (void)b; (void)n; (void)o; return 0; }
static inline void strscpy(char *d, const char *s, size_t n)
{ (void)d; (void)s; (void)n; }
static inline struct cred *current_cred(void) { return NULL; }
#define lockdep_assert_held(_l) do { } while (0)
#define DEFINE_MUTEX(_n) struct mutex _n

/* --- fds, files, anon inode, task_work: used by gateway.c --- */
typedef struct { int counter; } atomic_t;
#define __user
#define O_RDWR	0x0002
#define O_CLOEXEC 0x80000
#define PF_KTHREAD 0x00200000
#define THIS_MODULE ((struct module *)0)
#define container_of(_p, _t, _m) \
	((_t *)(void *)((char *)(_p) - offsetof(_t, _m)))

struct file { void *private_data; };
struct inode;
struct file_operations {
	struct module *owner;
	long (*unlocked_ioctl)(struct file *, unsigned int, unsigned long);
	long (*compat_ioctl)(struct file *, unsigned int, unsigned long);
	int (*release)(struct inode *, struct file *);
	loff_t (*llseek)(struct file *, loff_t, int);
};
struct mm_struct;
struct task_work {
	void (*func)(struct task_work *work);
};
enum task_work_notify { TWA_NONE, TWA_RESUME, TWA_NOWAIT };
struct wait_queue_head { int lock; int head; };
typedef struct wait_queue_head wait_queue_head_t;
struct user_namespace;

static inline void init_waitqueue_head(struct wait_queue_head *wq) { (void)wq; }
static inline void wake_up(struct wait_queue_head *wq) { (void)wq; }
#define wait_event(_wq, _cond) do { (void)(_wq); } while (0)
static inline loff_t no_llseek(struct file *f, loff_t o, int w)
{ (void)f; (void)o; (void)w; return 0; }
static inline long get_unused_fd_flags(unsigned int f) { (void)f; return -1; }
static inline void put_unused_fd(unsigned int fd) { (void)fd; }
static inline void fd_install(unsigned int fd, struct file *f) { (void)fd; (void)f; }
static inline void fput(struct file *f) { (void)f; }
static inline struct file *anon_inode_getfile(const char *n,
					       const struct file_operations *o,
					       void *p, int fl)
{ (void)n; (void)o; (void)p; (void)fl; return NULL; }
static inline void mutex_init(struct mutex *m) { (void)m; }
static inline void mutex_destroy(struct mutex *m) { (void)m; }
static inline int atomic_fetch_add_unless(atomic_t *v, int a, int u)
{ (void)v; (void)a; (void)u; return 0; }
static inline int atomic_dec(atomic_t *v) { (void)v; return 0; }
static inline int atomic_dec_and_test(atomic_t *v) { (void)v; return 1; }
static inline int atomic_inc(atomic_t *v) { (void)v; return 0; }
static inline int atomic_read(const atomic_t *v) { (void)v; return 0; }
#define unlikely(_x)	(_x)
#define likely(_x)	(_x)
static inline unsigned long copy_from_user(void *k, const void __user *u, size_t n)
{ (void)k; (void)u; (void)n; return 0; }
static inline int copy_to_user(void __user *u, const void *k, size_t n)
{ (void)u; (void)k; (void)n; return 0; }
#define IS_ERR_VALUE(p) ((p) == NULL)
#define IS_ERR(p) IS_ERR_VALUE(p)
extern struct task_struct *current;
extern struct mm_struct *current_mm;

#endif /* _ZSU_STUB_H */#define BIT(n) (1UL << (n))
