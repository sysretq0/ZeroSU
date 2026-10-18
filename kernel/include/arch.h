/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ZeroSU - kernel/include/arch.h
 *
 * The only architecture specific file. Everything above it speaks in
 * ZSU_SYS_PARAMn() and ZSU_SYS_PT_REGS(), so gateway.c contains no per arch
 * code at all.
 *
 * Why the double indirection: a kprobe handler receives the pt_regs of the
 * *interrupted* context, but the syscall entry wrapper (__arm64_sys_reboot
 * and friends) receives a pointer to the syscall pt_regs as its first
 * argument. gateway.c therefore takes ZSU_SYS_PT_REGS(kp_regs) to reach the
 * register set the wrapper itself would have used, then reads parameters
 * out of it.
 */

#ifndef _ZSU_ARCH_H
#define _ZSU_ARCH_H

#include <linux/ptrace.h>
#include <linux/types.h>

/* Name of the syscall entry wrapper we kprobe for reboot(2). */
#if defined(CONFIG_ARM64)
#define ZSU_ARCH_NAME		"arm64"
#define ZSU_REBOOT_SYMBOL	"__arm64_sys_reboot"
/*
 * PT_REGS_PARM1 comes from <linux/kprobes.h> on some trees and
 * <asm/ptrace.h> on others; the MediaTek 5.10 vendor tree defines neither, so
 * fall back to reading the arch's first argument register directly.
 */
#ifndef PT_REGS_PARM1
#define PT_REGS_PARM1(_r)	((_r)->regs[0])
#endif
#define ZSU_SYS_PT_REGS(_kp)	((struct pt_regs *)PT_REGS_PARM1(_kp))
#define ZSU_SYS_PARAM1(_r)	((unsigned long)(_r)->regs[0])
#define ZSU_SYS_PARAM2(_r)	((unsigned long)(_r)->regs[1])
#define ZSU_SYS_PARAM3(_r)	((unsigned long)(_r)->regs[2])
#define ZSU_SYS_PARAM4(_r)	((unsigned long)(_r)->regs[3])
#define ZSU_SYS_PARAM5(_r)	((unsigned long)(_r)->regs[4])
#define ZSU_SYS_PARAM6(_r)	((unsigned long)(_r)->regs[5])

#elif defined(CONFIG_X86_64)
#define ZSU_ARCH_NAME		"x86_64"
#define ZSU_REBOOT_SYMBOL	"__x64_sys_reboot"
/*
 * On x86_64 a syscall's arguments live in di/si/dx/r10/r8/r9: the SYSCALL
 * instruction clobbers rcx with the return address and r11 with rflags, so
 * the kernel's syscall convention moves the caller's 4th argument into
 * r10 (glibc's syscall() makes the same move). In the pt_regs snapshot
 * taken at syscall entry, cx therefore holds the *user RIP*, not the 4th
 * argument; r10 is the arg. The wrapper's own first argument (the pt_regs
 * pointer) is in di, which is what ZSU_SYS_PT_REGS reads.
 */
#ifndef PT_REGS_PARM1
#define PT_REGS_PARM1(_r)	((_r)->di)
#endif
#define ZSU_SYS_PT_REGS(_kp)	((struct pt_regs *)PT_REGS_PARM1(_kp))
#define ZSU_SYS_PARAM1(_r)	((unsigned long)(_r)->di)
#define ZSU_SYS_PARAM2(_r)	((unsigned long)(_r)->si)
#define ZSU_SYS_PARAM3(_r)	((unsigned long)(_r)->dx)
#define ZSU_SYS_PARAM4(_r)	((unsigned long)(_r)->r10)
#define ZSU_SYS_PARAM5(_r)	((unsigned long)(_r)->r8)
#define ZSU_SYS_PARAM6(_r)	((unsigned long)(_r)->r9)

#elif defined(CONFIG_RISCV)
#define ZSU_ARCH_NAME		"riscv64"
#define ZSU_REBOOT_SYMBOL	"__riscv_sys_reboot"
#ifndef PT_REGS_PARM1
#define PT_REGS_PARM1(_r)	((_r)->a0)
#endif
#define ZSU_SYS_PT_REGS(_kp)	((struct pt_regs *)PT_REGS_PARM1(_kp))
#define ZSU_SYS_PARAM1(_r)	((unsigned long)(_r)->a0)
#define ZSU_SYS_PARAM2(_r)	((unsigned long)(_r)->a1)
#define ZSU_SYS_PARAM3(_r)	((unsigned long)(_r)->a2)
#define ZSU_SYS_PARAM4(_r)	((unsigned long)(_r)->a3)
#define ZSU_SYS_PARAM5(_r)	((unsigned long)(_r)->a4)
#define ZSU_SYS_PARAM6(_r)	((unsigned long)(_r)->a5)

#else
#error "ZeroSU: unsupported architecture (need arm64, x86_64 or riscv64)"
#endif

/*
 * reboot(2) takes exactly one argument. Reading it through the wrapper's
 * pt_regs keeps us independent of how each arch shuffles syscall arguments
 * into the interrupted context.
 */
static inline unsigned long zsu_reboot_mode(struct pt_regs *kp_regs)
{
	return ZSU_SYS_PARAM1(ZSU_SYS_PT_REGS(kp_regs));
}

#endif /* _ZSU_ARCH_H */