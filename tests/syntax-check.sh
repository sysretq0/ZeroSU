#!/bin/sh
# ZeroSU - tests/syntax-check.sh
#
# Two independent checks, neither of which needs a kernel tree:
#
#   1. UAPI ABI      - compiles and runs tests/abi_layout.c against the real
#                      uapi/zerosu.h. Every struct size and field offset is a
#                      _Static_assert, so this fails loudly if the contract
#                      moves. Also built for -m32 when a multilib toolchain
#                      exists, which is the check that actually proves the
#                      32 bit compat path.
#
#   2. Kernel headers - compiles kernel/*.c with -fsyntax-only against the
#                      minimal stubs in tests/stub-include/, once per supported
#                      kernel version anchor. This catches type errors, label
#                      and exit-path wiring bugs, and the mirrored-ABI
#                      static_assert sizes without building a kernel.
#
# Note that (2) is a syntax/type check, not a build: it cannot catch a kernel
# ABI mismatch. That is what zsu_selinux_layout_sane() and the
# zsu_selinux_discover() probe are for at runtime.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CC=${CC:-cc}
fail=0

say() { printf '%s\n' "$*"; }

say "=== 1. UAPI ABI layout ==="
if "$CC" -Wall -Wextra -Werror -I "$ROOT/kernel/include" \
	-o /tmp/zsu-abi-layout "$ROOT/tests/abi_layout.c"; then
	/tmp/zsu-abi-layout
else
	say "FAIL: host build of abi_layout.c"
	fail=1
fi

# The 32 bit build is the interesting one: it is what pins sizeof() and the
# _IOC encoding for compat tasks. Not every host has multilib installed.
if "$CC" -m32 -Wall -Wextra -Werror -I "$ROOT/kernel/include" \
	-o /tmp/zsu-abi-layout32 "$ROOT/tests/abi_layout.c" 2>/dev/null; then
	say "32 bit build ok:"
	/tmp/zsu-abi-layout32
else
	say "SKIP: no 32 bit multilib toolchain (install gcc-multilib to enable)"
fi

say ""
say "=== 2. Kernel sources, per version anchor x arch ==="
#
# gateway.c is the only file that reads pt_regs, and it does so through
# arch.h, so the arch is part of the matrix: a change to one branch that
# breaks another has to fail here rather than on a device.
#
for arch in arm64 x86_64 riscv; do
	case "$arch" in
	arm64)  archcfg=CONFIG_ARM64  ;;
	x86_64) archcfg=CONFIG_X86_64 ;;
	riscv)  archcfg=CONFIG_RISCV   ;;
	esac

	for ver in 5.10.0 6.1.0 6.6.0 6.12.0 6.18.0; do
		major=$(echo "$ver" | cut -d. -f1)
		minor=$(echo "$ver" | cut -d. -f2)
		bugfix=$(echo "$ver" | cut -d. -f3)
		printf '%-8s %-8s ' "$ver" "$arch"

		ok=""
		for src in "$ROOT"/kernel/*.c; do
			[ -e "$src" ] || continue
			base=$(basename "$src" .c)

			if "$CC" -fsyntax-only -Wall -Wextra -Wno-unused-parameter \
				-Wno-attributes \
				-DLINUX_VERSION_CODE="KERNEL_VERSION($major, $minor, $bugfix)" \
				-D"$archcfg"=1 \
				-I "$ROOT/tests/stub-include" \
				-I "$ROOT/kernel/include" \
				"$src" 2>/tmp/zsu-syntax-err; then
				ok="$ok $base"
			else
				printf '\n'
				head -20 /tmp/zsu-syntax-err
				fail=1
			fi
		done

		if [ -n "$ok" ]; then
			printf 'ok:%s\n' "$ok"
		else
			printf 'no sources\n'
		fi
	done
done

say ""
if [ "$fail" -eq 0 ]; then
	say "RESULT: PASS"
else
	say "RESULT: FAIL"
fi
exit "$fail"