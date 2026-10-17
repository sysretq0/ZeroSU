#!/bin/sh
# ZeroSU - tests/syntax-check.sh
#
# Six independent checks, none of which needs a kernel tree:
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
#   3. Authorization - source-level guards for the kernel permission model
#                      (hdr.flags is untrusted; enrollment is uid 0 only).
#
#   4. Userspace     - compiles every userspace/*.c with -fsyntax-only under
#                      the same flags userspace/Makefile uses (-std=gnu11
#                      -Wall -Wextra -Werror). It needs no Android libraries:
#                      the daemon, stub and ctl are raw syscalls and libc.
#
#   5. EventLog      - runs the proc_monitor decoder against hand-built AOSP
#                      payloads.
#
#   6. ctl auth      - asserts the ctl socket's mutating ops require the
#                      SuperKey and the read-only ops do not.
#
#   7. key slot      - links the daemon and asserts the ZSUKEY00 magic appears
#                      exactly once, the invariant zsu_ctl patch depends on.
#
# Note that (2) is a syntax/type check, not a build: it cannot catch a kernel
# ABI mismatch. That is what zsu_selinux_layout_sane() and the
# zsu_selinux_discover() probe are for at runtime.
set -eu

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CC=${CC:-cc}
fail=0

# Per-invocation scratch directory. This check runs from `make check`, from CI
# and by hand, and those can overlap; fixed /tmp paths would let one run clobber
# another's test binaries and captured compiler stderr. mktemp -d gives each run
# its own, and the trap removes it on any exit path (including set -e aborts).
TMP=$(mktemp -d "${TMPDIR:-/tmp}/zsu-check.XXXXXX")
trap 'rm -rf "$TMP"' EXIT

say() { printf '%s\n' "$*"; }

say "=== 1. UAPI ABI layout ==="
if "$CC" -Wall -Wextra -Werror -I "$ROOT/kernel/include" \
	-o "$TMP/zsu-abi-layout" "$ROOT/tests/abi_layout.c"; then
	"$TMP/zsu-abi-layout"
else
	say "FAIL: host build of abi_layout.c"
	fail=1
fi

# The 32 bit build is the interesting one: it is what pins sizeof() and the
# _IOC encoding for compat tasks. Not every host has multilib installed.
if "$CC" -m32 -Wall -Wextra -Werror -I "$ROOT/kernel/include" \
	-o "$TMP/zsu-abi-layout32" "$ROOT/tests/abi_layout.c" 2>/dev/null; then
	say "32 bit build ok:"
	"$TMP/zsu-abi-layout32"
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
				"$src" 2>"$TMP/zsu-syntax-err"; then
				ok="$ok $base"
			else
				printf '\n'
				head -20 "$TMP/zsu-syntax-err"
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
say "=== 3. Authorization regression guard ==="
#
# Historical bug: zerosu_check_perm() took the caller's hdr.flags as its
# permission mask, so any process holding a session fd could set ZSU_PERM_KEY
# and skip AUTH_VERIFY entirely. The compiler cannot catch that - it is a
# perfectly well-typed program - so it is checked here.
#
# The rule: struct zerosu_cmd is untrusted input. The only legitimate use of
# hdr.flags is rejecting a non-zero value outright.
fail_perm=0

bad=$(grep -n 'hdr\.flags' "$ROOT"/kernel/*.c \
	| grep -v 'hdr\.flags != 0' \
	| grep -vE ':[0-9]+:[[:space:]]*(\*|/\*|//)' || true)
if [ -n "$bad" ]; then
	printf 'FAIL: hdr.flags used for anything but rejection:\n%s\n' "$bad"
	fail_perm=1
fi

if ! grep -q 'ctx->authenticated' "$ROOT"/kernel/supercall.c; then
	printf 'FAIL: no ctx->authenticated gate in supercall.c\n'
	fail_perm=1
fi

if ! grep -q 'GLOBAL_ROOT_UID' "$ROOT"/kernel/supercall.c; then
	printf 'FAIL: enrollment is not restricted to uid 0\n'
	fail_perm=1
fi

if [ "$fail_perm" -eq 0 ]; then
	printf 'ok: hdr.flags rejected, permissions kernel-derived\n'
else
	fail=1
fi

say ""
say "=== 4. Userspace sources ==="
#
# Same flags as userspace/Makefile. Kept here (rather than shelling into
# `make -C userspace check`, which itself runs this script) so the check has
# no recursion and runs everywhere a host cc exists.
for src in \
	"$ROOT"/userspace/daemon/*.c \
	"$ROOT"/userspace/su/*.c \
	"$ROOT"/userspace/ctl/*.c; do
	[ -e "$src" ] || continue
	rel=${src#"$ROOT"/}
	printf '  %-28s ' "$rel"
	if "$CC" -fsyntax-only -std=gnu11 -Wall -Wextra -Werror -D_GNU_SOURCE \
		-I "$ROOT/userspace/include" \
		-I "$ROOT/kernel/include" \
		-I "$ROOT/userspace/daemon" \
		"$src" 2>"$TMP/zsu-user-err"; then
		printf 'ok\n'
	else
		printf 'FAIL\n'
		head -20 "$TMP/zsu-user-err"
		fail=1
	fi
done

say ""
say "=== 5. EventLog decoder regression ==="
#
# proc_monitor.c decodes Android's binary event log. The format is easy to get
# subtly wrong (list header, per-element type bytes, length-prefixed strings),
# so the decoder is exercised against hand-built AOSP-encoded payloads rather
# than trusted to compile.
if "$CC" -O0 -std=gnu11 -Wall -Wextra -Werror -D_GNU_SOURCE \
	-I "$ROOT/userspace/include" \
	-I "$ROOT/kernel/include" \
	-I "$ROOT/userspace/daemon" \
	-o "$TMP/zsu-evtags" "$ROOT/tests/evtags_decode_test.c" \
	&& "$TMP/zsu-evtags"; then
	:
else
	say "FAIL: EventLog decoder regression"
	fail=1
fi

say ""
say "=== 6. ctl socket authorization guard ==="
#
# DAC membership in the shell group must never stand in for the SuperKey.
# ALLOW writes a persistent grant and REVOKE kills a cgroup, so both are at
# least as sensitive as SHELL and must call superkey_ok(); the read-only ops
# must not. The compiler cannot see that a switch arm is missing a check, so
# the invariant is asserted on the source.
if awk '
function flush() {
	if (op != "") {
		need = (op == "ZSU_CTL_ALLOW" || op == "ZSU_CTL_REVOKE" ||
			op == "ZSU_CTL_SHELL")
		has = (body ~ /superkey_ok\(/)
		if (need && !has)  { print "  FAIL: " op " has no superkey_ok()"; bad = 1 }
		if (!need && has)  { print "  FAIL: " op " requires the key"; bad = 1 }
	}
	op = ""; body = ""
}
/^[[:space:]]*case ZSU_CTL_[A-Z_]*:/ {
	flush()
	op = $2; sub(/:$/, "", op)
	next
}
/^[[:space:]]*default:/ { flush(); next }
{ if (op != "") body = body $0 "\n" }
END { flush(); exit bad }
' "$ROOT/userspace/daemon/broker.c"; then
	say "ok: ALLOW/REVOKE/SHELL keyed, reads open"
else
	fail=1
fi

say ""
say "=== 7. key slot uniqueness ==="
#
# zsu_ctl patch refuses a binary that contains the ZSUKEY00 magic more than
# once. Referencing ZSU_PATCH_MAGIC as a string literal in the daemon emits a
# second copy into .rodata, which silently made every release binary
# unpatchable (caught only by running patch on a real device). Assert the
# linked binary carries exactly one slot.
if "$CC" -O2 -std=gnu11 -Wall -Wextra -Werror -D_GNU_SOURCE \
	-I "$ROOT/userspace/include" \
	-I "$ROOT/kernel/include" \
	-I "$ROOT/userspace/daemon" \
	-o "$TMP/zerosud" "$ROOT"/userspace/daemon/*.c 2>"$TMP/zsu-link-err"; then
	n=$(grep -ao "ZSUKEY00" "$TMP/zerosud" | wc -l)
	if [ "$n" -eq 1 ]; then
		say "ok: exactly one key slot"
	else
		say "FAIL: $n ZSUKEY00 occurrences (patch requires exactly 1)"
		fail=1
	fi
else
	say "FAIL: daemon link"
	head -20 "$TMP/zsu-link-err"
	fail=1
fi

say ""
if [ "$fail" -eq 0 ]; then
	say "RESULT: PASS"
else
	say "RESULT: FAIL"
fi
exit "$fail"