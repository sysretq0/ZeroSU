# ZeroSU

**An architectural proof of concept and reference implementation: panic-free,
zero-hotpath kernel elevation across Android GKI 5.10 → 6.18.**

This repository exists to demonstrate and document one specific claim: that a
credential-elevation module can be built for a 3.5-year, six-branch kernel
range **without a single hotpath hook, without a single `#ifdef` in a `.c`
file, and without a single unverified assumption about a kernel ABI** — and
that you can prove which parts are actually verified rather than assert it.

**The core deliverable is `kernel/`.** Alongside it is a single-threaded
reference `userspace/` tree — the daemon (`zerosud`), the `/system/bin/su`
stub, and the `zsu_ctl` CLI — that exercises the ABI end to end. A manager UI,
key-management UX and OTA flow remain **out of scope** — see [Scope](#scope).
`tests/` exists to *prove* the design compiles and lays out correctly, not to
ship a product.

---

## The problems this addresses

Existing Android root frameworks solve a different problem and pay for it in
ways that show up as panics, silent corruption, or unverifiable claims:

| Problem | Approach here |
|---|---|
| VFS/LSM hooks on hot paths (`execve`, `faccessat`, `stat`, `avc_has_perm`, …) | **One** kprobe, on the `reboot(2)` syscall entry wrapper, and it returns 0 without ever blocking. Everything else happens in `TWA_RESUME` task work on the way back to userspace. |
| Authorization driven by a caller-supplied struct | The permission mask is derived **only** from kernel state. `zerosu_cmd.flags` is reserved and must arrive as zero; `tests/syntax-check.sh` fails the build if anything reads it for anything else. |
| "We added a domain to the policy" | The `zsu` type is grown into the **live** `policydb` correctly: all three indexed arrays reallocated with the right allocator, self-bit set at the right index, role authorisation added, `nprim` bumped last as the commit point, and the replaced arrays retired only after a grace period. |
| Depending on `<objsec.h>` | Zero. The SELinux internals are mirrored locally with `static_assert` on every size and offset, and every version difference is isolated in `compat.h`. |
| `user_struct` / `ucounts` refcount bugs | The uid swap goes through the kernel's own `alloc_uid()`/`free_uid()` pair, `set_cred_ucounts()` is re-run after the uid change and before the cred is visible, and supplementary groups are sorted (because `in_group_p()` binary searches them) with a balanced `put_group_info()`. |
| Unload-time use-after-free | A `task_work` that is already queued survives `unregister_kprobe()`. An `inflight_tw` counter, incremented *before* `task_work_add()` and decremented as the last statement of the callback, is what makes module teardown safe. |
| "It compiles on my kernel" | A 15-cell matrix (5 version anchors × 3 architectures) of `-Wall -Wextra` checks, plus a host-compiled `_Static_assert` ABI test. And an explicit list of what is *not* verified. |

## Authorization model

The gateway is deliberately reachable by unprivileged processes: the kprobe
runs **before** `sys_reboot`'s `ns_capable(CAP_SYS_BOOT)` check, so any process
can obtain an anonymous `[zerosu]` fd. That is intentional — the kernel
capability check governs *rebooting the machine*, not handing out a session
handle, and a handle alone grants nothing.

Authorization is therefore entirely kernel-side, and there is exactly one path
to privilege:

```
  unprivileged process
      │  reboot(MAGIC1, MAGIC2, mode, &fd)      → anonymous session fd
      │
      ├─ AUTH_SET_KEY   requires !key_enrolled && uid == 0
      │                 (one-time bootstrap of the device master key)
      │
      ├─ AUTH_VERIFY    sends a digest; constant-time compare against the
      │                 module-global key_digest
      │                 → on success only: ctx->authenticated = true
      │
      └─ ELEVATE        requires ctx->authenticated  (ZSU_PERM_KEY)
```

Two properties are load-bearing:

- **The mask is never caller-supplied.** `zerosu_session_perm()` computes it
  from `key_enrolled`, `current_uid()` and the session's `authenticated` bit.
  Reading a permission bit out of `struct zerosu_cmd` would be equivalent to a
  server honouring a client-supplied `X-Is-Admin: true` header.
- **`AUTH_VERIFY` refuses before it compares.** With no key enrolled,
  `key_digest` is 32 zero bytes, so an attacker-supplied block of 32 zeros
  would otherwise match it and authenticate.

`key_digest` is module-global **on purpose**: that is the SuperKey model — one
device-wide master key enrolled once by the privileged loader, against which
every later session authenticates. Scoping it per-session would be
self-defeating, since a fresh session could then enrol its own key and
elevate itself.

---

## Scope

**In scope:** the kernel module (`kernel/`), the UAPI contract, the offline
verification harness (`tests/`), a single-threaded reference userspace tree
(`userspace/`), and the research notes below.

**Out of scope, on purpose:** a manager UI, OTA/update flow, multi-session UX,
and non-Android targets. None of that is novel research — it is C plumbing.
`userspace/` is deliberately the smallest tree that can drive the ABI on a
real device (one daemon, one `su` stub, one CLI) and it is a reference, not a
product. A ~100-line `tests/smoke_test.c` also exists, purely to show how
userspace talks to the ABI and to prove the UAPI header is usable from an
ordinary host program.

**Not tested on hardware.** Nothing here has been loaded on a device. See
[Verification](#verification) for exactly what that means.

---

## Architecture

```
userspace  ──reboot(MAGIC1, MAGIC2, mode, &fd)──►  gateway.c
                                                        │
                                            kprobe on __<arch>_sys_reboot
                                                        │  validate, kmalloc(GFP_ATOMIC)
                                                        ▼
                                                   task_work_add (TWA_RESUME)
                                                        │
                                                        ▼
                                            install_work(): anon_inode_getfile,
                                            copy_to_user(&fd), fd_install
                                                        │
                                          ioctl() on [zerosu] / [zerosu_su]
                                                        │
                                                        ▼
                                    supercall.c ──► elevate.c ──► seccomp.c
                                         │                │
                                         │                └── SELinux domain via
                                         │                    selinux.c + sepolicy.c
                                         └── sha256, constant-time compare
```

| File | Role |
|---|---|
| `main.c` | Init/exit ordering and nothing else. A dependency chain, not a preference. |
| `symbols.c` | The resolver engine only. Bootstraps `kallsyms_lookup_name` by registering a kprobe *by symbol name* — no scanning. Each subsystem owns its own symbol table. |
| `sepolicy.c` | Grows the `zsu` type into the live `policydb`. |
| `selinux.c` | Locates the cred blob (`lbs_cred`), resolves the domain SID, stamps a not-yet-committed cred. |
| `supercall.c` | The ioctl surface: auth, payload validation, event ring. |
| `elevate.c` | Builds and installs the elevated cred. |
| `seccomp.c` | Detaches a seccomp filter by handing it to a throwaway `task_struct`. |
| `gateway.c` | The only kernel hook. |
| `include/compat.h` | Every version and KMI difference. The only file allowed to be ugly about that. |
| `include/arch.h` | The only architecture-aware file. |

---

## Research notes: what the kernel actually does

Every row below was read out of the Android GKI trees
(`sysretq0/android-kernel-common`, branches `android12-5.10-lts` …
`android17-6.18-lts`), not assumed. **Each one contradicts something that is
widely written down or that I got wrong first.** This table is the most
valuable artifact in the repository.

### Assumptions that are false

| Assumption | Reality | Evidence |
|---|---|---|
| `reboot(cmd, magic1, magic2, &fd)` | The kernel sees `SYSCALL_DEFINE4(reboot, int magic1, int magic2, unsigned int cmd, void __user *arg)` — **magics first**. libc's `reboot(int cmd, …)` reorders them. | `kernel/reboot.c`, identical on 5.10 & 6.18 |
| Argument stomping is needed to stop the real reboot | Not needed at all. `magic1 != LINUX_REBOOT_MAGIC1` (`0xfee1dead`) → `-EINVAL` before `switch (cmd)`. The stomp was deleted as dead weight. | `kernel/reboot.c:325` |
| `permissive_map` is indexed by `type - 1` | It is indexed by the **raw type value**. Getting this wrong marks the *neighbouring* type permissive — a security bug, not a crash. | `services.c:1147` (both branches) |
| `role_datum->types` is indexed by `type` | It is indexed by `type - 1`. | `policydb.c:969` |
| `ebitmap_set_bit(e, unsigned long bit, int)` | `u32 bit` from 6.x onward. A 64-bit argument width on a 32-bit parameter is a real ABI mismatch. | `ss/ebitmap.h:130` |
| `prepare_creds(const struct cred *old)` | `prepare_creds(void)` — **no arguments**. | `cred.c:253` (5.10), `:206` (6.18) |
| `set_cred_ucounts()` returns `void` | Returns **`int`**. | `cred.c:533` |
| `commit_creds()` rebinds ucounts | It does not. The `set_cred_ucounts()` call in `cred.c` belongs to `prepare_kernel_cred()`. It must be done by the caller before commit. | `cred.c:320` vs `:1116` |
| `alloc_uid(struct user_namespace *)` | `alloc_uid(kuid_t uid)`, in `kernel/user.c`, and it is **not exported**. Passing a namespace pointer reinterprets it as a `kuid_t`. | `kernel/user.c:177` / `:211` |
| `free_uid()` needs resolving | It is `EXPORT_SYMBOL_GPL` and declared in `<linux/sched/user.h>` — called directly. | `kernel/user.c:175` / `:209` |
| `set_user()` syncs uid into `user_struct` | Removed in 2.6.29. Zero hits in `user.c` and `cred.c`. | — |
| `clear_task_syscall_work()` is a `kernel/fork.c` function | It is a **macro** in `<linux/thread_info.h>`, so kallsyms can never find it; resolving it always returned NULL and the bit was never cleared. It does not exist at all on 5.10. | `thread_info.h:168` |
| `selinux_state.ss->policy_rwlock` before 6.4 | No branch in 5.10–6.18 has `ss` at all. All six use `selinux_state.policy` (RCU) + `policy_mutex`. | `include/security.h`, all six |
| `avc_ss_reset(0)` | 2-arg `(avc, seqno)` through 6.1, 1-arg `(seqno)` from 6.6. | `include/avc_ss.h` |
| `security_secctx_to_secid()` | Does not exist. It is `security_context_str_to_sid()`, which itself changes arity: `(state, scontext, out, gfp)` ≤6.1, `(scontext, out, gfp)` ≥6.6. | `include/security.h` |
| `cred->security` blob is `struct task_security_struct` | Renamed to `struct cred_security_struct` in 6.18, where `task_security_struct` was recycled for the AVC dir cache. Both are `__randomize_layout`. | `include/objsec.h` |
| `PF_EXITING` needs a 6.11 split | It is in `task_struct->flags` on 5.10 *and* 6.18 (`signal_struct` was removed in 5.8). Same value, `0x4`. No split needed. | `include/sched.h:1577` / `:1794` |
| `struct seccomp` is stable | 5.10 has an extra `filter_count` between `mode` and `filter`. It is a public header, so there is nothing to mirror. | `include/seccomp.h` |
| `cap_bset` is refcounted | It is a plain `kernel_cap_t` embedded by value in `struct cred`. Writing it is an assignment. | `cred.h:132` / `:125` |

### Bugs that were in this code, and are now regression-tested

Kept here because a reference implementation that hides its own mistakes is
worth less than one that names them.

| Bug | Impact | Guard |
|---|---|---|
| `zerosu_check_perm()` took the caller's `hdr.flags` as the permission mask | **Complete authentication bypass.** Any process with a session fd set `ZSU_PERM_KEY` and called `ELEVATE` directly, skipping `AUTH_VERIFY`. | `syntax-check.sh` check 3: any use of `hdr.flags` other than the zero-rejection fails the build |
| `AUTH_VERIFY` compared before checking enrollment | With no key enrolled, 32 zero bytes from userspace matched the zeroed `key_digest` | Ordering is now enforced and commented at the call site |
| `AUTH_SET_KEY` gated on `hdr.flags & ZSU_PERM_ENROLL` | Any process could enrol the device master key | Gate is now `!key_enrolled && uid == 0` |
| `kallsyms` resolve of `clear_task_syscall_work()` | Always NULL — it is a macro, so the `SYSCALL_WORK_SECCOMP` bit was never cleared | Now a direct macro call |
| `u32` used in the UAPI header | Compiled in the kernel, **unusable** from userspace | `tests/smoke_test.c` builds against the real header |

### Structural facts the design leans on

- **Three different indexing conventions for three type bitmaps**, in one
  structure: `type_attr_map_array[v-1]` (self bit at `v-1`), `role->types`
  (bit `v-1`), `permissive_map` (bit `v`). They are not interchangeable.
- **`symtab_insert()` does not touch `nprim`.** The loader increments it, and
  so must we: `policydb_type_isvalid()` is `type <= p->p_types.nprim`. That
  makes the `nprim` write the commit point of the whole type insertion.
- **`sym_name()` has no bounds check at all** — it is
  `return p->sym_val_to_name[sym_num][element_nr];` — and
  `context_struct_to_string()` `strlen()`s the result on every
  `/proc/self/attr/current` read. So `sym_val_to_name[SYM_TYPES]` must be
  grown too, or the first `id -Z` reads off the end of the slab.
- **Both indexed arrays come from `kvcalloc()`** and are released by
  `policydb_destroy()` through `kvfree()`. `krealloc()` is wrong twice over: it
  rejects vmalloc'ed memory outright, and the release path is `kvfree()`.
- **Concurrent readers walk those arrays under `rcu_read_lock()` with no
  `policy_mutex`**, so a replaced array may only be freed after a grace
  period — which is why retirement happens *after* the unlock rather than
  inside it.
- **`commit_creds()` only ever acts on `current`.** Its body is
  `rcu_assign_pointer(task->real_cred); rcu_assign_pointer(task->cred);`
  under `task_lock()`. For a remote task we reproduce exactly that sequence
  and never call it.
- **`selinux_state.policy`'s offset is not constant**: it moves with
  `policycap[]`, which is 8 / 8 / 9 / 14 across 5.10 / 6.6 / 6.12 / 6.18 and is
  config-dependent besides. Hence a bounded ±32-byte probe validated against
  the policydb's own invariants, caching the *slot address* (not the value, so
  a `selinuxfs` policy reload cannot leave it stale).

### Deliberate omissions, and why

- **No `avc_ss_reset()`.** The AVC is keyed by SID and `zsu_sid` is brand new,
  so no stale decision can exist for it. Skipping the flush also removes the
  6.1/6.6 arity split and the need to reach `selinux_state.avc` at all.
- **No constant-time compare from the kernel.** The kernel's helper is a
  `static inline` over `__crypto_memneq`, which is unexported; calling it
  through an `int (*)` would trip the kCFI return-type hash on 6.1+. Since we
  only ever compare two 32-byte SHA-256 digests, there is a 4×`u64`
  branchless XOR accumulator with `OPTIMIZER_HIDE_VAR` instead. Zero
  dependencies, and no path where `AUTH_VERIFY` can degrade to `memcmp()`.
- **No `SHASH_DESC_ON_STACK`.** It expands to a VLA, and GKI builds with
  `-Werror=vla`. The descriptor is preallocated as
  `sizeof(shash_desc) + crypto_shash_descsize(tfm)`.
- **No `MODULE_IMPORT_NS()`.** On 6.18 `prepare_creds()` sits in a mangled
  `ANDROID_GKI_VFS_internal_…` namespace *and* `CONFIG_TRIM_UNUSED_KSYMS=y` is
  on. The cred entry points are resolved by name, which sidesteps both.

---

## Verification

```
sh tests/syntax-check.sh
```

Three independent checks, none needing a kernel tree:

1. **UAPI ABI** — `tests/abi_layout.c` compiles with `-Werror` against the real
   header and asserts every struct size and field offset, then prints them.
   `struct zerosu_cmd` is asserted to be exactly 24 bytes, which is what makes
   the ioctl encoding (`0xc0185a00` for `PING`) identical for 32-bit compat
   tasks and lets `compat_ioctl` be a verbatim copy. A 32-bit build is
   attempted when multilib is available and skipped otherwise.
2. **Kernel sources** — every `.c` compiled `-fsyntax-only -Wall -Wextra`
   against hand-written stub headers, across **5 version anchors × 3
   architectures = 15 cells**, with `CONFIG_ARM64`/`CONFIG_X86_64`/`CONFIG_RISCV`
   driving `arch.h` so a change to one arch's branch cannot silently break
   another.
3. **Authorization regression guard** — greps for the historical bypass: any
   use of `hdr.flags` other than rejecting a non-zero value, a missing
   `ctx->authenticated` gate, or enrollment not restricted to uid 0 fails the
   run. It exists because the compiler *cannot* catch this class of bug — the
   flawed version was perfectly well-typed. Both faults were confirmed to fail
   the check by deliberate injection.

The stub harness earned its keep: it caught a wrong `set_cred_ucounts` return
type, a `cap_raise()` called by value instead of by pointer, a `cap_bset`
modelled as a pointer, a const-violating `put_cred()`, a dangling `goto` label,
and `u32` leaking into the UAPI header (which compiles fine in the kernel and
is *unusable* from userspace).

### What is NOT verified

Being explicit about this is the point:

- **Nothing has been run on hardware.** No `insmod`, no ioctl, no reboot.
- `make -C $KDIR M=… modules` has never been executed — there is no configured
  kernel tree in this environment. The build files are written but untested.
- The mirrored `policydb` layout assumes `CONFIG_RANDSTRUCT` is off. It is,
  on every GKI `arm64/gki_defconfig` checked — and `compat.h` fails the build
  if it ever is not, because `__randomize_layout` is on `struct policydb`,
  `struct selinux_policy` *and* `struct selinux_state`.
- The `selinux_state.policy` probe is a heuristic validated against the
  policydb's own invariants and a `symtab_search("kernel")`. It is designed to
  refuse a kernel it does not recognise, not to guess.
- `alloc_uid()` is resolved, not called, because it is not exported. Its
  signature is verified; the *resolution* is untested at runtime.
- **`userspace/` compiles, but has never been run.** No daemon, no stub, no
  `su` transition has executed on a device. It links no library beyond libc
  and the kernel ABI it uses is the committed one, but "compiles" is the
  strongest claim available here.
- **The doorbell depends on OverlayFS and inotify behaviour that is not
  hardware-tested.** The stub in `upper/su` rings by `open()`ing its own
  overlaid `/system/bin/su`. Stock SELinux permits that open — the stub is
  labelled `system_linker_exec`, which is a `system_file_type`, and `domain.te`
  grants `{ appdomain coredomain }` `r_file_perms` (`open`, which
  `do_open_execat()` needs for `execve()` anyway). The subtlety is in the
  kernel: opening a file *through* an overlay notifies the overlay inode, not
  the upper inode (on 5.10/6.1 `ovl_open_realfile()` → `open_with_fake_path()`
  keeps the overlay dentry; on 6.18 `backing_file_open()` sets
  `FMODE_NONOTIFY`), so a bare watch on `upper/su` never fires. `ns_inject()`
  therefore bind-mounts the real `upper/su` over `/system/bin/su` inside the
  app's mount namespace, so the app's open reaches the inode the daemon
  watches. This is reasoned from the kernel sources, not observed on hardware.

---

## Building

```sh
# checks, no kernel tree needed
sh tests/syntax-check.sh

# the module, against a configured tree
make -C /path/to/kernel M=$PWD/kernel modules

# or from inside kernel/
make KDIR=/path/to/kernel
make KDIR=/path/to/kernel check      # same as syntax-check.sh
```

There is deliberately no fallback that guesses a kernel tree: a module built
against the wrong headers is worse than no build at all.

### Talking to it from userspace

```sh
cc -Wall -Wextra -Werror -I kernel/include -o /tmp/zsu-smoke tests/smoke_test.c
sudo /tmp/zsu-smoke        # plain session, PING
sudo /tmp/zsu-smoke su key # enroll, verify, elevate, drain events
```

Note the raw `syscall(__NR_reboot, …)`, not libc's `reboot()` — see the first
row of the corrections table.

### Reference userspace (`userspace/`)

Three binaries, no shared library, no build system beyond a Makefile:

| File | Role |
|---|---|
| `userspace/daemon/` | `zerosud`: a strictly single-threaded epoll daemon (no threads, no `fork`, no `/proc` scans). ctl socket, `packages.list` cache, logdr spawn monitor, per-uid inotify doorbells, inline mount-namespace overlay + bind injection, and the only code that speaks the ioctl ABI. |
| `userspace/su/zsu_stub.c` | the template `/system/bin/su`: parks two anonymous pipes on fixed descriptors, rings the daemon by opening its own binary, waits for the one-byte ack, then execs `/system/bin/sh`. |
| `userspace/ctl/zsu_ctl.c` | the orchestrator: `patch`, `allow`, `revoke`, `list`, `status`, `ping`, `shell`. `patch` stamps the SuperKey into the daemon's ELF slot and prints it once. |

```sh
cd userspace && make      # builds zerosud, zsu_stub, zsu_ctl (-Wall -Wextra -Werror)
cd userspace && make check # same kernel-side checks as tests/syntax-check.sh
```

There is no key file anywhere: `zsu_ctl patch <zerosud> [hex_key]` finds the
one unpatched `ZSUKEY00` slot in the daemon's image, writes 64 key bytes, and
prints them exactly once; the daemon `explicit_bzero()`s the slot after it has
authenticated the kernel session.

---

## Design rules this codebase holds itself to

1. **No hotpath hooks.** One kprobe, on a syscall entry wrapper, returning 0.
2. **Never block or sleep in the kprobe.** Validate, `GFP_ATOMIC`, queue
   `TWA_RESUME`, return.
3. **Never `return 1` from a kprobe.** Everything interesting happens in task
   work, where allocation and copying are legal.
4. **Zero `#ifdef` in `.c` files.** Version and KMI differences live in
   `compat.h` and `arch.h`, or nowhere.
5. **No unverified symbol assumption.** If it cannot be verified, it is
   resolved by name and fails closed, or it is not used. There is no third
   option.
6. **Fail closed.** Every unresolved required symbol, implausible policydb, or
   out-of-range blob offset is a module load failure, not a warning.
7. **Counters before commit.** Anything that must be visible before a
   concurrent reader can observe it is incremented first
   (`inflight_tw`), and retired only after the reader can be proven gone.