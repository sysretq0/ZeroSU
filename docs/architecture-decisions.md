# ZeroSU — architecture decision record

State as of commit `1220204` (main), before any manager UI exists.
Written to be self-contained: a reader (human or another model) needs no
prior context about the repository. Where a claim is verified against
kernel source it says so; where something is a known tradeoff or an open
question it is marked **[risk]** or **[open]**.

The companion artifact to this file is the README's "assumptions that
are false" research table: this record explains what was *decided*; that
table explains what the kernel trees *forced*.

---

## L0 — Mission and constraints

### D1. Target: unmodified Android GKI, loadable module only
- **Decision.** ZeroSU ships as a single `.ko` per KMI, built against
  `android12-5.10` … `android17-6.18` (`-lts`/`-stable` branches of
  `sysretq0/android-kernel-common`). No kernel source fork, no vendor
  defconfig changes, no built-in ISoC driver tricks, no boot image
  re-signing. Installation = `insmod` at boot from an install-time
  boot script.
- **Alternative rejected.** Kernel patching (APatch/KernelPatch style)
  and direct LRU-embedding. Both would give stronger guarantees but
  violate "no kernel image modification" and die on the GKI matrix:
  a `-lts` bump silently changes every offset.
- **Consequence.** Every privileged primitive must exist as *resolvable
  certain black* non-exported symbols; every layout the module touches
  must be mirrored and re-verified per branch. The whole `compat.h`
  mirror regime (L5) and the resolver engine (L2) exist because of this
  single decision.

### D2. Privilege model: install-time root exists; runtime peers do not
- **Decision.** The **only** guarantee at install time is that a
  privileged installer can `insmod` the module. Everything after that —
  the daemon, the ctl CLI, an app (someday the manager) — starts
  **unprivileged** and becomes privileged only through the kernel.
- **Alternative rejected.** Daemon started as root by the boot script.
  This works (it is exactly what `magiskd` does) and would delete the
  entire auth architecture. It was rejected because the module is
  simultaneously the *elevator* for a rootless runtime, i.e. the module
  is the privilege oracle, not the convenient already-root-helper.
- **Consequence.** There must be a secret that (a) a root installer can
  provision once, (b) an unprivileged runtime peer can prove possession
  of, and (c) other unprivileged processes cannot copy. That secret is
  the device **SuperKey** (D8). Everything in L3 exists to honor D2
  without weakening it.

### D3. Stealth posture (deliberate design axis)
- **Decision.** The module and the daemon are *not* advertised
  process-wide. The one externally visible object — the `su` binary —
  exists only where it is granted: a bind mount inside a *specific
  app's mount namespace*. Other apps see a stock boot.
- **Refinement.** This is a stated design goal, not an accident of the
  implementation. It is why the architecture contains an inotify
  doorbell (an app "opens" the file that only it can see), a
  namespace-scoped overlay, and a root companion process (`zerosud`).
  Removing the daemon in favor of "apps ask the kernel directly" is
  contradictory to D3 — a kernel cannot scoped-mount on behalf of
  another task, and a globally reachable kernel hook is the opposite of
  invisible. Every shipped su provider that an informed user has seen
  (`magiskd`, `ksud`, `apd`) holds a root companion for the same reason.
- **[open]** the current handshake magic constants are public and
  therefore a *detection oracle* for any scanner that knows them. This
  is accepted today (see D6) and revisited in L6 open questions.

---

## L1 — Kernel entry: one hook (gateway.c)

### D4. kprobe on `__<arch>_sys_reboot` as the single door
- **Decision.** `gateway.c` registers one kprobe on the reboot syscall
  wrapper of each supported arch. The probe fires **before** the real
  syscall body runs (which means *before* the `CAP_SYS_BOOT` check).
  A magic pair + mode + `&fd` argument is the protocol.
- **Why reboot(2) specifically.** `SYSCALL_DEFINE4(reboot, ...)` checks
  `magic1/magic2` (0x fee1dead/1234567) before anything else, so the
  real handler's behavior is unchanged by the ride-along. The ABI is
  also stable across 5.10…6.18, and kCFI-friendly.
- **Alternatives rejected.**
  - LSM hooks (KernelSU route): much wider hook surface, per-KMI risk,
    and least stealthy — that is a profiler watching every syscall.
  - An exec-path hook to bootstrap the daemon: global `execve`
    instrumentation is exactly the fingerprint class D3 forbids.
- **Tradeoffs.**
  - The table in `gateway.c` documents that the kprobe runs before
    capability checks, so *any uid* can obtain a session fd. This is
    intentional: a handle alone grants nothing (D8).
  - **[risk]** if the magic values leak from the public header, any
    unprivileged app gains a "is this module loaded" oracle. Mitigation
    in design but not yet implemented (randomized per-device magics).

### D5. Cannot do anything in the kprobe itself: task_work deferral
- **Decision.** `reboot_pre()` runs in kprobe (atomic) context. It only
  *validates, kmalloc(GFP_ATOMIC), and queues a `task_work_add`*. All
  fd-y things — `anon_inode_getfile()`, `copy_to_user(&fd)`,
  `fd_install()` — run in `install_work()` at syscall exit, in the same
  task that called reboot.
- **Why.** The point is not convenience; *you cannot perform* those
  operations in a kprobe pre-handler. Deferral is forced. The
  `task_work_add` callback is a resolved-pointer call, so it carries the
  `__nocfi` attribute (D15).
- **Trade-off.** Queue-back reference counting is non-obvious; the
  `inflight_tw` counter is incremented *before* `task_work_add()`
  returns and decremented as the very last action of the callback, so
  `rmmod` can wait safely (D7).

### D6. Unload safety: inflight counter is the gate
- **Decision.** `zerosu_rmmod` unregisters the kprobe and then waits on
  `wait_event(zsu_tw_wait, atomic_read(&inflight_tw) == 0)` before
  mapping out. The counter, not `synchronize_rcu()`, is the
  synchronization primitive; a queued-but-pending task_work is invisible
  to both the kprobe-unregister rcu read of the module's own text.
- **Alternative rejected.** `synchronize_rcu()` alone (only proves no
  CPU currently *inside* reboot_pre, not that nothing's pending), a
  module refcount (anonymous inodes are not module-owned file objects
  in a clean way), and delaying fd install.
- **[open]** a *live session* (`[zerosu]` fd already handed to
  userspace, ioctl in flight on another CPU) at `rmmod` time is not
  fully closed — the session object outlives the module text if the
  fd keeps it open (releases the anon inode) while `rmmod` proceeds is
  not fully closed. Known gap on the audit list.

### D7. Session object: anonymous inode with private fops
- **Decision.** The userspace-visible handle is an `[zerosu]` /
  `[zerosu_su]` anon_inode whose `file_operations` are module-private
  (`gateway.c:zerosu_session_fops`). `ZSU_MAX_SESSIONS` caps concurrent
  sessions (currently 8).
- **Why anon_inode.** avoids `/dev` node (needs a registered char device
  + udev-ish plumbing + it would be a global, scannable object — D3),
  avoids `misc device`, and lets the fops live in module space only as
  long as the module is loaded.
- **Alternative rejected.** A `/dev/zsu` char device or a
  `/proc`-backed file. Both are *globally* visible objects and would
  break D3; anon inodes have no pathname and only exist in the holder's
  fdtable.
- **Note on the ioctl surface.** the "sessions are a type-
  request, not policy" comment is explicit in supercall.c: `type` is
  the caller's claim. Security is never keyed off it (D9).

---

## L2 — Symbol resolution (symbols.c)

### D8. kallsyms bootstrap via a name-registered kprobe — no scanning
- **Decision.** `kallsyms_lookup_name` stopped being exported (6.7+), so
  the module cannot call it before it has it. The bootstrap registers a
  kprobe *by symbol name*; the kprobe core resolves the name internally
  (GKI defconfigs ship `CONFIG_KALLSYMS_ALL=y`) and returns the address
  in `kp.addr`. That address becomes the resolver primitive for all
  other lookups.
- **Alternative rejected.** Scanning `.text`/kallsyms blob for the
  string prefix — fragile, arch-dependent, and the kind of thing that
  breaks on the first 6.x kernel with different section layout.
- **Consequence.** The resolver is a *typed symbol table* engine: each
  subsystem owns a table of `{name, (void**)&ptr, is-skip-if-missing}`;
  nothing is resolved that isn't unnamed in some table. Gone are the
  days of "call addresses found by grep."

### D9. Exported-symbol vs resolved-symbol split; `.cfi_jt` preference
- **Decision.**
  1. *Exported on every supported branch* → direct call (compiler and
     `Module.symvers` do the work; no lookup).
  2. *Unexported* → per-subsystem `symtab` resolve at init. Currently
     that is: SELinux internals, `alloc_uid/free_uid`,
     `set_cred_ucounts` (optional), `seccomp_filter_release`,
     `task_work_add` on some branches.
  3. On `CONFIG_CFI_CLANG` builds the lookup prefers the `nm.symname
     .cfi_jt` interpolation path, because a *checked* indirect call to
     the body address of a CFI-instrumented function is a guaranteed
     panic at next invoke; the jt thunk is the type-correct call target.
  4. On non-CFI builds (or when jt isn't present) the body address is
     used directly.
- **Why matters.** Under CFI, "we found the address" is not the same
  thing as "we are allowed to call it." The double rule (jt thunk when
  instrumented; raw body address only where instrumentation is absent),
  plus the second rule that every *module-internal* function that
  contains a resolved-pointer indirect call is marked `__nocfi`, is the
  language-level guarantee that the built module cannot panic on a
  CFI-instrumented kernel. (Verified on the emulator module for 5.10 =
  `CONFIG_CFI_CLANG=y`.)
- **Alternative rejected.** KernelSU's "patch modpost/direct-link" rely
  entirely on module-building infra hacks — it works for a
  single-KMI product but is not a KMI-portable practice and defeats
  modpost's ability to catch symbol mis-declarations at build time.

### D10. Resolver caching / failure digging
- One resolver call per boot; the returned addresses are stored in
  module-static pointers. A subsystem's `*_init()` returning
  `-ENOSYS/-ENOENT` *refuses the module* — a half-initialized cannot
  result from a found-but-wrong symbol. This decision is what forces
  `compat.h`'s per-branch tables to be byte-accurate (L5).

---

## L3 — The SuperKey auth model (supercall.c)

### D11. One device key, digest-only, kernel-resident
- **Decision.** There is exactly one device secret at a time. At
  *install time* `zsu_ctl patch <zerosud>` generates it (getrandom,
  64 bytes), stamps it into a magic-marked slot in the `zerosud`
  binary, and prints it once. At *boot* the daemon:
  1. loads the key from its own binary slot,
  2. opens an `[zerosu_su]` session,
  3. proves possession: `AUTH_VERIFY` with SHA-256(key) over the ioctl,
  4. `explicit_bzero()`s the plaintext from RAM — **the key never
     leaves device and never lives in memory after boot**.
- **What the kernel stores.** Only SHA-256(key) — 32 bytes — in
  `.rodata`-adjacent module state. The kernel *never sees the plaintext
  key after init* except transiently at `AUTH_SET_KEY`. The key may be
  re-rotated only via explicit re-enroll after `rmmod` (or via a
  future opt-in command).
- **Why a kernel-side digest and not "the kernel just trusts the
  daemon."** the ioctl surface is an open-handle door (D7): any process
  that can obtain an fd could otherwise ask for elevation. The digest
  compare is what makes *only the SuperKey holder* able to transition
  an unprivileged process into a privileged one.
- **Constant-time compare.** `zerosu_digest_eq()` is a fixed-length,
  branch-free reduce; a wrong guess reveals nothing about how close it
  was.
- **Alternative rejected.** Storing the raw key in kernel (any oops in
  dmesg with module internals would risk key disclosure), or a
  per-session nounce/handshake protocol (more moving parts with no
  adversary model that deserves it: the secret is *already* on the same
  device).
- **[risk]** `AUTH_SET_KEY` requires `!key_enrolled && uid==0`: between
  module load and first enrollment *any root process* can set the key.
  Also **[risk]** a re-enrollment rewrites the digest: an "installer
  controls keys" adversary can also *un-key* the device.

### D12. Session permission map
- Every ioctl dispatches through `zerosu_perm_required(opcode)` vs
  `zerosu_session_perm(ctx)` (nothing vs KEY vs ENROLL), *plus*
  `zerosu_check_session_type()` (GET_PROFILE / ELEVATE / ELEVATE_TASK
  require the caller explicitly asked for a SU-type session).
- **Decision.** Specific wrappers per intent rather than a single
  generic "authorized" flag:
  - `AUTH_SET_KEY` needs `!key_enrolled && uid==0` (ENROLL);
  - `AUTH_VERIFY` succeeds *only* on digest match and only then
    transitions ctx->authenticated = true and grants `ZSU_PERM_KEY`;
  - `ELEVATE`, `ELEVATE_TASK`, `GET_PROFILE` need `ZSU_PERM_KEY` +
    SU-type session;
  - `PING`, `GET_INFO`, `GET_STATUS`, `NEXT_EVENT` are open reads.
- **Why.** The permission-bit map is small and the only *stateful
  transition* is `AUTH_VERIFY`. Keeping it explicit (wrapper per op =
  separate function = separate failure domain) is what makes "the
  elevate path can be reasoned about on one screen" true.

### D13. Event ring per session (planned manager support)
- Fixed-capacity per-session ring; `NEXT_EVENT` pops;
  drop-newest-and-count policy on overflow.
- **Why kept despite thin userspace use today.** The manager (D3) is a
  future peer that will need to be *told* about grants, elevations, and
  rejections it did not itself initiate. The ring is the arrival
  notification channel from the kernel; the daemon's own inotify and
  ctl.sock cannot carry kernel-side facts.

---

## L4 — Elevation (elevate.c, seccomp.c, selinux.c)

### D14. commit_creds for self; pointer-swap equivalent for others
- **Decision.** The `ELEVATE` op runs on `current` and corresponds to
  the textbook `commit_creds()` path. `ELEVATE_TASK`, however, targets
  a *remote* task — impossible through `commit_creds()` (which only
  operates on `current`); so the equivalent sequence is spelled out:
  both `task->real_cred` and `task->cred` are `rcu_assign_pointer()`ed
  under `task_lock()`, old references dropped afterwards — the same
  sequence `kernel/cred.c:commit_creds()` performs.
- **Why an anti-pid-recycle token.** the daemon validates `/proc/<pid>/stat`
  field 22 (start-time) against the kernel's own view before issuing
  `ELEVATE_TASK`, and the kernel re-derives the same token itself so a
  recycled pid cannot be mistaken for the granted uid.

### D15. Per-user struct accounting: `alloc_uid`
- Elevated uid's `struct user_struct` must exist *before* swapping the
  cred (the kernel assumes `cred->user` is sane); `free_uid` on the way
  out mirrors. On GKI 6.18 `set_cred_ucounts` is optional (absent) and
  the elevate path is written defensively around its presence.

### D16. seccomp detach via a throwaway task
- **Decision.** Instead of reimplementing filter release, the module
  *detaches* the task's filter and then calls the genuine
  `seccomp_filter_release()` with a throwaway `task_struct` carrying
  that filter. `PFA_NO_NEW_PRIVS` clearing is optional (`keep_no_new_privs`
  module param).
- **Why not inline-reeimplement.** the release path owns RCU graces and
  pending-work cancellation that a reimplementation can get wrong; the
  official function under a spare task is correct-by-construction.
- **[risk]** the "spare task" must carry whatever the release path
  touches; `6.6`+ shape change (`sighand` reaches release) was caught by
  branch audit and is mirrored in `compat.h`; the 5.10…6.1 shape is the
  "bare task is required" shape. Future kernels that grow more fields
  touched by `seccomp_filter_release` will need this table updated:
  every `.c` touching it is behind the compat umbrella (D19's cause).

### D17. SELinux: grow the live policydb once, via `policy_mutex`
- **Decision (sepolicy.c).** The `zsu` type is inserted into the *live*
  policy: symtab insert into `p_types`, `type_val_to_struct`,
  `sym_val_to_name`, `type_attr_map_array` all grown via `kvcalloc()`;
  role authorization added for `r`; permissive bit set if requested;
  `nprim` bump is the **commit point** (last). Replaced arrays are
  retired after `policy_mutex` release + `synchronize_rcu()` because
  callback readers walk without the mutex.
- **Discipline.** three different indexing conventions (bit `v-1` vs
  bit `v`, permissive map is 1-based) are named in the header comment —
  any of them wrong is an OOB slab read on the first AVC for
  `u:r:zsu:s0`, not a crash.
- **Refuse rather than guess.** an unmatchable expectation (wrong
  type-min, unexpected size, rollover) refuses the *load*; nothing is
  half-inserted.
- **[open — recorded in audit].** a insert vs RCU-reader transient race
  (a reader sees `nprim` bump while an array index beyond its bound is
  still being written) is not fully proven absent under adversarial
  scheduling; treated as an audit finding to close.

### D18. Cred blob domain stamp — only uncommitted creds
- **Decision (selinux.c).** never mutates a *committed* cred. It
  locates SELinux's `cred->security` (offset learned via
  `selinux_blob_sizes.lbs_cred`, not a constant: stacked LSMs move it;
  negative means no blob — refuse), resolves `u:r:zsu:s0` to a SID once
  at init, and stamps only the fresh cred elevate.c built for
  commit.
- **Why.** the domain transition is policy-driven in theory (SELinux
  transitions on `execve`), but a *synthesized* type cannot be reached
  by stock transition rules on stock policy, so the module seeds the
  SID manually on the cred it is about to commit. Rule injection (also
  provided) makes the resulting context legal to *hold*, not merely
  write.
- **Validation.** On the emulator the obtained SID for `u:r:zsu:s0` was
  2195 on 5.10 and the cred blob was at `cred->security + 0` — the
  `policy_state.policy` pointer drift was absorbed as designed.

---

## L5 — Version & arch compatibility (include/compat.h, include/arch.h)

### D19. compat.h is the only file allowed to talk about versions
- **Decision.** Every `LINUX_VERSION_CODE`-dependent fact lives in
- `compat.h` (and arch-only facts in `arch.h`). No `.c` file contains a
  version `#ifdef`. compat.h also carries *byte-by-byte mirrors* of the
  subset of SELinux internal structures the module touches
  (`policydb`, `symtab`, `hashtab`, `ebitmap`, `avtab`, `context`,
  `mls_types`), plus static asserts (compile-time tripwires on size /
  field offsets).
- **Mirrors are parametrized.** e.g. `ZSU_POLICYDB_BASE` /
  `ZSU_POLICYDB_SIZE` go parametric (6.18's `policydb` layout changed
  in the `policycap` count, so the mirror's trailing array position
  differs). The policycap count limit itself is branch-checked
  (`ZSU_POLICYCAP_MAX`: 12 at 6.18, 14 in 5.10-6.12 builds).
- **Why static asserts instead of nothing.** if a future LTS_KERNEL
  changes a mirrored layout without the assert firing, the failure mode
  becomes *wrong-layout* writes, which is an OOB slab read (not a
  compile error). The asserts convert a runtime bug into a build
  failure.
- **Related.** Because version differences leak into `.c`-adjacent
  behavior (`symbols.c`), that file uses *compiled-constant branches*
  rather than `#if`s (D22), and `elevate.c` does not carry
  `#ifdef ZSU_HAS_SET_CRED_UCOUNTS` — it uses a runtime-boolean table
  in `compat.h`.

### D20. seccomp release lock-shape is branch-checked
- `compat.h` records that from 6.6+ `seccomp_filter_release()` takes
  `tsk->sighand->siglock`; earlier it required a *bare* fake task
  (`WARN_ON(sighand != NULL)`). The fake task therefore carries a
  zeroed tail-allocated `sighand_struct` only from 6.6+ (D16).

---

## L6 — Userspace topology (userspace/)

### D21. Exactly one daemon, exactly one thread, no forked worker
- **Decision.** `zerosud` is single-threaded epoll: accept loop, ctl
  socket, inotify (packages.list + per-uid doorbells), signalfd,
  timerfd. Because there is no second thread, `CLONE_FS` (fs
  isolation) and setns-into-app-namespace operations can run without
  cross-thread namespace view corruption. This is the reason *not* to
  add threads later without re-reviewing D3/D4 and ns_inject
  (D25/D26).

### D22. Grant persistence = plain uid list file, nothing else
- `/data/adb/zerosu/grants` is a plain uid list (0755 root:root) the
  daemon replays at boot into its policy table. It is not a secret and
  never should be. Per-uid staging dirs (`upper/`, `work/`, su stub
  template) are 0700 root:root ZSU_UIDS_DIR.
- **Why file, not kernel.** the module's state dies with the module
  (D2). The daemon *is* the persistent peer, so persistence lives in
  the daemon; the kernel is the authority per-boot, the file just
  carries the answer across boots.

### D23. How an app becomes su — doorbell + kernel-side identity check
- Grant flow:
  1. `zsu_ctl allow <package>` — package → uid lookup, allowed-uid
     bitmap + grants file, staging dir creation, per-uid doorbell
     watch, run `ns_inject` for running procs.
  2. Later, the app execs `/system/bin/su`, which (via the overlay, per
     uid) is the **stub**: it parks anonymous pipes on fixed fd 3/4/5
     and *opens its own binary* — the inotify doorbell rings.
  3. The daemon resolves the uid → live pids via
     `/sys/fs/cgroup/uid_<uid>` (never /proc, to avoid ptrace-attached
     lies) + `fstat`s them, verifies `/proc/<stub-pid>/fd/3` carries
     the request magic `ZSU3`, recomputes the start-time token, and
     issues `ELEVATE_TASK` from its (already-authenticated) su session.
  4. The stub polls its ack fd; `ZSU_RDV_OK` arrives; it closes pipes
     and `execve /system/bin/sh`, now uid 0.
- **Why the kernel, not the daemon, is the elevating party.** anyone
  could pre-stage a fake pid + fake contents in /proc if the daemon did
  the swap; the kernel's ``ELEVATE_TASK`` re-derives start-time itself
  and refuses mismatches. The daemon is a planner, not the authority.
- **Security notes.** no authentication is needed from the app side at
  this layer: possessing `/system/bin/su` *is* the grant, and that
  binary is only visible in the granted app's namespace (D3). The
  SuperKey is never given to an app.

### D24. ctl.sock is shell-reachable, SuperKey-checked for mutation
- 0660 root:shell + `sockcreate u:r:shell:s0` (socket placed
  in shell domain), path labelled `shell_data_file`. Mutations
  (allow/revoke/shell/patch) prove SuperKey on top of DAC;
  status/list/ping are open reads (D12).
- **Why shell as the reach domain.** the install/ops workflow is root-
  or adb-managed (zsu_ctl runs as shell or root, never as an app), so
  the ctl socket is never app-reachable.

### D25. ns_inject is a `CLONE_FS`-only surgical actor
- `unshare(CLONE_FS)` at init (private `fs_struct`), never
  `CLONE_NEWNS`; then per-target: `setns()` into the app's mount
  namespace, make `/system/bin` private, add overlay (upper held by
  per-uid staging dir), then bind the *upper* `su` **directly** over
  the overlay's `su` (because opening overlayed files uses
  `FMODE_NONOTIFY` / fake-path on 5.10/6.1/6.18 — the doorbell
  requires the watch to see the open of the real upper file, not the
  overlay dentry), restore `fscreate`, get out.
- **Why namespace-scoped (and never global).** D3. Even the *overlay*
  is per-uid. A global overlay would be visible system-wide and
  directly fingerprintable.

---

## L7 — Build, CI, and the verification harness

### D26. ddk-min per-KMI CI builds, one artifact per run
- Each `ddk-lkm` workflow run targets one KMI in
  `ghcr.io/ylarod/ddk-min:<kmi>-<release>`, producing
  `aarch64-<kmi>-zerosu.ko` (+ another CI the user runs pushes to
  releases on tags). The kernel was *never* built locally: the DDK
  images are the single source of truth for artifaction.

### D27. The verification harness is a set of *compilers*, not a simulator
- `tests/syntax-check.sh` compile-checks the kernel tree against stub
  headers at the *anchored* version of each KMI (5.10, 5.15, 6.1, 6.6,
  6.12, 6.18) × {arm64, x86_64, (some arch cells)} plus two CFI cells
  (`CONFIG_CFI_CLANG` on 5.15). It is not a kernel build and makes no
  behavioral promises; it catches (a) syntax/shape illegal under a
  certain KMI's defconfig set, (b) any attempt to reference a stub that
  doesn't exist in that KMI's exported headers. 20 cells, all green at
  the current head. It's a *tripwire*, not a substitute for the DDK
  build.
- Because stub headers exist that don't ship in real kernels, the
  stub tree deliberately omits things the module must NOT depend on.

### D28. Smoke test is an ABI *user*, not a self-check instrument
- `tests/smoke_test.c` exercises PING → enroll → verify → ELEVATE →
  event-drain against a running module (documented in the header),
  runs by hand with `sudo` on whatever device the artifact is loaded
  on. It deliberately uses a *public* test key (0x5a × 64) and asserts
  the digest constant with `_Static_assert` — device SuperKey flow is
  tested nowhere in CI; it needs a device.

### D29. module __cfi shim is compiled per-config, not per-arch
- Under `CONFIG_CFI_CLANG` the DDK build generates `__cfi_check` for
  the module; on non-CFI kernels the shim's compiled shape differs.
  Both are exercised in the harness (D27), so the jt/body resolution
  decision (D9) cannot regress silently.

---

## L9 — Hardening batch (post-review, D30–D34)

Result of the second review round. Every item below is a *shrink*, not
a redesign: the mechanisms from L2–L5 keep their shapes; what changes
is that documented conventions become enforced invariants.

### D30. The gateway has a production posture: close after first authentication
- New insmod parameter `mode` (`0400`, on
  `/sys/module/zerosu/parameters/mode`): `0` = open (module stays armed
  forever — the lab/CI mode, and the default so existing flows
  continue to work), `1` = close. With `mode=1`, the *first successful
  `AUTH_VERIFY`** — i.e. the moment the boot-time daemon proves the
  SuperKey — unregisters the reboot kprobe
  (`zerosu_gateway_note_authenticated()` from the ioctl path, after the
  auth bookkeeping, outside the key mutex). From that point a fresh
  probe gets the stock reboot behavior even for a caller holding the
  public magics (O1).
- Two guards make the disarm airtight: the kprobe handler itself
  refuses everything once `gateway_closed` is set, and
  `zerosu_gateway_exit()` unregisters only on the
  `atomic_xchg(gateway_closed, 1)` transition, so exit after a close is
  not a double-unregister. The existing exit ordering (unregister →
  `synchronize_rcu()` → wait for `inflight_tw`) is unchanged and still
  applies to short-lived task work that may be in flight.
- Why unregistering beats a runtime flag check: a flag still puts the
  handler on every reboot(2) in the system; an unregistered probe is
  off the syscall path entirely, which is the claim stealth makes.
- Accepted cost (documented at the call site): after close, *new*
  sessions require `rmmod`/`insmod`, which is why D34 (ctl stop)
  exists. An existing session fd keeps working; the module merely
  stops advertising a door.
- Production install scripts pass `mode=1`; lab and CI use the default
  `mode=0` because the smoke tests mint sessions by hand.

### D31. A session fd pins the module — through the VFS, not by hand
- Corrected after live verification. The first cut of this decision
  added a manual `try_module_get()`/`module_put()` pair around
  `anon_inode_getfile()`, reasoning that "anon_inode_getfile() does not
  pin `fops->owner` on our behalf". That premise is **false**: with
  `fops .owner == THIS_MODULE` (our session fops), `__anon_inode_getfile()`
  itself takes `try_module_get(fops->owner)` — verified in the trees we
  build against (`fs/anon_inodes.c` line 87 on 5.10/5.15, line 99 on
  6.1–6.12, line 143 on 6.18). `__fput() -> fops_put()` releases it on
  close.
- The manual pair therefore double-counted: the module refcount grew by
  one per session, was never released, and one emulator session was
  rendered permanently `EBUSY` until reboot. Caught live: refcount went
  4 → 5 → 6 with zero fds open, one probe session added exactly +1.
- Standing invariant (O2): rmmod returns `-EBUSY` for exactly the
  window in which a session fd holds a file object, via the VFS-owned
  reference. Nobody takes module references by hand around session
  creation. The 1:1 property lives in `anon_inode_getfile()` + `fops_put`.

### D32. The new policy type is published, graced, then made findable
- Order in `zsu_sepolicy_add()` is now: grow → fill →
  `smp_store_release` publish (arrays are supersets; readers bounded by
  the old `nprim` are safe) → `synchronize_rcu()` →
  `zsu_symtab_insert()` (name becomes findable) → `nprim` commit
  (O3).
- The grace closes the name-lookup hazard the first review flagged:
  `security_context_str_to_sid()` walks `p_types` and then indexes
  `type_val_to_struct` / `type_attr_map_array` by the *found datum's*
  value with no `nprim` bound, so a reader that cached the old,
  smaller array pointer and found `zsu` post-insert would read out of
  bounds. After the grace, no pre-existing reader section remains, so
  any reader that finds `zsu` in the chain started after the grace and
  cannot hold the old pointers. Cost: one grace at boot, inside
  `policy_mutex`.
- Symtab-insert failure *after* the grace is handled by re-publishing
  the old arrays (the rollback that already existed) and letting the
  post-unlock retirement grace free the new storage. Readers after a
  rollback cannot have found `zsu` (the insert failed before the chain
  was touched), and the new arrays were fully initialized, so the
  republish is safe in both directions.
- The documented assumption, explicit for the next auditor: this relies
  on readers of the policydb being `rcu_read_lock()` sections and on
  `synchronize_rcu()`'s "every read-side section in flight at publish
  time has completed" guarantee. Plain, non-dependent loads of the
  array pointers inside those sections are the readers that made the
  grace necessary.

### D33. `ELEVATE_TASK` refuses multithreaded targets
- `zerosu_elevate_task()` now returns `-EPERM` when
  `!thread_group_empty(target)`, before touching credentials.
- This converts D14/D23's convention ("the target is the parked
  single-threaded suStub rendezvous") into a kernel-enforced invariant.
  Swap-and-put is only safe for a task with no concurrent execution on
  any CPU; refusing to trust the caller's claim about the target is
  cheaper than proving the caller right. A future legitimate
  multithreaded target requires a redesign (RCU-deferred old cred with
  per-thread sync), not the removal of this guard (O-note in D14).

### D34. `zsu_ctl stop` — the daemon half of module reload
- New SuperKey-gated ctl op (`ZSU_CTL_STOP`). The broker proves the
  key, replies, and sets `zsu_stop_requested`; the epoll loop takes the
  identical path as a caught signal (clean "stopped" exit), which
  releases the daemon's session fd — the very reference D31 makes
  `rmmod` wait on.
- The flow the new invariant (D30) and D31 create: `zsu_ctl stop` →
  `rmmod zerosu` → `insmod zerosu.ko mode=1` → restart zerosud via its
  init script. zsu_ctl deliberately does *not* re-spawn the daemon:
  spawning is the privilege of whatever runs at boot.
- The source-level ctl op audit in `tests/syntax-check.sh` (section 6)
  now expects STOP to be keyed, so a future mutation-shaped op cannot
  appear unkeyed without the harness objecting (D24/D27).

### D35. Session cap 8 → 2
- `ZSU_MAX_SESSIONS` is now 2: one for the daemon's long-lived SU
  session, one spare for a hand-opened lab session under `mode=0`.
  Every other consumer drives the daemon. A tighter cap is an
  attack-surface statement — idle fds cannot starve the broker — and
  matches the D30/D34 posture where sessions are rare, boot-time
  things.

---

## Open questions / risk register

These are explicitly *not settled*; they are recorded so that nothing
gets redesigned from a position of "that was an accident."

- **O1 — Public gateway magic = detection oracle.** CLOSED by D30 in
  the production posture (`insmod mode=1`): the door exists only for
  the boot-time window between insmod and the daemon's first
  successful `AUTH_VERIFY`, after which the kprobe is unregistered and
  the module stops answering probes entirely. In lab mode (`mode=0`)
  the oracle still exists *by design* — CI must be able to mint
  sessions by hand. Per-device randomized magics remain a rejected
  candidate: they do not survive a determined scanner and would break
  the smoke test's premises.
- **O2 — rmmod with a live session fd.** CLOSED by D31: every session
  fd now holds one module reference taken in `install_work()` and
  released by `fops_put()` at close, so `rmmod` returns `-EBUSY` for
  exactly the window in which the module's fops are reachable, and
  `zsu_ctl stop` (D34) provides the release half of the reload flow.
- **O3 — policydb grow vs RCU-reader transient.** CLOSED by D32: the
  name-findability insert now happens after a full
  `synchronize_rcu()` between the array publish and the symtab link,
  so no reader that finds `zsu` can be holding the old array pointers.
  The remaining assumption (readers are RCU sections; grace semantics
  as documented) is stated in D32 rather than assumed silently.
- **O4 — Manager UI existence changes the door threat model.**
  REFRAMED, kernel side closed. The manager never opens its own
  session: it talks to zerosud over a socket in the manager's own
  `data_dir` (the daemon, when it creates the socket under a connectto
  transition, lands it in the manager's data dir and labels it there),
  and the daemon is the only kernel client. What remains open is
  userspace design only: the socket's path/label/connectto rules and
  the clear-data lifecycle (a wiped data dir destroys the socket until
  the daemon recreates it) are recorded as future-work traps, not
  kernel decisions. A package-digest-bound manager credential for
  *direct* kernel access is rejected as unnecessary under the "manager
  is a daemon client" shape.
- **O5 — session-type PLAIN/SU is policy, not security** — retained for
  debugging; a future manager may drop it entirely.
- **O6 — the artifacts are public** (CI uploads). Nothing secret is in
  them (the SuperKey is generated on-device; the smoke key is public by
  design), but any future "bake a secret at build time" idea is wrong
  by definition because of this.

---

## L8 — Reference implementations observed

Grounded in the projects' own trees and docs (fetched via GitHub API
from these canonical repos: `tiann/KernelSU`,
`KernelSU-Next/KernelSU-Next`, `SukiSU-Ultra/SukiSU-Ultra`,
`bmax121/KernelPatch`, `bmax121/APatch`). Not a re-audit; a mechanism
inventory whose purpose is to justify keeping, differentiating, or
borrowing from our D1–D29.

### L8-a. Two mechanism families

**Family R — runtime hooks (KernelSU, KernelSU-Next, SukiSU-Ultra,
ReSukiSU — one tree family).** The kernel module or kernel source
registers hooks at runtime: `kernel/hook/lsm_hook.c` in KernelSU finds
the LSM hook slot by walking `security_hook_heads` (and
`lsm_static_calls_table` on ≥6.12), *binary-patches the slot in memory*
(`ksu_patch_text`, `static_call_update`), and restores it on
unload. KernelSU-Next's layout is KernelSU's plus `susfs/`;
SukiSU-Ultra's is the same family plus `kpm/` and a branch policy:
`main` = runtime kprobes/kretprobes/`sys_enter` tracepoint only
(CONFIG_KSU tristate, works as an LKM), `builtin` = manual hook calls
inserted into kernel source. ReSukiSU is the same family (visible
integrated in build action CI alongside these two).

**Family P — kernel image patch (KernelPatch/APatch).** KernelPatch
*KPatches the vmlinux image once at build/install time* (`kpimg`); from
then on there is no runtime hook registration: syscall interception is
inline patching or syscall-table pointer swap (`doc/en/syscall-hook.md`),
and the whole API is **one multiplexed syscall** — reusing
`__NR_truncate` (45) — whose first argument is *always* the superkey
string, with a magic (`0x1158`) and version measured in the command
encoding (`doc/en/super-syscall.md`). Dynamic sub-modules ("KPM") are
loaded through that supercall.

What all three have in common, usefully for D-references: **each has a
persistent root userspace member** (`runtime/ksud.c` in KSU launches
`/system/bin/ksud` from an injected init.rc line and hooks that exact
execve to escalate it as a *bootstrap*; APatch has `apd`; Magisk's
`magiskd` is the archetype). No member of either family achieved the
"no long-running root process" shape; KSU's daemon is the one closest
to a broker in role.

### L8-b. Mechanism comparison to ours

| axis | Family R (KSU/Next/SukiSU) | Family P (APatch/KP) | ZeroSU |
|---|---|---|---|
| kernel change | none (runtime) | image patch at install | none (runtime) |
| hook surface | every execve (or stat/openat in sucompat), plus LSM slots | inline, once-patched image | one syscall (reboot), magic-gated |
| root grant authority | kernel allowlist (uid-keyed) + per-app profile | kernel-side supercalls | kernel digest check (D11/D12) |
| su visibility | global `/system/bin/su` (hook-checks, not restricted) by symlink/hook; sucsess is uid-gated at the hook, not namespace-scoped | superkey-gated binary | **namespace-scoped**: only the granted uid's mount ns |
| superkey / secret | n/a (allowlist is the policy; no per-device secret) | superkey string in the image; printed once | SuperKey digest in .ko, patched daemon holds plaintext only until first auth (D11) |
| app→root IPC | ksud daemon + embedded init.rc bootstrap; per-syscall hook on kb 45 (their shortcut) | supercall on nr 45 | reboot magic + ioctl door |
| allowlist persistence | `/data/adb/ksu` files via ksud replays (kernel keeps live copy) | apd config files | grants file on `/data/adb/zerosu` (D22; kernel keeps no state) |
| stealth cost | hot-path presence on execve/stat; LSM slot patching detectable | promises the smallest surface after boot; but requires image modification | the narrowest runtime hook (one rare syscall), but a **public** magic constant (O1) |

### L8-c. Adoption verdicts

- **Keep D4 then, absolutely.** The references' every-execve hook cost
  is exactly the global-profiler output state D3 disallows; our
  single `reboot()` hook does not probe any hot path (reboot is
  rare, magic-gated, and the hook check is constant work).
  SukiSU-Ultra's `main` branch validates independently that
  "kprobes-only runtime hooks, LKM-safe, on GKI" is field-viable on
  the exact KMIs we target, which is supporting evidence for the CFI
  posture of D9 too.
- **Borrow, if O4 reshapes the manager:**
  1. KernelSU's exec-anchored *bootstrap escalation*
     (`escape_to_root_for_init()`, the exact execve of the daemon path
     at init) — a precedent for replacing our "privilege boot script
     needs to exist to insmod and later exec the daemon as root"
     assumption (D2) with a hook-anchored equivalent, without
     expanding to hot paths beyond that one anchor. [open, not planned]
  2. KernelSU's **per-app profiles** (`policy/app_profile.c` — per-uid
     SELinux domain, groups, capabilities) — treat as a *future* if the
     manager (O4) lands, since it implies per-app domain transitions,
     i.e. more than our one SID (`u:r:zsu:s0`) policy — then D17/D18's
     "grow the policy once" must become per-domain growth.
  3. KSU allowlist-in-kernel policy vs our daemon-held grants (D22) —
     treat as a *divergening design* on purpose; our decision keeps
     the kernel stateless about grants and puts persistence wholly in
     userspace, with the daemon as broker, because per-boot kernel
     persistence would need an extra storage discipline (a `/proc` or
     module param channel) inside the module's trust boundary. Only
     worth revisiting if the manager is ever expected to work without
     the daemon (O4's first fork in the design).
- **Reject permanently**, they are outside this project's envelope:
  LSM slot binary-patching, inline or syscall-table patching (Family
  R/P shapes), kernel image superkey embedding, KPM dynamic module
  loading, and SUSFS integration — each violates D1 (no kernel image
  change) or D3 (global permanent hook in a hot path) and none maps
  onto a problem we currently have.

---

## Decisions Index


| # | Layer | Summary |
|---|---|---|
| D1 | mission | unmodified GKI, `.ko` per KMI only |
| D2 | mission | install-time root = the only assumed root |
| D3 | mission | stealth: scope visibility to granted uids only |
| D4 | kernel entry | kprobe on reboot syscall wrapper, one hook |
| D5 | kernel entry | kprobe defers fd work to task_work (forced) |
| D6 | kernel entry | inflight counter owns the unload race |
| D7 | kernel entry | anon-inode session objects, no global devnode |
| D8 | symbols | name-registered kprobe bootstraps kallsyms |
| D9 | symbols | exported vs resolved + `.cfi_jt`/`__nocfi` CFI doctrine |
| D10 | symbols | typed per-subsystem symtabs; refuse load on doubt |
| D11 | auth | one device key, digest-only, wiped from userspace |
| D12 | auth | permission-map per opcode; explicit wrappers |
| D13 | auth | per-session event ring for a future manager |
| D14 | elevate | commit_creds for self, pointer-swap for remote |
| D15 | elevate | alloc_uid/set_cred_ucounts defense |
| D16 | seccomp | fake-task relay to real seccomp_filter_release |
| D17 | selinux | live policydb grow once, refuse-to-load on doubt |
| D18 | selinux | stamp only uncommitted creds; blob-offset discovery |
| D19 | compat | compat.h is the single version control point |
| D20 | compat | seccomp release lock-shape per branch recorded |
| D21 | userspace | single-threaded epoll daemon |
| D22 | userspace | grants = plain uid-list file; kernel not persistent |
| D23 | userspace | app flow: stub doorbell → daemon plans → kernel elevates |
| D24 | userspace | ctl.sock = shell domain + SuperKey for mutation |
| D25 | userspace | ns_inject: CLONE_FS surgery, per-uid overlay/direct bind |
| D26 | build | ddk-min CI per KMI is the artifact source of truth |
| D27 | build | compile-tripwire harness (6 KMI × 3 arch + CFI) |
| D28 | build | smoke test = hand-run ABI user with public test key |
| D29 | build | CFI shim shape is a harness cell, not an assumption |
| D30 | gateway | `mode=1`: kprobe disarmed at first authentication |
| D31 | gateway | session fd pins the module (1:1 `try_module_get`) |
| D32 | selinux | publish arrays → full grace → symtab link → nprim |
| D33 | elevate | `ELEVATE_TASK` refuses multithreaded targets |
| D34 | userspace | `zsu_ctl stop`: SuperKey-gated daemon exit for reload |
| D35 | kernel entry | session cap 8 → 2 |
