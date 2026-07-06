# Spike M5 — cgroup v2 delegation (Linux)

**Status:** proven (green) on the reference host. Throwaway spike validating
Task 14 (cgroup v2 resource limits).

- **Test:** `spikes/cgroup/cgroup_delegation_linux_test.go` (`//go:build linux`,
  package `cgroup`, capability-gated).
- **Run:** `go test -race ./spikes/cgroup/ -run TestCgroupPidsDelegation -v`

## What it proves

1. **A fork bomb is capped at `pids.max`.** A helper child is joined into a
   transient cgroup at clone time via `CLONE_INTO_CGROUP`
   (`syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}`, Go 1.22+) — the
   exact mechanism Task 14's backend will use to join its stage-2 child. Inside
   a cgroup with `pids.max = 20`, the helper's bounded fork loop
   (up to 60 `sleep` children) is stopped: its N+1-th `fork()` fails with
   `EAGAIN` and, at that instant, `pids.current == pids.max == 20`.
2. **Detect + report cleanly when delegation is unavailable.** If no writable
   ancestor distributes the `pids` controller (or the host is cgroup v1/hybrid —
   no `/sys/fs/cgroup/cgroup.controllers`), the test `t.Skip`s with a *specific*
   recorded reason. A skip is never a silent pass.

## Delegated-root resolution (discovered at runtime — nothing hardcoded)

Read the unified `0::<path>` line of `/proc/self/cgroup`, then walk UP the
ancestry to the nearest directory that is **(a) writable** AND **(b)** lists
`pids` in its `cgroup.subtree_control`. The transient child is created directly
under that ancestor, where a fresh `pids.max` file works immediately.

On the reference host (systemd user session, uid 1000, kernel 6.8, unified v2)
this resolves to:

```
/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/session.slice
```

Note: the controller's brief predicted `user@1000.service`, but on this host
`session.slice` **also** distributes `pids` (its `cgroup.subtree_control` is
`memory pids`) and is writable, so the *nearest*-ancestor rule lands there. This
is equally safe: our transient cgroup is a fresh, empty **sibling** of the
desktop's `org.gnome.Shell@wayland.service` node — we never touch that node, and
`pids` limits are strictly per-cgroup, so a cap of 20 inside our scope cannot
affect the desktop or the wider system. (`user@1000.service` is the next match
up if `session.slice` ever stops distributing `pids`.)

## Observed results (reference host)

| case    | `pids.max` | outcome  | spawned | `pids.current` at stop |
|---------|-----------:|----------|--------:|-----------------------:|
| capped  |         20 | `EAGAIN` |      16 |                     20 |
| control |        200 | `NOLIMIT`|      60 |                     64 |

The 16 successful `sleep` children + ~4 of the helper's own Go-runtime tasks
(`GOMAXPROCS=1`) sum to the cap of 20. The control runs the full loop (60), well
past 20, proving the cap — not some ambient limit — is what stopped the capped
case.

## Anti-fail-open discipline

A naive "some fork failed" is not accepted as proof. The capped case asserts
**all** of:

- `outcome == EAGAIN` (it actually hit the cap), and
- `1 <= spawned < 60` (real forks succeeded — not "0 forks for an unrelated
  reason" masquerading as a cap — yet the loop *was* limited), and
- `pids.max` reads back as the configured `20`, and
- `pids.current == pids.max` (the cgroup was genuinely at its configured cap).

The **control** case is the positive-capability half: the identical loop with a
high `pids.max` must run to completion (`spawned == 60 > 20`), so we know the
cgroup path and join mechanism work and it was the cap that limited the other case.

## Safety / cleanup

Every mutation is confined to a fresh child cgroup the test creates itself
(`lrsb-spike-<pid>-<tag>`, unique from `os.Getpid()` — no `time.Now`/rand). The
test **never** writes to an existing cgroup's `cgroup.subtree_control` and
**never** moves a pre-existing process. Teardown is registered with `t.Cleanup`
*before* any fallible step, so it runs even on assertion failure: recursive
`cgroup.kill`, then `SIGKILL` of any pid still listed in `cgroup.procs` (only
pids in our own transient cgroup), then `rmdir` retried while procs drain.
Verified after runs: no `lrsb-*` cgroups remain and no leftover `sleep`
processes.

## Implication for Task 14

`SysProcAttr.UseCgroupFD` (CLONE_INTO_CGROUP) is the right join primitive: the
stage-2 child is placed in the limit cgroup atomically at `clone()`, so it is
capped from its first fork with no write-to-`cgroup.procs` race. The backend
must (1) probe for a writable delegated ancestor distributing `pids` and degrade
gracefully (or error clearly) when absent, and (2) own unconditional teardown of
its transient scope (`cgroup.kill` + `rmdir`) on every exit path.

## Carry-forward for Task 14 (from adversarial review — SOUND verdict, no blockers)

The spike is sound as-is on this host; these are hardening notes for the
*shipped* backend, not spike defects:

1. **By-pid straggler kill has a pid-reuse window.** After `cgroup.kill`, the
   spike re-reads `cgroup.procs` and `SIGKILL`s each pid by number — a read-then-
   kill race that could, on a host with a *small* `pid_max`, kill an unrelated
   reused pid. Negligible here (`cgroup.kill` empties the cgroup first;
   `pid_max = 4194304`). The backend should prefer `cgroup.kill` +
   poll-until-empty + `rmdir`, or re-verify `/proc/<pid>/cgroup` membership
   before any by-pid kill.
2. **Size the pids cap with Go-runtime thread headroom.** `pids.max = 20` is
   close to the runtime's own thread need; under `GOMAXPROCS=1` the runtime uses
   ~4–5 threads (≈15 spawn slots observed). A cap set too near the runtime's
   thread floor risks a fatal "can't create OS thread" (fail-closed, but flaky).
   The backend applies limits to the *target* command (which is `execve`'d, so it
   is not the Go runtime) — but any Go-side supervisor sharing the cgroup needs
   headroom.
3. **Transient-scope names need entropy beyond the pid.** The spike uses
   `lrsb-spike-<pid>-<tag>`; under `-count=N` or after a crashed prior run a
   stale dir makes `Mkdir` fail `EEXIST` (fail-closed, not a false green). The
   backend's transient cgroup names should include an additional uniqueness
   source (e.g. a monotonic counter or random suffix).
4. **Keep the self-`pids.max` readback pattern.** A kernel that silently ignores
   `UseCgroupFD` (too old) is caught because the joined child's own `pids.max`
   readback would not match the configured value → fail-closed. The backend
   should retain an equivalent positive membership/limit check rather than
   assuming the join took.
