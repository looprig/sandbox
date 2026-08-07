# Lifetime containment

A Supervised spawn (`Executor.PrepareProcess` → `PreparedProcess.Start`) is
torn down at the end of its run by whatever `zeroProver` the platform backend
attached to it: something that proves the whole fork tree the spawn produced
— not just the immediate child — is gone. What that proof can actually
guarantee differs by platform and by backend. `Process.LifetimeContainment()`
reports, per spawn, which of three contracts was actually achieved. This page
is the reference for that contract, why macOS is the one platform that
downgrades it, and what a caller should do about that.

Access confinement (which files, network targets, and environment a process
can touch) is a completely separate axis from lifetime containment (whether
every descendant the process forks is guaranteed to be torn down when the
run ends). This page is only about the second one. A spawn's access
confinement is unaffected by which `LifetimeContainment` value it reports.

## The three contract values

`exec.LifetimeContainment` / `sandbox.LifetimeContainment` (an alias of the
same type) is one of:

- **`LifetimeContainmentUnspecified`** (zero value) — the spawn carries no
  lifetime containment claim at all. This is the non-Supervised
  `RunCommand`/`RunArgv` path, an `Unconfined` executor, or a spawn compiled
  through a test double backend. Teardown is the plain process-group
  SIGKILL-and-poll sweep every platform has always had, which a `setsid` or
  double-fork descendant can defeat undetected. Reporting anything stronger
  than `Unspecified` here would misrepresent a guarantee that was never
  requested.
- **`LifetimeContainmentEnforced`** — the kernel itself guarantees teardown.
  No descendant, however it forks or detaches, can escape it.
- **`LifetimeContainmentBestEffort`** — teardown is process-group SIGKILL
  plus active tracking of the fork tree, not a kernel guarantee. A
  descendant that evades tracking can survive the spawn's own teardown as an
  orphan. This is macOS's answer for a real Seatbelt-confined Supervised
  spawn, and is the whole reason this page exists.

## Per-platform matrix

| Platform | Backend / rung | `LifetimeContainment` | Mechanism |
|---|---|---|---|
| Linux | Rung 1 | `Enforced` | Fresh PID namespace; the namespace's init process exiting tears down every process still inside it, kernel-guaranteed. |
| Linux | Rung 2 (delegated cgroup v2) | `Enforced` | `cgroup.kill` plus a proven-empty `cgroup.procs` read. If no delegated cgroup v2 `pids` ancestor is available to delegate from, the spawn is rejected before it starts with `enforce.ErrLifetimeContainmentUnavailable` instead of silently downgrading — Rung 2 has no best-effort fallback of its own. |
| Windows | Elevated/broker backend | `Enforced` | The process runs inside a Job object; an unassigned or already-terminated Job makes teardown unconditional and kernel-guaranteed, matching the Linux rungs. |
| macOS | Seatbelt | `BestEffort` | Process-group SIGKILL-and-poll plus a proc-table-closure descendant tracker (below). No kernel-enforced tree-teardown primitive is available to an unentitled process on this platform — see "Why macOS is best-effort" below. |
| macOS / any | `Unconfined` or a test-double backend | `Unspecified` | No containment claim is made; not applicable. |

Access confinement is unaffected by any of this: a macOS Seatbelt-confined
descendant that survives past its spawn's teardown is still running under
the exact same Seatbelt profile it was born into. It cannot read, write, or
reach network targets the profile didn't already allow.

## Why macOS is best-effort

Two kernel-level mechanisms exist that could, in principle, give macOS the
same kernel-guaranteed teardown Linux and Windows have, and neither is
available to this module:

- **`EVFILT_PROC` with `NOTE_TRACK`** — the kqueue facility that would let a
  process transitively follow every fork in a target's tree, the closest
  Darwin analog to a PID namespace's kernel bookkeeping — is rejected with
  `ENOTSUP` by XNU's `filt_procattach` (empirically verified, macOS 26.5.2
  arm64, 2026-08-06). The constant exists in Darwin's headers only for
  FreeBSD source compatibility; it does not work on Darwin's own kernel.
- **Endpoint Security** (`ES_EVENT_TYPE_NOTIFY_FORK`/`EXEC`/`EXIT`), Apple's
  real process-tree-observation framework, requires a system-extension
  entitlement Apple grants selectively and that this module cannot assume
  its consumers have. It is the only known path to a real `Enforced`
  contract on macOS, and remains out of scope for this module until a
  consumer can supply that entitlement.

Until one of those changes, no unprivileged macOS process can be handed
kernel-level proof that a fork tree is empty. The project's accepted
position (2026-08-06 acceptance decision) is that this does not have to
block Supervised spawns on macOS altogether: Seatbelt access confinement is
inherited by every descendant regardless of how it was discovered, so an
undetected descendant is an orphaned-but-still-sandboxed process, not an
access-control hole. Earlier, the Darwin backend took the opposite position —
`attachSupervisedProof` rejected every real Seatbelt-confined Supervised
spawn outright, before `cmd.Start()` ever ran, with
`enforce.ErrLifetimeContainmentUnavailable` (Task 12c's fail-closed posture).
That rejection is gone; this page's best-effort contract replaced it.

## The darwin mechanism

`attachSupervisedProof` (`internal/exec/process_tree_darwin.go`) attaches a
`darwinBestEffortProof` to every Supervised spawn compiled through the real
Seatbelt backend. It combines two layers:

1. **Process-group SIGKILL-and-poll** — the same mechanism every platform
   has always used for a non-Supervised spawn: SIGKILL the group, poll until
   it's empty. This alone is what `LifetimeContainmentUnspecified` spawns
   rely on, and it is exactly what a `setsid` or double-fork descendant
   escapes.
2. **`descendantTracker`** (`internal/exec/process_descendants_darwin.go`) —
   narrows that gap by actively following the fork tree instead of trusting
   the process group alone:
   - **Closure sampling.** Every ~100ms (and on demand, see below), it reads
     the whole process table (`kern.proc.all`) and grows the transitive
     closure rooted at the spawned root: a process joins the tracked set if
     its parent PID or process-group ID is already a member. This is
     iterated to a fixpoint within one snapshot, so a whole fork chain that
     appeared between samples is captured in one pass.
   - **kqueue acceleration.** `EVFILT_PROC` with `NOTE_FORK`/`NOTE_EXIT` is
     registered on every tracked member (`NOTE_TRACK` itself is the thing
     that doesn't work — see above). A `NOTE_FORK` event triggers an
     immediate extra sample instead of waiting for the next tick, narrowing
     the race between a fork and the next scheduled sample. `NOTE_EXIT`
     retires a member as soon as it exits. If a given kernel rejects
     `NOTE_FORK` registration with `ENOTSUP`, the tracker permanently
     degrades to `NOTE_EXIT`-only for its own lifetime and leans harder on
     polling.
   - **Identity-guarded kills.** Every tracked member is recorded as
     `(pid, start-time)`, not just `pid`. macOS reparents an orphaned
     process to `launchd` (pid 1) rather than leaving it parentless, which
     would otherwise let a tracked slot's pid be recycled by an unrelated
     process before teardown notices the original is gone. Before signaling
     a member, its live start-time is re-checked against the recorded one; a
     mismatch means the pid was recycled, and that process is left alone
     rather than killed. `launchd` itself is never treated as a closure
     anchor, or every process on the system it has ever reparented (nearly
     every daemon) would be wrongly recruited into the tracked set.

Teardown (`darwinBestEffortProof.terminateAndWait`) samples once more (to
catch anything forked just before the kill), then SIGKILLs the process group
and every identity-verified live member, polling until both the group and
every tracked member are gone. If the tracker itself failed to construct
(e.g. file-descriptor exhaustion prevented allocating its `kqueue`), the
spawn still proceeds — the tracker only ever narrows the best-effort gap; it
is never the containment itself — and teardown falls back to the plain
process-group sweep alone.

### Accepted gaps

None of the above adds up to a proof, by design. The specific gaps the
project has accepted rather than treating as bugs:

- A descendant that double-forks **and** leaves the process group between
  two samples, with no `NOTE_FORK` event to accelerate detection (or on a
  kernel where `NOTE_FORK` itself is unsupported), is never discovered.
- A member whose pid is recycled before its retirement is noticed is skipped
  at kill time by the start-time identity check — the tracker's failure mode
  is deliberately fail-safe: it would rather miss an escapee than kill an
  unrelated, innocent process that happens to reuse a tracked pid.
- Tracking is armed just after `cmd.Start()`, not before; a child forked in
  that narrow window is caught only by the first sample's closure walk (via
  its parent/group link), not by a kevent.

## Implications for callers

A caller that hosts long-lived or interactive children through
`PrepareProcess`/`Start` on macOS should plan for these outcomes on a
`BestEffort`-reported spawn, however rare in practice:

- **Orphaned-but-still-sandboxed processes.** A descendant that evades the
  tracker can outlive the run the caller believes it stopped. It remains
  fully confined by the spawn's Seatbelt profile — it gains no additional
  filesystem or network authority by surviving — but it is still consuming
  resources under a session the caller has already torn down.
- **Port or lock squatting.** A survived descendant that was listening on a
  port or holding a filesystem lock keeps holding it. A caller that
  immediately retries the same work (e.g. re-running the same tool on the
  same port) can see a spurious "address already in use" or lock-contention
  failure that a truly-enforced platform would never produce.
- **Post-stop workspace writes.** Because access confinement — not lifetime
  — is what actually bounds a descendant's authority, a survivor can keep
  writing inside whatever workspace scope its Seatbelt profile already
  granted it, after the caller considers the run finished.

## Guidance

Check `Process.LifetimeContainment()` rather than assuming a platform's
answer. A caller that hosts long-lived children and cares about this
distinction — most concretely, anything wiring a persistent child process
(e.g. an ACP-bridged agent loop) through this module — should surface
`BestEffort` to its own users on macOS, rather than silently presenting the
same teardown promise it can make on Linux or Windows. `Unspecified` and
`Enforced` need no special handling beyond what the caller already does
today; `BestEffort` is the one value that means "the process should be gone,
but the module cannot prove it."
