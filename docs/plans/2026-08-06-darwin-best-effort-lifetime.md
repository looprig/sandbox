# Darwin Best-Effort Supervised Lifetime Containment — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Let a Supervised (PreparedProcess/Start) spawn run under the real Seatbelt backend on macOS with best-effort process-tree lifetime containment — process-group SIGKILL-and-poll plus a descendant tracker built on process-table closure polling accelerated by kqueue `NOTE_FORK`/`NOTE_EXIT` — instead of failing closed with `ErrLifetimeContainmentUnavailable`, and report the downgrade honestly per spawn.

**Architecture:** Darwin's `attachSupervisedProof` stops rejecting Seatbelt spawns and instead attaches a `darwinBestEffortProof` `zeroProver`. The prover owns a `descendantTracker` armed post-`Start` via an optional `pidArmer` seam invoked from `processTree.start`. The tracker maintains a transitive-closure member set (pid + start-time identity) by sampling `kern.proc.all` while the spawn is alive — membership persists after reparenting — and registers `EVFILT_PROC NOTE_FORK|NOTE_EXIT` kevents on members to trigger immediate resampling (narrowing the race window) and prune exits. **`NOTE_TRACK` is NOT used: XNU rejects it with `ENOTSUP` (empirically verified on this host, macOS 26.5.2) — it exists in headers/x-sys for FreeBSD compatibility only. Do not "simplify" back to it.** Teardown SIGKILLs the group and every identity-verified live member and polls until both are gone. A new exported `LifetimeContainment` value on `Process` reports which contract a spawn actually got (`Enforced` / `BestEffort` / zero-value `Unspecified`). Access confinement (Seatbelt) is untouched — an escapee is orphaned but still sandboxed.

**Decision context (from design discussion, 2026-08-06):** macOS has no kernel-enforced tree-teardown primitive available without an Endpoint Security entitlement. The user accepted the guarantee downgrade for darwin: best-effort is OK because Seatbelt inheritance means lifetime escape is a hygiene problem (orphaned-but-confined processes), not an access-control hole. SPEC Task 12c's "no success path until a concrete primitive exists" contract is superseded by this decision; SPEC.md is updated in Task 8.

**Amendment (2026-08-07, during Task 6 execution):** the "Access confinement (Seatbelt) is untouched" line above turned out not to hold exactly. Exercising a real Seatbelt-confined Supervised spawn end-to-end for the first time (PTY spawns previously always failed closed pre-spawn, so this code path had never actually run under real confinement before) surfaced a genuine, previously-undiscovered gap: `ioctl(2)` on a confined process's own controlling terminal was denied outright — `baseSandboxPreamble` had zero `file-ioctl` rule at all — breaking `stty` and any terminal-aware tool, even though plain PTY read/write already worked confined. The user was consulted directly and explicitly chose to widen the Seatbelt profile rather than narrow the test. The fix (`internal/darwin/seatbelt.go`'s `compilePTYSlaveIoctl`, commit `d98167f`) is minimally scoped and empirically verified: `(allow file-ioctl (regex #"^/dev/ttys[0-9]+$"))`, restricted to the PTY slave device family only — no new file-read/write/network grant, no guarantee-bitmask change, structurally inert for any non-PTY spawn. This is a deliberate, narrow, reviewed departure from this plan's original architecture statement, not a silent scope creep — recorded here for anyone reading this plan after the fact.

**Tech Stack:** Go, `golang.org/x/sys/unix` v0.45.0 (`Kqueue`, `Kevent`, `Kevent_t`, `EVFILT_PROC`, `EVFILT_USER`, `NOTE_FORK`, `NOTE_EXIT`, `NOTE_TRIGGER`, `EV_ADD`, `EV_CLEAR`, `CloseOnExec`, `SysctlKinfoProcSlice`, `SysctlKinfoProc`), existing `zeroProver`/`quarantinedSpawn` machinery.

**Branch/worktree:** `feat/darwin-best-effort-lifetime` at `/Users/ipotter/code/looprig/.worktrees/darwin-best-effort-lifetime/sandbox`, based on `feat/long-running-commands` (93b909a). All commands below run from that directory with `GOWORK=off` (the worktree is outside go.work).

**Commit style:** conventional commits, NO Co-Authored-By trailer (project rule).

---

## Background for an engineer with zero context

- A **Supervised** spawn is the asynchronous `PrepareProcess → Start` path (`internal/exec/process.go:782` sets `Supervised: true`); synchronous `RunCommand`/`RunArgv` never attaches a proof and keeps using the process-group signal-and-poll loop in `processTree.terminateAndWait` (`internal/exec/process_tree_unix.go:121`).
- A **zeroProver** (`internal/exec/process_quarantine.go:16`) proves "every process in the boundary is gone". `quarantinedSpawn.reapOnce` retries `terminateAndWait` forever (async reaper, 100ms interval) until `proofErr == nil`, then calls `release`, which calls `prover.close()` — so the tracker's `close()` runs only after a nil proof. Verified ordering: `process_quarantine.go:72–117` → `process_tree_unix.go:154–159`.
- `attachSupervisedProof` (per-platform: `process_tree_linux.go:79`, `process_tree_darwin.go:51`) picks the mechanism. Linux: PID-namespace (Rung 1) or delegated cgroup v2 (Rung 2). Darwin today: returns `enforce.ErrLifetimeContainmentUnavailable` unconditionally for the real Seatbelt backend, before `cmd.Start()` — that is the behavior this plan replaces.
- The real Seatbelt backend is detected by `reflect.TypeOf(options.Backend) == darwinBackendType` (`process_tree_darwin.go:18`). Keep that scoping: `enforce.NewNull()` / test doubles / Unconfined still attach nothing — and per this plan they report `LifetimeContainmentUnspecified`, NOT `Enforced` (see Task 3 rationale).
- `processTree.start` (`process_tree_unix.go:66`) is the only place that runs after `cmd.Start()` with the tree in hand — that is where the tracker gets armed. Both the pipe path and the PTY path funnel through `lease.start` → `tree.start` (`process.go:830, 932`; `executor_lifecycle.go:79–92`), so one hook covers both. PTY spawns set `Setsid` (session leader), pipe spawns set `Setpgid`; both make pgid == root pid.
- `process.go`'s spawn code holds the tree as the `processTreeBoundary` **interface** (`process_quarantine.go:21–24`), which has only `start`/`terminateAndWait`/`close`. Any new per-tree accessor must be reached via an optional-interface type-assertion, NOT by widening `processTreeBoundary` (widening breaks the fakes at `process_quarantine_test.go:189–200` and `process_lifecycle_test.go:278`).
- **Darwin kqueue facts (empirically verified during plan review — trust these over intuition):**
  - `EVFILT_PROC` with `NOTE_EXIT` on an existing pid: works.
  - `EVFILT_PROC` with `NOTE_TRACK` (or `NOTE_TRACKERR`/`NOTE_CHILD`): registration fails `ENOTSUP`. XNU's `filt_procattach` rejects it. There is no transitive fork-following on darwin.
  - `EVFILT_USER` + `NOTE_TRIGGER`: works, and reliably unblocks a parked `Kevent` — needed because closing a kqueue fd does NOT unblock a blocked `Kevent` call.
  - x/sys v0.45.0 struct literals as written below compile on darwin (`Ident uint64`, `Filter int16`, `Flags uint16`, `Fflags uint32` — untyped constants convert cleanly). `err == syscall.EINTR` works (`unix.Errno`).
  - `NOTE_FORK` support is asserted by Apple's docs but was not part of the review's probe; Task 2 Step 0 verifies it empirically and the tracker degrades to pure polling if it's rejected.
- Process-table sampling: `unix.SysctlKinfoProcSlice("kern.proc.all")` returns `[]unix.KinfoProc`; per element: pid = `p.Proc.P_pid`, ppid = `p.Eproc.Ppid`, pgid = `p.Eproc.Pgid`, start-time = `p.Proc.P_starttime` (a `unix.Timeval` — the pid-reuse identity check). Single-pid lookup: `unix.SysctlKinfoProc("kern.proc.pid", pid)`. Existing precedent in this package: `process_group_state_darwin.go` uses `SysctlKinfoProcSlice("kern.proc.pgrp", pgid)` and `p.Proc.P_stat` (`darwinZombieState = 5`).

Existing test conventions:
- Unit tests: plain `go test`, files like `process_tree_darwin_test.go` (`//go:build darwin`). `facade_test.go` at the repo root is **untagged** and runs everywhere.
- Integration tests (spawn real processes / real Seatbelt): `//go:build integration` (plus platform tags where needed), run with `GOWORK=off go test -tags integration ./internal/exec/`.
- Real-executor construction for unit-level spawns: `newProcessTestExecutor(t, Allow)` → `executor.PrepareProcess(...)` → `prepared.Start(ctx)` (`process_test.go:51–77, 102–130`) — note this builds an **Unconfined/null-backend** executor.
- `Process.Signal` signature: `func (p *Process) Signal(ctx context.Context, kind ProcessSignal) error` (`process.go:1704`); usage example `proc.Signal(context.Background(), ProcessSignalKill)` at `process_parent_death_integration_unix_test.go:236`.

**Files that structurally encode the OLD darwin-rejection contract** (each is explicitly handled by a task below — none may be left to chance):

| File | What it asserts today | Handled in |
|---|---|---|
| `facade_test.go:198–241` | untagged; darwin `prepared.Start` fails `ErrLifetimeContainmentUnavailable`, nil Process, `Wait` → `ErrProcessClosed` | Task 5 |
| `internal/exec/process_tree_darwin_test.go:29–99` | five subtests; the rejection ones flip, the scoping ones survive | Task 5 |
| `internal/exec/process_pty_integration_unix_test.go:77–98, 144–185` | `TestIntegrationProcessPTYDarwinLifetimeUnavailable` + skip-on-unavailable branches | Task 6 |
| `internal/exec/process_parent_death_integration_unix_test.go:117–124, 250–302` | darwin branch asserts `Start` fails before spawn; escape-proof test has darwin carve-out | Task 6 |
| `internal/exec/process_grant_integration_test.go:30, 95` | darwin skip branch (grant lifecycle never ran under Seatbelt) | Task 6 |
| `init_other.go:11–18`, `internal/exec/lifetime_unix.go:19–24`, `internal/exec/process.go:887–898`, `internal/exec/process_tree_unix.go:15–25, 107–120`, `internal/enforce/enforce.go:15–30`, `sandbox.go:~330` | stale prose: "rejects every Supervised spawn unconditionally" etc. | Task 8 |

---

### Task 1: Extract the group signal-and-poll loop into a reusable helper

The nil-proof polling loop in `processTree.terminateAndWait` is also the darwin prover's fallback when the tracker could not be constructed or armed. Extract it so both share one implementation. (The tracker-armed teardown path in Task 2 runs its own combined loop — group + members interleaved — and does NOT reuse this helper; don't oversell the sharing in comments.)

**Files:**
- Modify: `internal/exec/process_tree_unix.go`
- Test: existing `internal/exec` suites (pure refactor — the existing suite is the regression net)

**Step 1: Refactor**

In `process_tree_unix.go`, add a free function and make `terminateAndWait`'s nil-proof branch use it:

```go
// signalAndPollProcessGroupZero drives pgid's whole process group to zero the
// best-effort way: reap zombies, inspect, SIGKILL again while anything is
// still live, poll until the group is empty. Shared by every non-Supervised
// spawn's terminateAndWait and by Darwin's Supervised prover when its
// descendant tracker is unavailable (process_tree_darwin.go).
func signalAndPollProcessGroupZero(pgid int, signalGroup func(syscall.Signal) error) {
	for {
		reapProcessGroup(pgid)
		active, err := processGroupActive(pgid)
		if err != nil {
			// Inspection failure is not evidence that the group is gone.
			time.Sleep(time.Millisecond)
			continue
		}
		if !active {
			return
		}
		// Darwin can report EPERM for a redundant kill during exit transition;
		// no kill error proves absence, so retry after re-inspecting.
		_ = signalGroup(syscall.SIGKILL)
		time.Sleep(time.Millisecond)
	}
}
```

Replace the loop body in `(tree *processTree) terminateAndWait` (currently `process_tree_unix.go:130–151`) with `signalAndPollProcessGroupZero(tree.pgid, tree.signalGroup); return nil, nil` — keep the `tree.pgid <= 0` early return; move the loop-rationale comments onto the helper (as above) rather than duplicating them.

Note: `reapProcessGroup` only reaps *direct children of this process* in the group; it stays inside the helper.

**Step 2: Run the exec suites**

Run: `GOWORK=off go test ./internal/exec/` → PASS (pure refactor).
Run: `GOWORK=off go test -tags integration ./internal/exec/` → PASS.

**Step 3: Commit**

```bash
git add internal/exec/process_tree_unix.go
git commit -m "refactor: extract process-group signal-and-poll helper"
```

---

### Task 2: Darwin descendant tracker (poll-closure + kevent-accelerated)

A standalone tracker type, fully testable without any backend. Mechanism (in order of authority):

1. **Closure sampling (the backbone):** every `descendantSampleInterval` (100ms), read `kern.proc.all` and grow the member set to the transitive closure rooted at the spawn: any process whose `ppid` is a member, or whose `pgid` equals a member's pid-as-pgid, joins the set, recorded as (pid, start-time). Iterate to fixpoint within one sample (a chain of forks can appear in one snapshot). **Membership is permanent** — once seen, a member stays tracked even after its parent dies and it reparents to launchd (the ancestry link that let us find it is gone, but we already hold its identity).
2. **kevent acceleration:** register `EVFILT_PROC` `NOTE_FORK|NOTE_EXIT` (`EV_ADD|EV_CLEAR`) on every member as it joins. `NOTE_FORK` triggers an immediate resample (instead of waiting out the interval), shrinking the window in which a fast double-forker can vanish unobserved; `NOTE_EXIT` prunes the member (identity retired — a recycled pid is a different process). Registration failing for a member (already exited, or `NOTE_FORK` unsupported — Step 0 verifies) is recorded but non-fatal: sampling still covers it.
3. **Teardown (`killAndAwaitZero`):** SIGKILL the group; SIGKILL every member that still passes the identity check (single-pid `kern.proc.pid` lookup, start-time equal — never kill a recycled pid); loop reap/inspect/re-kill at 1ms until the group is inactive AND no identity-verified member remains. Zombie members (`P_stat == darwinZombieState`) count as gone — only their (dead or dying) parent can reap them, and once the tree's parents are gone launchd reaps them; treating them as live would stall the proof on a corpse.

**Accepted gaps (document, don't fight):** a descendant that double-forks *and* changes its pgid in between two samples, before any `NOTE_FORK` of its parent was delivered or acted on, is never discovered; a member that exits and whose pid is recycled before a sample retires it is skipped at kill time by the identity check (fail-safe: we prefer missing an escapee to killing an innocent process). This is exactly why the prover reports `LifetimeContainmentBestEffort`.

**Files:**
- Create: `internal/exec/process_descendants_darwin.go`
- Create: `internal/exec/process_descendants_darwin_test.go` (`//go:build darwin && integration` — every test here spawns real processes)

**Step 0: Empirically verify `NOTE_FORK` on this host**

Write a throwaway probe in the scratchpad (NOT the repo), mirroring the review's probe:

```go
// probe_notefork.go — go run it; do not commit.
package main

import (
	"fmt"
	"os/exec"

	"golang.org/x/sys/unix"
)

func main() {
	kq, _ := unix.Kqueue()
	cmd := exec.Command("/bin/sleep", "5")
	_ = cmd.Start()
	_, err := unix.Kevent(kq, []unix.Kevent_t{{
		Ident: uint64(cmd.Process.Pid), Filter: unix.EVFILT_PROC,
		Flags: unix.EV_ADD | unix.EV_CLEAR, Fflags: unix.NOTE_FORK | unix.NOTE_EXIT,
	}}, nil, nil)
	fmt.Println("NOTE_FORK|NOTE_EXIT register err:", err)
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}
```

Run: `cd <scratchpad> && GOWORK=off go run probe_notefork.go` (needs a tiny go.mod requiring x/sys — `go mod init probe && go get golang.org/x/sys@v0.45.0`).
- If err is nil: proceed as designed.
- If err is `ENOTSUP`: drop `NOTE_FORK` from the tracker (keep `NOTE_EXIT`-only registration and pure interval sampling), and record the probe result in the tracker's doc comment.

**Step 1: Write failing tests**

`process_descendants_darwin_test.go`:

```go
//go:build darwin && integration

package exec

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startTracked starts cmd in its own process group and arms a tracker on it.
func startTracked(t *testing.T, cmd *exec.Cmd) *descendantTracker {
	t.Helper()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tracker, err := newDescendantTracker()
	if err != nil {
		t.Fatalf("newDescendantTracker: %v", err)
	}
	if err := tracker.arm(cmd.Process.Pid); err != nil {
		t.Fatalf("arm: %v", err)
	}
	return tracker
}

func awaitMembers(t *testing.T, tracker *descendantTracker, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(tracker.liveMembers()) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tracker never reached %d members; live=%v", want, tracker.liveMembers())
}

func TestDescendantTrackerSeesForkedChild(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 & wait")
	tracker := startTracked(t, cmd)
	defer tracker.close()
	defer func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() }()
	awaitMembers(t, tracker, 2) // sh + sleep
}

func TestDescendantTrackerKillsSessionEscapee(t *testing.T) {
	// perl POSIX::setsid detaches from the process group AND (after the
	// parent is killed) from the ancestry chain — the exact escapee a plain
	// pgid sweep cannot see. The parent prints the child pid then lingers,
	// keeping the ppid link alive long enough for a sample (the tracker's
	// job is to have captured membership by then).
	cmd := exec.Command("/usr/bin/perl", "-MPOSIX", "-e",
		`my $pid = fork(); if ($pid == 0) { POSIX::setsid(); sleep 300; exit 0 } $| = 1; print "$pid\n"; sleep 300`)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	tracker := startTracked(t, cmd)
	defer tracker.close()

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("read escapee pid: %v", err)
	}
	escapee, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("parse escapee pid %q: %v", line, err)
	}
	if err := syscall.Kill(escapee, 0); err != nil {
		t.Fatalf("escapee not alive: %v", err)
	}
	// Wait until the tracker has discovered the escapee before tearing down.
	awaitMembers(t, tracker, 2)

	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	tracker.killAndAwaitZero(cmd.Process.Pid)

	if err := syscall.Kill(escapee, 0); err != syscall.ESRCH {
		t.Fatalf("escapee survived teardown: kill(pid,0) err=%v", err)
	}
}

func TestDescendantTrackerIdentityGuardSkipsRecycledPID(t *testing.T) {
	// A member whose recorded start-time no longer matches the live process
	// must not be killed. Simulate by injecting a bogus member entry for an
	// existing long-lived process (pid 1 with a zero start-time can never
	// match launchd's real start-time).
	cmd := exec.Command("/bin/sleep", "30")
	tracker := startTracked(t, cmd)
	defer tracker.close()
	tracker.injectMemberForTest(1, syscall.Timeval{})
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	tracker.killAndAwaitZero(cmd.Process.Pid) // must return; must not signal pid 1
	if err := syscall.Kill(1, 0); err != nil {
		t.Fatalf("launchd unexpectedly gone?! %v", err)
	}
}

func TestDescendantTrackerCloseUnblocksLoop(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	tracker := startTracked(t, cmd)
	done := make(chan struct{})
	go func() { tracker.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close blocked on the kevent/sampler loops")
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}
```

**Step 2: Run to verify failure**

Run: `GOWORK=off go test -tags integration ./internal/exec/ -run TestDescendantTracker -v`
Expected: compile FAIL — `newDescendantTracker` undefined.

**Step 3: Implement**

`internal/exec/process_descendants_darwin.go`:

```go
//go:build darwin

package exec

import (
	"errors"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// descendantSampleInterval paces the kern.proc.all closure sampler. A
	// NOTE_FORK kevent on any member triggers an immediate extra sample.
	descendantSampleInterval = 100 * time.Millisecond
	// wakeIdent is the EVFILT_USER identity used to unblock the kevent loop
	// on close. Any constant works; it only has to be stable within one kq.
	wakeIdent = 1
)

// descendantMember is one tracked process: pid plus the start-time identity
// that guards against pid reuse (a recycled pid is a different process and
// must never be signaled on this member's behalf).
type descendantMember struct {
	pid   int32
	start unix.Timeval
}

// descendantTracker follows one spawned process's fork tree, BEST-EFFORT.
//
// Darwin has no kernel fork-following: EVFILT_PROC NOTE_TRACK is rejected
// with ENOTSUP by XNU's filt_procattach (empirically verified 2026-08-06 on
// macOS 26.5.2; the constant exists in headers for FreeBSD compatibility
// only). So membership is discovered by sampling the process table
// (kern.proc.all) and growing the transitive closure rooted at the spawn —
// ppid-of-member or pgid-equals-member-pid joins — recorded permanently as
// (pid, start-time) so reparenting to launchd cannot erase a member. kqueue
// NOTE_FORK on members triggers immediate resampling to narrow the
// between-samples race; NOTE_EXIT retires members.
//
// Accepted gaps (why this is LifetimeContainmentBestEffort, never a proof):
//   - a descendant that double-forks AND leaves the group between two
//     samples, unobserved, is never discovered;
//   - a member whose pid is recycled before retirement is skipped at kill
//     time by the start-time identity check (fail-safe direction: prefer
//     missing an escapee to killing an innocent process);
//   - arming happens just after cmd.Start(), so a child forked in that
//     window is caught only by the first sample's closure walk (via its
//     ppid/pgid link), not by kevents.
type descendantTracker struct {
	mu      sync.Mutex
	kq      int
	members map[int32]descendantMember
	watched map[int32]bool // kevent registration succeeded for this member
	closed  bool
	resample chan struct{} // NOTE_FORK → immediate sample request
	stop     chan struct{}
	loops    sync.WaitGroup
	rootPID  int32
	forkNote bool // NOTE_FORK accepted by this kernel (degrades if not)
}

func newDescendantTracker() (*descendantTracker, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(kq)
	tracker := &descendantTracker{
		kq:       kq,
		members:  make(map[int32]descendantMember),
		watched:  make(map[int32]bool),
		resample: make(chan struct{}, 1),
		stop:     make(chan struct{}),
	}
	// Registering the wake event first means close() can always deliver it —
	// closing a kqueue fd does NOT unblock a parked Kevent call.
	_, err = unix.Kevent(kq, []unix.Kevent_t{{
		Ident: wakeIdent, Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_CLEAR,
	}}, nil, nil)
	if err != nil {
		_ = unix.Close(kq)
		return nil, err
	}
	return tracker, nil
}

// arm begins tracking pid (which must already exist — call after cmd.Start())
// and starts the sampler and kevent loops.
func (tracker *descendantTracker) arm(pid int) error {
	if tracker == nil {
		return errors.New("sandbox: nil descendant tracker")
	}
	tracker.rootPID = int32(pid)
	if start, ok := processStartTime(int32(pid)); ok {
		tracker.mu.Lock()
		tracker.members[int32(pid)] = descendantMember{pid: int32(pid), start: start}
		tracker.mu.Unlock()
	}
	tracker.watch(int32(pid))
	tracker.sample() // synchronous first sample: catch pre-arm forks now
	tracker.loops.Add(2)
	go tracker.runKevents()
	go tracker.runSampler()
	return nil
}

// watch registers NOTE_FORK|NOTE_EXIT (or NOTE_EXIT alone once a kernel has
// rejected NOTE_FORK) for pid. Failure is recorded, not fatal: sampling
// still covers the member.
func (tracker *descendantTracker) watch(pid int32) {
	fflags := uint32(unix.NOTE_EXIT)
	tracker.mu.Lock()
	forkNote := tracker.forkNote
	tracker.mu.Unlock()
	if forkNote {
		fflags |= unix.NOTE_FORK
	}
	_, err := unix.Kevent(tracker.kq, []unix.Kevent_t{{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_CLEAR,
		Fflags: fflags,
	}}, nil, nil)
	if err == syscall.ENOTSUP && forkNote {
		// Kernel without NOTE_FORK: degrade to NOTE_EXIT-only permanently.
		tracker.mu.Lock()
		tracker.forkNote = false
		tracker.mu.Unlock()
		tracker.watch(pid)
		return
	}
	tracker.mu.Lock()
	tracker.watched[pid] = err == nil
	tracker.mu.Unlock()
}

func (tracker *descendantTracker) runKevents() {
	defer tracker.loops.Done()
	events := make([]unix.Kevent_t, 16)
	for {
		n, err := unix.Kevent(tracker.kq, nil, events, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return
		}
		for _, event := range events[:n] {
			switch {
			case event.Filter == unix.EVFILT_USER:
				return // close() woke us
			case event.Filter != unix.EVFILT_PROC:
				continue
			case event.Fflags&unix.NOTE_EXIT != 0:
				tracker.mu.Lock()
				delete(tracker.members, int32(event.Ident))
				delete(tracker.watched, int32(event.Ident))
				tracker.mu.Unlock()
			case event.Fflags&unix.NOTE_FORK != 0:
				select {
				case tracker.resample <- struct{}{}:
				default:
				}
			}
		}
	}
}

func (tracker *descendantTracker) runSampler() {
	defer tracker.loops.Done()
	ticker := time.NewTicker(descendantSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-tracker.stop:
			return
		case <-tracker.resample:
		case <-ticker.C:
		}
		tracker.sample()
	}
}

// sample grows the member set to the current transitive closure rooted at
// the spawn. Iterates to fixpoint within one snapshot so a whole fork chain
// appearing between samples is captured at once.
func (tracker *descendantTracker) sample() {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return // sampling is best-effort; the next tick retries
	}
	tracker.mu.Lock()
	memberPIDs := make(map[int32]struct{}, len(tracker.members)+1)
	for pid := range tracker.members {
		memberPIDs[pid] = struct{}{}
	}
	memberPIDs[tracker.rootPID] = struct{}{} // root anchors even pre-membership
	tracker.mu.Unlock()

	var added []int32
	for {
		grew := false
		for i := range procs {
			pid := procs[i].Proc.P_pid
			if _, known := memberPIDs[pid]; known {
				continue
			}
			_, parentKnown := memberPIDs[procs[i].Eproc.Ppid]
			_, groupKnown := memberPIDs[procs[i].Eproc.Pgid]
			if parentKnown || groupKnown {
				memberPIDs[pid] = struct{}{}
				added = append(added, pid)
				grew = true
			}
		}
		if !grew {
			break
		}
	}
	if len(added) == 0 {
		return
	}
	tracker.mu.Lock()
	for i := range procs {
		pid := procs[i].Proc.P_pid
		for _, addedPID := range added {
			if pid == addedPID {
				tracker.members[pid] = descendantMember{pid: pid, start: procs[i].Proc.P_starttime}
			}
		}
	}
	tracker.mu.Unlock()
	for _, pid := range added {
		tracker.watch(pid)
	}
}

// liveMembers returns the currently tracked members (tests + teardown).
func (tracker *descendantTracker) liveMembers() []descendantMember {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	members := make([]descendantMember, 0, len(tracker.members))
	for _, member := range tracker.members {
		members = append(members, member)
	}
	return members
}

// injectMemberForTest plants a member entry with an arbitrary start-time so
// tests can prove the identity guard. Test seam only.
func (tracker *descendantTracker) injectMemberForTest(pid int32, start syscall.Timeval) {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.members[pid] = descendantMember{pid: pid, start: unix.Timeval{Sec: start.Sec, Usec: start.Usec}}
}

// memberAlive reports whether member still refers to the same live,
// non-zombie process it was recorded as. Absent, recycled (start-time
// mismatch), or zombie ⇒ gone.
func memberAlive(member descendantMember) bool {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", int(member.pid))
	if err != nil || info == nil {
		return false
	}
	if info.Proc.P_starttime != member.start {
		return false // recycled pid — a different process; hands off
	}
	return info.Proc.P_stat != darwinZombieState
}

func processStartTime(pid int32) (unix.Timeval, bool) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil || info == nil {
		return unix.Timeval{}, false
	}
	return info.Proc.P_starttime, true
}

// killAndAwaitZero SIGKILLs the process group and every identity-verified
// live member, polling until the group is inactive and no member remains.
// One final sample runs first so descendants forked just before teardown are
// included. Zombies count as gone (their reaper is launchd once the tree's
// parents are dead; waiting on a corpse would stall the proof forever).
func (tracker *descendantTracker) killAndAwaitZero(pgid int) {
	tracker.sample()
	for {
		if pgid > 0 {
			reapProcessGroup(pgid)
		}
		groupActive := false
		if pgid > 0 {
			var err error
			groupActive, err = processGroupActive(pgid)
			if err != nil {
				groupActive = true // no evidence of absence — keep going
			}
		}
		anyMember := false
		for _, member := range tracker.liveMembers() {
			if !memberAlive(member) {
				tracker.mu.Lock()
				delete(tracker.members, member.pid)
				tracker.mu.Unlock()
				continue
			}
			anyMember = true
			_ = syscall.Kill(int(member.pid), syscall.SIGKILL)
		}
		if !groupActive && !anyMember {
			return
		}
		if pgid > 0 {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
		time.Sleep(time.Millisecond)
	}
}

func (tracker *descendantTracker) close() {
	tracker.mu.Lock()
	if tracker.closed {
		tracker.mu.Unlock()
		return
	}
	tracker.closed = true
	tracker.mu.Unlock()
	close(tracker.stop)
	// Wake the kevent loop, join both loops, then release the kqueue.
	_, _ = unix.Kevent(tracker.kq, []unix.Kevent_t{{
		Ident: wakeIdent, Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER,
	}}, nil, nil)
	tracker.loops.Wait()
	_ = unix.Close(tracker.kq)
}
```

Implementation notes for the executor:
- `unix.Timeval` comparison: `Timeval` is a comparable struct (`Sec`, `Usec`) — `!=` works. If the compiler disagrees on this x/sys version, compare fields.
- `Eproc.Ppid`/`Eproc.Pgid` field names: verify against `unix.KinfoProc` in the module cache (`go doc golang.org/x/sys/unix.Eproc`); adjust casts (`int32`) as the real types dictate. `Proc.P_pid` and `P_starttime` are already used implicitly via `process_group_state_darwin.go`'s `P_stat` precedent.
- The `pgid`-join rule uses "pgid equals a *member's pid*" (a new group's leader is a member; its group id is its own pid). That is deliberate: it catches in-group forks AND new groups created by members via setpgid/setsid.
- Sampling while holding no lock during `SysctlKinfoProcSlice` (it can be slow) — the sketch above already does this; keep it that way.
- If `kern.proc.all` needs a zero arg on this x/sys version, it's `unix.SysctlKinfoProcSlice("kern.proc.all")` — no extra args (compare: the pgrp call passes one). Verify with `go doc`.

**Step 4: Run tests**

Run: `GOWORK=off go test -tags integration ./internal/exec/ -run TestDescendantTracker -v`
Expected: PASS (5 tests). `TestDescendantTrackerKillsSessionEscapee` is the load-bearing one.
Run: `GOWORK=off go vet ./internal/exec/` → clean.
Run: `GOWORK=off go test ./internal/exec/` → PASS (nothing untagged touched).

**Step 5: Commit**

```bash
git add internal/exec/process_descendants_darwin.go internal/exec/process_descendants_darwin_test.go
git commit -m "feat: best-effort darwin descendant tracking via proc-table closure"
```

---

### Task 3: `LifetimeContainment` vocabulary + optional interfaces

**Files:**
- Create: `internal/exec/lifetime_containment.go` (platform-neutral — NO build tag; Windows compiles it too)
- Modify: `sandbox.go` (aliases)

**Step 1: Implement**

`internal/exec/lifetime_containment.go`:

```go
package exec

// LifetimeContainment reports which process-tree teardown contract a
// Supervised spawn actually received — achieved enforcement, not requested
// policy (the same honesty rule as profile.Guarantees).
type LifetimeContainment uint8

const (
	// LifetimeContainmentUnspecified (zero value): the spawn carries no
	// lifetime containment claim at all — an Unconfined/null-backend or
	// test-double spawn, whose teardown is the escapable process-group
	// signal-and-poll sweep. Deliberately NOT Enforced: reporting kernel
	// enforcement for a spawn that has none would violate the honesty rule.
	LifetimeContainmentUnspecified LifetimeContainment = iota
	// LifetimeContainmentEnforced: the kernel itself guarantees teardown —
	// Linux Rung 1 PID namespace, Linux Rung 2 delegated cgroup v2, or a
	// Windows Job. No descendant can escape it.
	LifetimeContainmentEnforced
	// LifetimeContainmentBestEffort: teardown is process-group SIGKILL plus
	// proc-table closure descendant tracking (Darwin Seatbelt). A descendant
	// that daemonizes through a tracking gap can survive as an orphan —
	// still fully confined by the spawn's Seatbelt profile, but outliving
	// the session. See docs/lifetime-containment.md.
	LifetimeContainmentBestEffort
)

func (c LifetimeContainment) String() string {
	switch c {
	case LifetimeContainmentEnforced:
		return "enforced"
	case LifetimeContainmentBestEffort:
		return "best-effort"
	default:
		return "unspecified"
	}
}

// lifetimeReporter is the single optional self-description seam: a
// zeroProver that knows its contract implements it, and each platform's
// process tree implements it to surface the spawn-level answer
// (process_tree_unix.go delegates to its proof; process_tree_windows.go
// answers Enforced). process.go type-asserts the processTreeBoundary —
// never widen processTreeBoundary itself (the test fakes would break).
type lifetimeReporter interface {
	lifetimeContainment() LifetimeContainment
}

// pidArmer is the optional post-Start hook a zeroProver can carry; a prover
// that must observe the live root pid (the darwin descendant tracker)
// implements it and processTree.start invokes it right after cmd.Start().
type pidArmer interface {
	armPID(pid int) error
}
```

`sandbox.go` — add to the type-alias block next to the other `Process*` aliases (after `ProcessSignal`, ~line 287):

```go
	// LifetimeContainment reports the process-tree teardown contract a
	// Supervised spawn actually received (enforced / best-effort /
	// unspecified). See Process.LifetimeContainment.
	LifetimeContainment = exec.LifetimeContainment
```

and a constants block next to the `ProcessSignal` values block (~line 308):

```go
// LifetimeContainment values.
const (
	LifetimeContainmentUnspecified = exec.LifetimeContainmentUnspecified
	LifetimeContainmentEnforced    = exec.LifetimeContainmentEnforced
	LifetimeContainmentBestEffort  = exec.LifetimeContainmentBestEffort
)
```

**Step 2: Build all platforms**

Run: `GOWORK=off go build ./...` → OK.
Run: `GOWORK=off GOOS=linux GOARCH=amd64 go build ./...` → OK.
Run: `GOWORK=off GOOS=windows GOARCH=amd64 go build ./...` → OK.
(`lifetimeReporter`/`pidArmer` are unreferenced until Task 4 — Go allows unused package-level declarations; only unused imports/locals fail.)

**Step 3: Commit**

```bash
git add internal/exec/lifetime_containment.go sandbox.go
git commit -m "feat: add LifetimeContainment vocabulary"
```

---

### Task 4: Darwin prover — replace the unconditional rejection

**Files:**
- Modify: `internal/exec/process_tree_darwin.go` (the core change — full replacement below)
- Modify: `internal/exec/process_tree_unix.go` (arm seam in `start`; `lifetimeReporter` on `*processTree`)
- Modify: `internal/exec/process_tree_windows.go` (`lifetimeReporter` on its tree type → `Enforced`)
- Test: `internal/exec/process_tree_darwin_test.go` (flip rejection subtests; keep scoping subtests)

**Step 1: Update/flip the darwin unit tests**

`process_tree_darwin_test.go` (`process_tree_darwin_test.go:29–99`, five subtests): the subtests asserting `(nil, ErrLifetimeContainmentUnavailable)` for the real backend flip; the nil-backend/fake-backend scoping subtests (attach nothing, no error) survive unchanged. New expectations:

```go
func TestAttachSupervisedProofSeatbeltBestEffort(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	proof, err := attachSupervisedProof(cmd, processTreeOptions{
		Supervised: true,
		Backend:    darwin.NewBackend(),
	})
	if err != nil {
		t.Fatalf("attachSupervisedProof: %v", err)
	}
	if proof == nil {
		t.Fatal("expected a best-effort prover, got nil")
	}
	reporter, ok := proof.(lifetimeReporter)
	if !ok || reporter.lifetimeContainment() != LifetimeContainmentBestEffort {
		t.Fatal("prover must report best-effort containment")
	}
	if _, ok := proof.(pidArmer); !ok {
		t.Fatal("prover must be armable post-Start")
	}
	proof.close()
}
```

Also add a `*processTree`-level test (platform-neutral semantics, darwin file is fine):

```go
func TestProcessTreeLifetimeDelegation(t *testing.T) {
	// nil proof → Unspecified; reporter proof → its answer.
	tree := &processTree{}
	if got := tree.lifetimeContainment(); got != LifetimeContainmentUnspecified {
		t.Fatalf("nil-proof tree = %v, want unspecified", got)
	}
}
```

**Step 2: Run to verify failure**

Run: `GOWORK=off go test ./internal/exec/ -run 'TestAttachSupervisedProof|TestProcessTreeLifetime' -v`
Expected: FAIL — current code returns `ErrLifetimeContainmentUnavailable`; `lifetimeContainment` undefined on the tree.

**Step 3: Implement**

**(a)** Replace `internal/exec/process_tree_darwin.go` entirely. Final import block: `os/exec`, `reflect`, `syscall`, `github.com/looprig/sandbox/internal/darwin` — the `enforce` import GOES AWAY (unused import = compile error). Keep `darwinBackendType` as is. New content after it:

```go
// darwinBestEffortProof is the Darwin Supervised zeroProver: process-group
// SIGKILL-and-poll plus proc-table-closure descendant kills
// (descendantTracker, process_descendants_darwin.go). BEST-EFFORT by design:
// macOS has no kernel-enforced tree-teardown primitive available to an
// unentitled process (NOTE_TRACK is ENOTSUP; Endpoint Security needs an
// Apple-granted entitlement), and the project accepted the downgrade
// (2026-08-06) because Seatbelt access confinement is inherited by every
// descendant — a lifetime escapee is an orphaned but still-sandboxed
// process, not an access-control hole. The downgrade is reported per spawn:
// lifetimeContainment() answers LifetimeContainmentBestEffort, surfaced as
// Process.LifetimeContainment. See docs/lifetime-containment.md.
type darwinBestEffortProof struct {
	cmd     *exec.Cmd
	tracker *descendantTracker
}

func (p *darwinBestEffortProof) lifetimeContainment() LifetimeContainment {
	return LifetimeContainmentBestEffort
}

func (p *darwinBestEffortProof) armPID(pid int) error {
	if p == nil || p.tracker == nil {
		return nil
	}
	return p.tracker.arm(pid)
}

func (p *darwinBestEffortProof) terminateAndWait() (error, error) {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil, nil
	}
	pgid := p.cmd.Process.Pid
	if pgid <= 0 {
		return nil, nil
	}
	if p.tracker != nil {
		p.tracker.killAndAwaitZero(pgid)
		return nil, nil
	}
	// Tracker unavailable (construction or arm failed): plain group sweep.
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	signalAndPollProcessGroupZero(pgid, func(sig syscall.Signal) error {
		err := syscall.Kill(-pgid, sig)
		if err == syscall.ESRCH {
			return nil
		}
		return err
	})
	return nil, nil
}

func (p *darwinBestEffortProof) close() {
	if p != nil && p.tracker != nil {
		p.tracker.close()
	}
}

// attachSupervisedProof attaches Darwin's best-effort prover to every real
// Seatbelt-backed Supervised spawn. Scoping mirrors Linux: an Unconfined
// executor or a pinned test backend makes no Darwin containment claim, so it
// attaches nothing (and the spawn reports LifetimeContainmentUnspecified).
func attachSupervisedProof(cmd *exec.Cmd, options processTreeOptions) (zeroProver, error) {
	if options.Backend == nil || reflect.TypeOf(options.Backend) != darwinBackendType {
		return nil, nil
	}
	tracker, err := newDescendantTracker()
	if err != nil {
		// Tracker construction failing (fd exhaustion) degrades to the plain
		// group sweep rather than blocking the spawn: the tracker only ever
		// narrows the best-effort gap; it is not the containment itself.
		tracker = nil
	}
	return &darwinBestEffortProof{cmd: cmd, tracker: tracker}, nil
}
```

**(b)** `process_tree_unix.go` — arm after start, and implement `lifetimeReporter`:

```go
func (tree *processTree) start(cmd *exec.Cmd) error {
	if tree == nil || cmd == nil || cmd != tree.cmd {
		return errors.New("sandbox: invalid command process tree")
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	tree.pgid = cmd.Process.Pid
	if armer, ok := tree.proof.(pidArmer); ok {
		// Arm failure only widens the best-effort gap; the spawn is already
		// running and group teardown still applies (the prover's own
		// tracker-nil fallback).
		_ = armer.armPID(cmd.Process.Pid)
	}
	return nil
}

// lifetimeContainment surfaces the spawn's teardown contract: the proof's
// own answer when it has one, Enforced for any other non-nil proof (the
// Linux namespace/cgroup provers are kernel-enforced by construction), and
// Unspecified for a proofless tree (Unconfined/null/test backends — the
// escapable group sweep makes no containment claim).
func (tree *processTree) lifetimeContainment() LifetimeContainment {
	if tree == nil || tree.proof == nil {
		return LifetimeContainmentUnspecified
	}
	if reporter, ok := tree.proof.(lifetimeReporter); ok {
		return reporter.lifetimeContainment()
	}
	return LifetimeContainmentEnforced
}
```

**(c)** `process_tree_windows.go`: add to its process-tree type (the one returned by its `newProcessTree` — find the concrete type in that file):

```go
// lifetimeContainment: a Windows supervised spawn lives in a Job with
// kill-on-close; teardown is kernel-enforced.
func (tree *windowsProcessTree) lifetimeContainment() LifetimeContainment {
	return LifetimeContainmentEnforced
}
```

(Use the file's real type name; if the Windows boundary distinguishes Job-attached vs not, answer `Enforced` only for the Job-attached case and `Unspecified` otherwise — mirror however the file models it and say so in the method comment.)

**Step 4: Run tests — including integration**

Run: `GOWORK=off go test ./internal/exec/ -run 'TestAttachSupervisedProof|TestProcessTreeLifetime' -v` → PASS.
Run: `GOWORK=off go test ./internal/exec/` → PASS.
Run: `GOWORK=off go test ./...` → **EXPECTED FAILURES in `facade_test.go` (root package)** — it hard-asserts the old rejection (lines 198–241). That flip is Task 5's job; do NOT paper over it here, and do NOT mark this task done claiming full-suite green. Record the failure in the task notes.
Run: `GOWORK=off go test -tags integration ./internal/exec/` → **EXPECTED FAILURES** in `process_pty_integration_unix_test.go` and `process_parent_death_integration_unix_test.go` (they assert the old rejection) — Task 6 flips them. Everything else must pass.
Cross-compile: `GOWORK=off GOOS=linux GOARCH=amd64 go build ./...` and `GOWORK=off GOOS=windows GOARCH=amd64 go build ./...` → OK.

**Step 5: Commit**

```bash
git add internal/exec/
git commit -m "feat: best-effort supervised lifetime containment on darwin"
```

---

### Task 5: Surface `LifetimeContainment` on `Process` + flip `facade_test.go`

**Files:**
- Modify: `internal/exec/process.go` (accessor; plumb from the tree)
- Modify: `facade_test.go` (root package — flip the darwin rejection assertions)
- Test: `internal/exec/process_test.go` (new unit test)

**Step 1: Write failing unit test**

In `process_test.go`, using the file's real pattern (`newProcessTestExecutor(t, Allow)` builds an **Unconfined/null-backend** executor — so the honest answer is `Unspecified`, NOT `Enforced`):

```go
func TestProcessLifetimeContainmentUnconfinedUnspecified(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: t.TempDir(),
		Command:   "echo ready",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = proc.Close(context.Background()) }()
	if got := proc.LifetimeContainment(); got != LifetimeContainmentUnspecified {
		t.Fatalf("LifetimeContainment() = %v, want unspecified (null backend makes no claim)", got)
	}
}
```

(Match `PrepareProcess`/`Start`/`Close` signatures and `ProcessOptions` fields to the file's existing tests at `process_test.go:102–130` — copy a neighboring test's construction verbatim and change only the assertion.)

**Step 2: Run to verify failure**

Run: `GOWORK=off go test ./internal/exec/ -run TestProcessLifetimeContainment -v`
Expected: compile FAIL — `LifetimeContainment` method undefined on `*Process`.

**Step 3: Implement in `process.go`**

- Add a field to `Process` (near its other spawn-time-fixed fields): `lifetime LifetimeContainment`.
- In `startConfined` and `startConfinedTTY`, after the tree is obtained (both hold it as `processTreeBoundary`): 

```go
	lifetime := LifetimeContainmentUnspecified
	if reporter, ok := tree.(lifetimeReporter); ok {
		lifetime = reporter.lifetimeContainment()
	}
```

  and thread `lifetime` into the `Process` literal each path constructs. (`startConfinedTTY` receives the tree from `startConfined` — `process.go:899` — compute once in `startConfined` before the TTY branch at `process.go:801` and pass it along, or recompute; either is fine, say which in a short comment.)
- `startBackendOwned` (Windows elevated broker — Job-backed): set `lifetime: LifetimeContainmentEnforced` explicitly with a one-line comment (broker Job teardown).
- Accessor:

```go
// LifetimeContainment reports the process-tree teardown contract this spawn
// actually received: Enforced (Linux namespace/cgroup, Windows Job),
// BestEffort (Darwin Seatbelt — see docs/lifetime-containment.md), or
// Unspecified (an Unconfined/null-backend spawn making no claim).
func (p *Process) LifetimeContainment() LifetimeContainment {
	if p == nil {
		return LifetimeContainmentUnspecified
	}
	return p.lifetime
}
```

The `sandbox.go` `Process` alias re-exports methods automatically — no facade change needed beyond Task 3's aliases.

**Step 4: Flip `facade_test.go`**

`facade_test.go:198–241`: the darwin branch currently asserts `prepared.Start` fails with `ErrLifetimeContainmentUnavailable`, returns nil, and `Wait` on the nil Process yields `ErrProcessClosed`. Rewrite: darwin now takes the same success path as other platforms — and since this untagged test will now spawn a real Seatbelt-confined process on dev Macs (sandbox-exec is present on every macOS install; this is deliberate and acceptable — it is the facade's job to prove the public surface), additionally assert `proc.LifetimeContainment() == LifetimeContainmentBestEffort` on darwin. Keep the sentinel map at `facade_test.go:297` intact (`ErrLifetimeContainmentUnavailable` remains a real, reachable sentinel — on Linux Rung 2 without a delegated cgroup); add the three new `LifetimeContainment*` constants to the facade-surface assertions if the file's style pins exported symbols.

**Step 5: Run tests**

Run: `GOWORK=off go test ./internal/exec/ -run TestProcessLifetimeContainment -v` → PASS.
Run: `GOWORK=off go test ./...` → PASS — the Task 4 facade failure is now resolved; nothing else may be red.
Cross-compile: `GOWORK=off GOOS=windows GOARCH=amd64 go build ./...` and `GOOS=linux` → OK.

**Step 6: Commit**

```bash
git add internal/exec/ facade_test.go
git commit -m "feat: report per-spawn lifetime containment on Process"
```

---

### Task 6: Flip the integration tests that encoded the rejection

**Files:**
- Modify: `internal/exec/process_pty_integration_unix_test.go`
- Modify: `internal/exec/process_parent_death_integration_unix_test.go`
- Modify: `internal/exec/process_grant_integration_test.go`
- Create: `internal/exec/process_supervised_darwin_integration_test.go` (`//go:build darwin && integration`)

**Step 1: Per-file rewrites**

1. `process_pty_integration_unix_test.go`:
   - DELETE `TestIntegrationProcessPTYDarwinLifetimeUnavailable` (lines 144–185) — the contract it proves no longer exists.
   - Lines 77–98: remove the darwin skip-on-unavailable branches; the PTY tests now run for real under Seatbelt on darwin. Expect them to pass; any Seatbelt denial surfacing here (e.g. `/dev/ptmx` access) is a REAL finding — investigate the SBPL profile rather than re-adding skips, and if a profile gap is found, stop and surface it (do not silently allow-list without review).
2. `process_parent_death_integration_unix_test.go`:
   - Lines 117–124: darwin branch asserting `Start` fails pre-spawn — delete; darwin joins the common path.
   - Lines 250–302 (the escape-proof test's darwin carve-out): rewrite so darwin asserts the NEW behavior — after teardown, the in-group tree is gone AND a tracked setsid escapee is also gone (this is precisely what the descendant tracker claims). If the existing test's escapee spawns too fast for discovery, gate on the tracker having seen it first (pattern from Task 2's `awaitMembers`). Keep the Linux side untouched.
3. `process_grant_integration_test.go` (lines 30, 95): remove the darwin skip branches; the grant lifecycle now runs under Seatbelt on darwin **for the first time** — expected to pass, but treat failures as real findings about the grant/Seatbelt interaction, not as reasons to restore the skip.
4. New `process_supervised_darwin_integration_test.go`:

```go
//go:build darwin && integration

package exec
```

   - `TestSupervisedSeatbeltSpawnStarts` — build a real Sandboxed executor exactly the way `acceptance_darwin_test.go` does (reuse its helper if exported within the package; otherwise copy its construction), `PrepareProcess` a `/bin/sh -c 'echo ready; read line'` with pipes, `Start`, assert: no error (in particular not `ErrLifetimeContainmentUnavailable`), stdout yields `ready`, and `proc.LifetimeContainment() == LifetimeContainmentBestEffort`. Close stdin → `Wait` → `Close`.
   - `TestSupervisedSeatbeltTeardownKillsDescendants` — spawn `/bin/sh -c '(sleep 300 &); sleep 300'`; find the in-group descendant via `unix.SysctlKinfoProcSlice("kern.proc.pgrp", pgid)`; then `proc.Signal(context.Background(), ProcessSignalKill)` and `Close`; assert every found pid answers `kill(pid, 0) == ESRCH`. (The setsid-escapee variant stays at the tracker level in Task 2 — under Seatbelt, perl may be denied by the profile; note that split in the test comment.)

**Step 2: Run**

Run: `GOWORK=off go test -tags integration ./internal/exec/ -v 2>&1 | tee /tmp/integration.log` — then READ the log:
- All tests PASS.
- The new darwin tests RUN (output shows `RUN`/`PASS`, not `SKIP`). **Darwin skip ≠ pass** is a standing project rule.
- No lingering `sleep 300` processes afterward: `pgrep -f 'sleep 300'` → empty.

**Step 3: Commit**

```bash
git add internal/exec/
git commit -m "test: prove confined supervised spawns and teardown on darwin"
```

---

### Task 7: Full-suite verification checkpoint

**Step 1:** `GOWORK=off go test ./...` → all PASS.
**Step 2:** `GOWORK=off go test -tags integration ./internal/exec/` → all PASS, no skips on darwin.
**Step 3:** `GOWORK=off go vet ./...` → clean.
**Step 4:** Cross-compile `GOOS=linux GOARCH=amd64` and `GOOS=windows GOARCH=amd64` → OK.
**Step 5:** Grep for stragglers: `grep -rn "ErrLifetimeContainmentUnavailable" --include='*_test.go' .` — every remaining reference must be about Linux Rung 2 or the sentinel's continued existence, none about darwin rejection.

No commit (verification only). If anything is red, fix within the responsible earlier task's scope before proceeding.

---

### Task 8: Comments, SPEC, and docs (post-implementation, per user direction)

**Files (every one enumerated — the review found stale prose in all of these):**
- `internal/exec/process_tree_darwin.go` — already rewritten in Task 4; re-read and confirm no stale "rejects unconditionally" language survives.
- `internal/enforce/enforce.go:15–30` — `ErrLifetimeContainmentUnavailable` doc: drop "and the Darwin backend unconditionally until a real containment primitive exists (Task 12c)"; the sentinel's remaining concrete caller is Linux Rung 2 with no delegated cgroup ancestor. Cross-reference `LifetimeContainment` for the darwin story.
- `sandbox.go` `ErrLifetimeContainmentUnavailable` alias doc (~line 330): same correction.
- `init_other.go:11–18` — "PreparedProcess.Start rejects every Supervised … spawn" is now false for darwin; reword (that file describes non-Linux platforms generally — split darwin from windows/other accurately).
- `internal/exec/lifetime_unix.go:19–24` — "Darwin has none yet, so its attachSupervisedProof … rejects every Supervised spawn unconditionally" → describe the best-effort prover instead.
- `internal/exec/process.go:887–898` — `startConfinedTTY` doc references "Darwin's fail-closed Seatbelt rejection" and the deleted `TestIntegrationProcessPTYDarwinLifetimeUnavailable`; rewrite.
- `internal/exec/process_tree_unix.go:15–25, 107–120` — `processTree.proof` and `terminateAndWait` docs: "every spawn on a platform with no exact mechanism wired yet" narrative → three-way story (exact proof / best-effort prover / proofless sweep).
- `SPEC.md` §7 (starts line 270, "Guarantees and platform behavior"): add a short normative paragraph in SPEC voice — macOS Supervised spawns receive best-effort lifetime containment (process-group teardown plus process-table-closure descendant tracking); the downgrade is reported per spawn via `LifetimeContainment`; access-confinement guarantees are unaffected; Linux and Windows retain kernel-enforced teardown; the earlier fail-closed posture (Task 12c) is superseded by the 2026-08-06 acceptance decision.
- Create `docs/lifetime-containment.md` — one page: the three contract values; per-platform matrix (Linux Rung 1 = PID namespace, Rung 2 = delegated cgroup, Windows = Job → all Enforced; Darwin Seatbelt = BestEffort and exactly why — NOTE_TRACK ENOTSUP, Endpoint Security entitlement-gated); the darwin mechanism (closure sampling + NOTE_FORK acceleration + identity-guarded kills) and its accepted gaps; implications for callers (orphaned-but-still-sandboxed processes, port/lock squatting, post-stop workspace writes); guidance (callers hosting long-lived children on darwin should surface `LifetimeContainment` to their own users). README.md and SPEC.md contain no OTHER darwin-rejection language (verified in review) — no further sweep needed beyond the list above.

**Step 1: Write all doc changes.** SPEC wording stays short and normative like its neighbors.

**Step 2: Verify**

Run: `GOWORK=off go build ./... && GOWORK=off go test ./internal/exec/ ./internal/enforce/ .` → PASS (comments only — this catches accidental code edits).
Grep: `grep -rn "unconditionally" internal/ init_other.go` → no stale rejection language.

**Step 3: Commit**

```bash
git add internal/ init_other.go sandbox.go SPEC.md docs/lifetime-containment.md
git commit -m "docs: document darwin best-effort lifetime containment"
```

---

### Task 9: Final sweep + Linux-box flag

**Step 1:** Repeat Task 7's four green gates one final time on the finished branch.
**Step 2:** `git log --oneline feat/long-running-commands..HEAD` — confirm the commit sequence tells the story cleanly.
**Step 3:** **Flag for the Linux box (do not skip):** `process_tree_unix.go` and `process.go` (shared files) changed — the module's `//go:build linux` + integration tests must be run on the user's Ubuntu host before release-tagging. Darwin skip ≠ pass. State this explicitly in the final report as an open follow-up; do not claim Linux verification from this machine.
**Step 4:** Report done, with: what shipped, the honest-reporting semantics, the accepted darwin gaps, and the two follow-ups (Linux-box run; ACP-child wiring as the consuming feature).

---

## Out of scope (deliberate)

- Wiring the ACP child (coderig/foreignloops) onto `PrepareProcess` — separate plan; this unblocks it on darwin.
- Endpoint Security–based exact containment (needs an Apple entitlement) — `docs/lifetime-containment.md` records it as the only known path to `Enforced` on darwin.
- Any change to Linux/Windows containment semantics (Windows only gains the `lifetimeContainment()` self-description).
- Guarantee *bits* (`profile.GuaranteeProcessBoundary` etc.) — those describe access enforcement; lifetime is reported per spawn via `LifetimeContainment` instead.

## Review provenance

Independently reviewed against the codebase on 2026-08-06 (adversarial subagent, empirical kqueue probes on macOS 26.5.2). Material findings incorporated: NOTE_TRACK is unsupported on darwin (BLOCKER — mechanism redesigned to poll-closure + NOTE_FORK acceleration); `facade_test.go` and three integration files enumerated for explicit flips; nil-proof Supervised spawns report `Unspecified`, not `Enforced`; tree→Process plumbing specified via a single `lifetimeReporter` optional interface (never widening `processTreeBoundary`); `Process.Signal(ctx, kind)` signature corrected; four additional stale-comment sites added to the doc sweep; darwin prover import block specified; invented test helper replaced with the file's real construction pattern.
