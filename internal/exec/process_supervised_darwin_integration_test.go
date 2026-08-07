//go:build darwin && integration

package exec

import (
	"context"
	"errors"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
	"golang.org/x/sys/unix"
)

// This file is Task 6's darwin-only proof that a real Seatbelt-confined
// Supervised spawn now actually starts and tears down, rather than failing
// closed: the 2026-08-06 best-effort containment decision
// (process_tree_darwin.go's attachSupervisedProof) attaches a best-effort
// process-tree teardown prover — the proc-table-closure descendant tracker,
// process_descendants_darwin.go — to every real Seatbelt-backed Supervised
// spawn instead of rejecting it with enforce.ErrLifetimeContainmentUnavailable.

// supervisedSeatbeltExecutor builds a real, async-capable Seatbelt executor
// through the production platform backend selector — the exact construction
// TestAcceptanceMatrixDarwin (acceptance_darwin_test.go) uses for its own
// real Seatbelt executor, via mustProfile + NewExecutorSet + ExecutorSet.For
// — so these tests exercise darwin's actual best-effort Supervised
// containment rather than a test double. HostRead is Allow so /bin/sh and
// sleep stay visible under Rung 1's restricted-read mount view, matching
// this package's other live async integration tests
// (integrationEscapeExecutor, process_parent_death_integration_unix_test.go).
func supervisedSeatbeltExecutor(t *testing.T, name string) (*ExecutorSet, *Executor, string) {
	t.Helper()
	requireSandboxExec(t)
	workspace := t.TempDir()
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	executor, err := set.For(name)
	if err != nil {
		_ = set.Close()
		t.Fatalf("ExecutorSet.For: %v", err)
	}
	return set, executor, workspace
}

// TestSupervisedSeatbeltSpawnStarts proves a real Seatbelt-confined
// Supervised spawn starts and runs for real on darwin: PrepareProcess/Start
// no longer reject with enforce.ErrLifetimeContainmentUnavailable (Task 4),
// the child's real stdout is observable, and the spawn self-reports exactly
// the containment level it actually achieved — LifetimeContainmentBestEffort
// — never Enforced (which darwin cannot honestly claim) and never
// Unspecified (which would misreport that no containment was attempted).
func TestSupervisedSeatbeltSpawnStarts(t *testing.T) {
	set, executor, workspace := supervisedSeatbeltExecutor(t, "supervised-spawn-starts")
	defer func() { _ = set.Close() }()

	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: "/bin/sh -c 'echo ready; read line'", ExecutionID: "supervised-spawn-starts",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		if errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Fatalf("Start: %v; darwin's best-effort prover should never report lifetime containment unavailable for a real Seatbelt spawn (Task 4)", err)
		}
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = proc.Close(context.Background()) }()

	if got := proc.LifetimeContainment(); got != LifetimeContainmentBestEffort {
		t.Fatalf("LifetimeContainment() = %v, want LifetimeContainmentBestEffort", got)
	}

	collected := make([]byte, 0, 64)
	buf := make([]byte, 64)
	for i := 0; i < 8; i++ {
		n, readErr := proc.Stdout().Read(buf)
		collected = append(collected, buf[:n]...)
		if strings.Contains(string(collected), "ready") || readErr != nil {
			break
		}
	}
	if !strings.Contains(string(collected), "ready") {
		t.Fatalf("stdout = %q, want it to contain %q", string(collected), "ready")
	}

	if _, err := proc.Stdin().Write([]byte("\n")); err != nil {
		t.Fatalf("Stdin.Write: %v", err)
	}
	if err := proc.Stdin().Close(); err != nil {
		t.Fatalf("Stdin.Close: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := proc.Wait(ctx); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if err := proc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

// pollProcessGoneESRCH polls kill(pid, 0) for every pid in pids until each
// answers syscall.ESRCH (no such process — fully reaped, not merely a
// zombie: the immediate child's own group members are direct children of
// this test binary and get reaped by the prover's reapProcessGroup, but a
// pid that reparents to launchd first, e.g. because it left the process
// group, is reaped by launchd on its own schedule) or timeout elapses.
func pollProcessGoneESRCH(t *testing.T, pids []int32, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		allGone := true
		var lastAlive int32
		var lastErr error
		for _, pid := range pids {
			err := syscall.Kill(int(pid), 0)
			if !errors.Is(err, syscall.ESRCH) {
				allGone = false
				lastAlive = pid
				lastErr = err
				break
			}
		}
		if allGone {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d still answers kill(pid, 0) with %v after teardown, want syscall.ESRCH", lastAlive, lastErr)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestSupervisedSeatbeltTeardownKillsDescendants proves a real Seatbelt-
// confined Supervised spawn's teardown reaches every descendant left in its
// Unix process group, not merely the immediate child: `(sleep 300 &)`
// backgrounds a subshell that stays in the run's process group (no setsid),
// so this is the plain group-signal containment every platform already had,
// now exercised for real on darwin's own backend for the first time. (The
// setsid-escapee variant — the descendant that LEAVES the process group,
// which only the new best-effort descendant tracker can reach — stays at the
// tracker level in Task 2's own tests, process_descendants_darwin_test.go,
// and at TestIntegrationProcessTreeDarwinSetsidEscapeContained
// (process_parent_death_integration_unix_test.go); under real Seatbelt
// confinement here, an unrelated helper like perl or setsid itself may be
// denied by the profile, so that variant is deliberately not repeated in
// this file.)
func TestSupervisedSeatbeltTeardownKillsDescendants(t *testing.T) {
	set, executor, workspace := supervisedSeatbeltExecutor(t, "supervised-teardown-descendants")
	defer func() { _ = set.Close() }()

	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: "/bin/sh -c '(sleep 300 &); sleep 300'", ExecutionID: "supervised-teardown-descendants",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if proc.cmd == nil || proc.cmd.Process == nil {
		t.Fatal("started Process has no underlying cmd.Process; cannot resolve its process group")
	}
	pgid := proc.cmd.Process.Pid

	// Poll for the group to grow to the shell plus its backgrounded sleep:
	// the fork is effectively synchronous from the shell's own perspective,
	// but this still gives the kernel a moment to publish the new process
	// table entry before this test relies on seeing it.
	var members []unix.KinfoProc
	discoverDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(discoverDeadline) {
		procs, sErr := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pgid)
		if sErr == nil && len(procs) >= 2 {
			members = procs
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(members) < 2 {
		t.Fatalf("only found %d process(es) in group %d before teardown, want the shell plus its backgrounded sleep", len(members), pgid)
	}
	pids := make([]int32, 0, len(members))
	for _, member := range members {
		pids = append(pids, member.Proc.P_pid)
	}

	if err := proc.Signal(context.Background(), ProcessSignalKill); err != nil {
		t.Fatalf("Signal(Kill): %v", err)
	}
	if err := proc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}

	pollProcessGoneESRCH(t, pids, 10*time.Second)
}
