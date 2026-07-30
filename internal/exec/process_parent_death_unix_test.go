//go:build darwin || linux

package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// This file exercises Task 12B's REAL Unix signal delivery end to end: a
// live spawned process, real SIGINT/SIGTERM/SIGKILL, and Process.Wait
// observing a prompt real exit. Task 12A's own signal state-machine tests
// (process_tree_signal_test.go) deliberately use a fake processSignalTarget
// and prove nothing about real OS delivery — that gap is exactly what
// lifetime_unix.go's sendInterrupt/sendTerminate/sendKill close, and this
// file is the proof. It runs on both darwin and linux natively (no root, no
// namespaces, no cgroups required): signal delivery is Unix-wide, not
// Linux-specific — only Task 12b's separate PID-namespace/cgroup CONTAINMENT
// work is Linux-only (see process_tree_linux_test.go).

// spawnSupervisedSleep starts a real, asynchronously supervised sleep of the
// given duration through the production PreparedProcess/Start path (the same
// path PrepareProcess/Start-based long-running command supervision uses),
// under a fast fake confinement backend (captureBackend, already used
// elsewhere in this package's async lifecycle tests) so the test needs no
// real OS confinement to exercise real OS signal delivery.
func spawnSupervisedSleep(t *testing.T, seconds int) (*Process, func()) {
	t.Helper()
	workspace := t.TempDir()
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(&captureBackend{
			bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		})))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("signal-delivery")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: portableSleepCommand(seconds), ExecutionID: "signal-delivery",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	return proc, func() { _ = proc.Close(context.Background()) }
}

// assertProcessDiesWithin proves the process actually reaches a terminal
// state well inside bound — the only way that can happen for a `sleep 30`
// (or `sleep 300`, for the group test below) target is that the signal was
// genuinely delivered by the OS, not merely accepted by Process.Signal's
// state machine and dropped.
func assertProcessDiesWithin(t *testing.T, proc *Process, bound time.Duration) ProcessResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	result, err := proc.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait after signal did not return within %s (signal was not really delivered): %v", bound, err)
	}
	return result
}

func TestUnixProcessSignalInterruptRealDelivery(t *testing.T) {
	proc, cleanup := spawnSupervisedSleep(t, 30)
	defer cleanup()
	if err := proc.Signal(context.Background(), ProcessSignalInterrupt); err != nil {
		t.Fatalf("Signal(Interrupt): %v", err)
	}
	result := assertProcessDiesWithin(t, proc, 5*time.Second)
	t.Logf("post-SIGINT result = %+v", result)
}

func TestUnixProcessSignalTerminateRealDelivery(t *testing.T) {
	proc, cleanup := spawnSupervisedSleep(t, 30)
	defer cleanup()
	if err := proc.Signal(context.Background(), ProcessSignalTerminate); err != nil {
		t.Fatalf("Signal(Terminate): %v", err)
	}
	// `sleep`'s default SIGTERM action is to exit immediately, so a real
	// delivery returns in milliseconds — well under the resolved terminate
	// grace period (5s default). If delivery were NOT real, only the grace
	// escalation to Kill would eventually stop it, which this bound (half the
	// default grace) is deliberately too tight to allow.
	result := assertProcessDiesWithin(t, proc, 2*time.Second)
	t.Logf("post-SIGTERM result = %+v", result)
}

func TestUnixProcessSignalKillRealDelivery(t *testing.T) {
	proc, cleanup := spawnSupervisedSleep(t, 30)
	defer cleanup()
	if err := proc.Signal(context.Background(), ProcessSignalKill); err != nil {
		t.Fatalf("Signal(Kill): %v", err)
	}
	result := assertProcessDiesWithin(t, proc, 5*time.Second)
	t.Logf("post-SIGKILL result = %+v", result)
}

// pidAlive reports whether pid still exists, using signal 0 (no signal sent,
// only existence/permission checked) — the standard Unix liveness probe.
func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	err := syscall.Kill(pid, 0)
	return err == nil || !errors.Is(err, syscall.ESRCH)
}

// TestUnixProcessSignalKillReachesProcessGroup proves Signal(Kill) is
// delivered to the whole Unix process group — not merely the immediate
// child — exactly like tree.terminate()/cmd.Cancel already guarantee for
// context cancellation (see process_tree_unix.go's signalGroup, which
// lifetime_unix.go's sendKill shares). The command backgrounds a grandchild
// sleep, records its real PID to a file, and blocks in the immediate child so
// the group id and the grandchild's pgid stay identical (no setsid/double
// fork here — that escape scenario is process_parent_death_integration_unix_test.go's
// job); this test only proves ordinary descendants are reached.
func TestUnixProcessSignalKillReachesProcessGroup(t *testing.T) {
	workspace := t.TempDir()
	pidFile := filepath.Join(workspace, "grandchild.pid")
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(&captureBackend{
			bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		})))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	defer func() { _ = set.Close() }()
	executor, err := set.For("signal-group")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	// Background a grandchild sleep, record ITS pid (not the shell's), then
	// block in the parent shell so the run stays alive until killed.
	cmd := "sleep 300 & echo $! > " + portableShellQuote(pidFile) + "; wait"
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: cmd, ExecutionID: "signal-group",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitForPath(t, pidFile)
	raw, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read pid file: %v", err)
	}
	grandchildPID, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatalf("parse grandchild pid %q: %v", raw, err)
	}
	if !pidAlive(grandchildPID) {
		t.Fatalf("grandchild pid %d not observed alive before kill", grandchildPID)
	}

	if err := proc.Signal(context.Background(), ProcessSignalKill); err != nil {
		t.Fatalf("Signal(Kill): %v", err)
	}
	assertProcessDiesWithin(t, proc, 5*time.Second)

	deadline := time.Now().Add(5 * time.Second)
	for pidAlive(grandchildPID) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if pidAlive(grandchildPID) {
		t.Fatalf("grandchild pid %d still alive after Signal(Kill): the group signal did not reach it", grandchildPID)
	}
}
