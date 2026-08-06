//go:build integration

package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
)

// This file is Task 21's tagged integration coverage for the Unix PTY-backed
// async process path, mirroring process_grant_integration_test.go and
// process_parent_death_integration_unix_test.go's own real-backend pattern
// (no withBackend test seam — NewExecutorSet selects whatever this host's
// production platform.Backend actually provides): a live end-to-end PTY
// lifecycle on Linux (TestIntegrationProcessPTYLifecycle), and Darwin's
// SEPARATE fail-closed contract for a REAL Seatbelt-confined PTY spawn
// (TestIntegrationProcessPTYDarwinLifetimeUnavailable) — proving Darwin
// rejects strictly before any PTY device is allocated or child process is
// spawned, exactly like process_parent_death_integration_unix_test.go's own
// TestIntegrationProcessTreeDarwinSetsidFailsClosed already proves for the
// pipe-backed path. This file deliberately carries no darwin||linux build
// restriction (unlike those two _unix_test.go files) — see PHASE GATE 5's
// command matrix, which discovers this file's tests with a plain `-tags
// integration -list` on every OS — so both tests below gate themselves on
// runtime.GOOS internally instead, and build a fresh local executor helper
// rather than depending on the unix-only helpers those other files declare.
//
// Tagged execution is deferred to Phase Gate 5's approved Linux and Darwin
// workers; this codebase's own execution rules do not require running it
// here. It must, however, compile under every GOOS this repository targets,
// including GOOS=linux and GOOS=windows.

// integrationTerminalExecutor builds a real ExecutorSet/Executor through the
// production platform backend selector (no withBackend override), skipping
// (never failing) when this host has no usable OS confinement backend at all
// — a genuine environment gap, not a defect either test below is responsible
// for proving.
func integrationTerminalExecutor(t *testing.T, name string) (*ExecutorSet, *Executor, string) {
	t.Helper()
	workspace := t.TempDir()
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1))
	if err != nil {
		if errors.Is(err, enforce.ErrUnavailable) {
			t.Skipf("NewExecutorSet: no OS confinement backend available on this host: %v", err)
		}
		t.Fatalf("NewExecutorSet: %v", err)
	}
	executor, err := set.For(name)
	if err != nil {
		_ = set.Close()
		if errors.Is(err, enforce.ErrUnavailable) {
			t.Skipf("ExecutorSet.For: no OS confinement backend available on this host: %v", err)
		}
		t.Fatalf("ExecutorSet.For: %v", err)
	}
	return set, executor, workspace
}

// TestIntegrationProcessPTYLifecycle is Task 21's exact live Linux test: a
// real end-to-end PTY-backed process — real interactive echo, a real resize,
// and a real EOF-driven exit — through the production PrepareProcess/Start
// path on whatever containment this host's real Linux backend actually
// provides (Rung 1's PID namespace, or Rung 2 with a delegated cgroup v2
// scope; Rung 2 with neither fails closed with
// enforce.ErrLifetimeContainmentUnavailable exactly like the pipe-backed
// path already does — that is this host's own documented fail-closed
// contract, not a defect this test reports).
func TestIntegrationProcessPTYLifecycle(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("this is the exact live Linux PTY lifecycle test; see TestIntegrationProcessPTYDarwinLifetimeUnavailable for Darwin's own contract")
	}
	set, executor, workspace := integrationTerminalExecutor(t, "pty-lifecycle")
	defer func() { _ = set.Close() }()

	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: "sh -c 'read _; stty size'", ExecutionID: "pty-lifecycle", TTY: true,
	})
	if err != nil {
		if errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Skipf("PrepareProcess: lifetime containment unavailable on this host: %v", err)
		}
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		if errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Skipf("Start: lifetime containment unavailable on this host: %v", err)
		}
		t.Fatalf("Start: %v", err)
	}
	defer func() { _ = proc.Close(context.Background()) }()

	if proc.StreamMode() != ProcessStreamModePTY {
		t.Fatalf("StreamMode() = %v, want ProcessStreamModePTY", proc.StreamMode())
	}
	if err := proc.Resize(context.Background(), 30, 120); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if _, err := proc.Stdin().Write([]byte("\n")); err != nil {
		t.Fatalf("Stdin.Write: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := proc.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}

	collected := make([]byte, 0, 64)
	buf := make([]byte, 64)
	for i := 0; i < 8; i++ {
		n, readErr := proc.Stdout().Read(buf)
		collected = append(collected, buf[:n]...)
		if strings.Contains(string(collected), "30 120") || readErr != nil {
			break
		}
	}
	if !strings.Contains(string(collected), "30 120") {
		t.Fatalf("`stty size` output = %q, want it to contain the resized \"30 120\"", string(collected))
	}
}

// TestIntegrationProcessPTYDarwinLifetimeUnavailable proves Darwin's
// fail-closed CONTRACT directly for a REAL Seatbelt-confined PTY request: a
// real Executor (built through the production platform backend selector,
// exactly like integrationTerminalExecutor's other callers) asked to
// PrepareProcess/Start a TTY-backed spawn is rejected with
// enforce.ErrLifetimeContainmentUnavailable before any PTY device is
// allocated and before any process — target or otherwise — is ever created.
// "Before any process is created" is proved by a marker file the target
// command would write if it ever ran, polled for and never found; "before
// any PTY device is allocated" follows structurally from this codebase's own
// ordering (startConfinedTTY, process.go, calls openProcessTerminal only
// after e.processTree has already succeeded — see that method's own doc
// comment), not from anything this test can observe as a side effect
// directly, exactly like process_parent_death_integration_unix_test.go's
// TestIntegrationProcessTreeDarwinSetsidFailsClosed already reasons for the
// pipe-backed path.
func TestIntegrationProcessPTYDarwinLifetimeUnavailable(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-only fail-closed contract; see TestIntegrationProcessPTYLifecycle for real PTY execution on Linux")
	}
	set, executor, workspace := integrationTerminalExecutor(t, "pty-darwin-failclosed")
	defer func() { _ = set.Close() }()

	marker := filepath.Join(workspace, "darwin-pty-failclosed-marker")
	command := portableWriteCommand(marker, "spawned")

	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: command, ExecutionID: "pty-darwin-failclosed", TTY: true,
	})
	switch {
	case err != nil:
		if !errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Fatalf("PrepareProcess failed with an unexpected error: %v, want enforce.ErrLifetimeContainmentUnavailable", err)
		}
	default:
		defer func() { _ = prepared.Close() }()
		proc, startErr := prepared.Start(context.Background())
		if startErr == nil {
			// Defensive only: if a future change makes Start succeed without a
			// real containment primitive, do not leak the process this test
			// never expected to exist.
			_ = proc.Signal(context.Background(), ProcessSignalKill)
			_, _ = proc.Wait(context.Background())
			t.Fatal("Start unexpectedly succeeded on darwin; want enforce.ErrLifetimeContainmentUnavailable before any spawn")
		}
		if !errors.Is(startErr, enforce.ErrLifetimeContainmentUnavailable) {
			t.Fatalf("Start error = %v, want it to wrap enforce.ErrLifetimeContainmentUnavailable", startErr)
		}
		if proc != nil {
			t.Fatalf("Start returned a non-nil Process alongside a fail-closed error: %v", proc)
		}
	}

	// The core proof: the spawn was rejected before cmd.Start ever ran, so
	// the target never executed and never wrote its marker.
	time.Sleep(2 * time.Second)
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("marker exists even though the PTY spawn was rejected before it started: stat err = %v", statErr)
	}
}
