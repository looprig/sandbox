//go:build integration

package exec

import (
	"context"
	"errors"
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
// lifecycle, TestIntegrationProcessPTYLifecycle, exercised for real on both
// Linux and Darwin. Darwin previously (Task 12c) rejected every Supervised
// spawn — including this one — with enforce.ErrLifetimeContainmentUnavailable
// strictly before any PTY device was allocated; the 2026-08-06 best-effort
// containment decision (process_tree_darwin.go's attachSupervisedProof,
// LifetimeContainmentBestEffort) replaced that rejection, so this test's own
// enforce.ErrLifetimeContainmentUnavailable skip branches below now stay live
// only for the case that sentinel still legitimately covers — Linux Rung 2
// with no delegated cgroup v2 ancestor — and are never hit on darwin. This
// file deliberately carries no darwin||linux build restriction (unlike those
// two _unix_test.go files) — see PHASE GATE 5's command matrix, which
// discovers this file's tests with a plain `-tags integration -list` on
// every OS — so it builds a fresh local executor helper rather than
// depending on the unix-only helpers those other files declare.
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

// TestIntegrationProcessPTYLifecycle is Task 21's live PTY test, now
// exercised for real on every platform this file's own real-backend pattern
// reaches: a real end-to-end PTY-backed process — real interactive echo, a
// real resize, and a real EOF-driven exit — through the production
// PrepareProcess/Start path on whatever containment this host's real backend
// actually provides. On Linux that is Rung 1's PID namespace or Rung 2 with a
// delegated cgroup v2 scope; Rung 2 with neither still fails closed with
// enforce.ErrLifetimeContainmentUnavailable exactly like the pipe-backed path
// already does (this host's own documented fail-closed contract, not a
// defect this test reports). On Darwin, PrepareProcess/Start now attach the
// best-effort process-tree teardown prover instead
// (LifetimeContainmentBestEffort; see process_tree_darwin.go) and never
// return that sentinel for a real Seatbelt-confined spawn, so this test runs
// the exact same live PTY lifecycle there too — a real Seatbelt denial
// surfacing here (e.g. /dev/ptmx access) would be a genuine SBPL profile
// gap, not something this test papers over with a skip.
func TestIntegrationProcessPTYLifecycle(t *testing.T) {
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
