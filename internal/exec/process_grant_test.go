package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// This file covers Task 11's Step 1 test list for the grant/path/route side
// of PrepareProcess: grant validation and reservation happen entirely during
// prepare (never at spawn time), the authoritative EffectiveAccess folds in
// approved deltas on top of the base profile, replay and path-drift both fail
// during prepare (never later), a workspace lease acquired after prepare
// cannot retroactively widen the frozen access, an unstarted Close burns the
// grant without making it replayable, and every retained resource (compiled
// backend spec here — proxy credential/route are covered by
// executor_proxy_backend_test.go, path handles by grant_path_lifecycle_test.go)
// stays live until the process actually terminates.

// mustCommandStartGrant issues and returns a single-use command.start.v1
// grant bound to executionID/command/cwd, failing the test on any error.
func mustCommandStartGrant(t *testing.T, executor *Executor, executionID, command, cwd string) string {
	t.Helper()
	token, err := executor.IssueGrant(context.Background(), executionID, command, cwd,
		"command.execute", "", GrantClassCommandStart, command, time.Now().Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatalf("IssueGrant (command.start): %v", err)
	}
	return token
}

// mustFilesystemPathWriteGrant issues and returns a single-use
// filesystem.path.write.v1 grant pinned to target.
func mustFilesystemPathWriteGrant(t *testing.T, executor *Executor, executionID, command, cwd, target string) string {
	t.Helper()
	token, err := executor.IssueGrant(context.Background(), executionID, command, cwd,
		"filesystem.write", target, GrantClassFilesystemPathWrite, target, time.Now().Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatalf("IssueGrant (filesystem.write): %v", err)
	}
	return token
}

func TestPrepareProcessGrantValidationReservesWithoutSpawn(t *testing.T) {
	executor := newProcessTestExecutor(t, Gated)
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	command := portableWriteCommand(marker, "spawned")
	token := mustCommandStartGrant(t, executor, "grant-no-spawn", command, dir)

	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: command, ExecutionID: "grant-no-spawn", Grants: []string{token},
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("PrepareProcess with a grant appears to have spawned: marker stat err = %v", statErr)
	}
	// The grant is already consumed (single-spawn, non-replayable) by the
	// time PrepareProcess returns, well before any spawn.
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "grant-no-spawn", dir, command, []string{token}); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("reusing the grant PrepareProcess already consumed = %v, want ErrGrantReplay", err)
	}

	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })
	if result, err := proc.Wait(context.Background()); err != nil || result.ExitCode != 0 {
		t.Fatalf("Wait = (%+v, %v), want (ExitCode 0, nil)", result, err)
	}
	if _, statErr := os.Stat(marker); statErr != nil {
		t.Fatalf("marker stat after Start+Wait: %v, want the process to have run", statErr)
	}
}

func TestPrepareProcessEffectiveAccessIncludesApprovedFilesystemDeltas(t *testing.T) {
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	target := filepath.Join(workspace, "target.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	executor, err := newTestExecutor(prof,
		withBackend(&captureBackend{bits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
	)
	if err != nil {
		t.Fatal(err)
	}
	// A Gated WorkspaceWrite base authority alone (no grant redeemed yet) is
	// already ScopedWrite in shape, but with no approved paths: only an
	// approved delta ever populates WritePaths/WriteTrees.
	base := executor.effectiveProcessAccess()
	if base.Kind != ProcessAccessScopedWrite || len(base.WritePaths()) != 0 || len(base.WriteTrees()) != 0 {
		t.Fatalf("base access = %+v, want ProcessAccessScopedWrite with no paths", base)
	}

	command := portableSuccessCommand()
	commandToken := mustCommandStartGrant(t, executor, "access-deltas", command, workspace)
	writeToken := mustFilesystemPathWriteGrant(t, executor, "access-deltas", command, workspace, target)

	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: command, ExecutionID: "access-deltas",
		Grants: []string{commandToken, writeToken},
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	t.Cleanup(func() { _ = prepared.Close() })

	access := prepared.EffectiveAccess()
	if access.Kind != ProcessAccessScopedWrite {
		t.Fatalf("access.Kind = %v, want ProcessAccessScopedWrite (base authority + one approved write-path delta)", access.Kind)
	}
	if got := access.WritePaths(); len(got) != 1 || got[0] != target {
		t.Fatalf("access.WritePaths() = %v, want [%q]", got, target)
	}
	if got := access.WriteTrees(); len(got) != 0 {
		t.Fatalf("access.WriteTrees() = %v, want empty", got)
	}
}

func TestPrepareProcessRejectsGrantReplayDuringPrepare(t *testing.T) {
	executor := newProcessTestExecutor(t, Gated)
	dir := t.TempDir()
	command := portableSuccessCommand()
	token := mustCommandStartGrant(t, executor, "prepare-replay", command, dir)

	first, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: command, ExecutionID: "prepare-replay", Grants: []string{token},
	})
	if err != nil {
		t.Fatalf("first PrepareProcess: %v", err)
	}
	t.Cleanup(func() { _ = first.Close() })

	if _, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: command, ExecutionID: "prepare-replay", Grants: []string{token},
	}); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("second PrepareProcess with the same token = %v, want ErrGrantReplay", err)
	}
}

func TestPrepareProcessRejectsPathDriftDuringPrepare(t *testing.T) {
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	target := filepath.Join(workspace, "target.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	executor, err := newTestExecutor(prof,
		withBackend(&captureBackend{bits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
	)
	if err != nil {
		t.Fatal(err)
	}
	command := portableSuccessCommand()
	commandToken := mustCommandStartGrant(t, executor, "path-drift", command, workspace)
	writeToken := mustFilesystemPathWriteGrant(t, executor, "path-drift", command, workspace, target)

	// Replace the target's identity (delete + recreate) between grant
	// issuance and consumption: the retained handle's identity no longer
	// matches the freshly re-acquired one.
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("drifted"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: command, ExecutionID: "path-drift",
		Grants: []string{commandToken, writeToken},
	}); !errors.Is(err, ErrGrantTargetChanged) {
		t.Fatalf("PrepareProcess after path drift = %v, want ErrGrantTargetChanged", err)
	}
}

func TestPrepareProcessAccessIsFrozenAgainstLaterWorkspaceLeases(t *testing.T) {
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	target := filepath.Join(workspace, "target.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(workspace, "other.txt")
	if err := os.WriteFile(other, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	executor, err := newTestExecutor(prof,
		withBackend(&captureBackend{bits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
	)
	if err != nil {
		t.Fatal(err)
	}
	command := portableSuccessCommand()
	commandToken := mustCommandStartGrant(t, executor, "frozen-access", command, workspace)
	writeToken := mustFilesystemPathWriteGrant(t, executor, "frozen-access", command, workspace, target)

	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: command, ExecutionID: "frozen-access",
		Grants: []string{commandToken, writeToken},
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	t.Cleanup(func() { _ = prepared.Close() })

	before := prepared.EffectiveAccess()

	// Acquire an entirely separate workspace write lease on the SAME
	// executor, between prepare and start.
	otherCommandToken := mustCommandStartGrant(t, executor, "frozen-access-other", command, workspace)
	otherWriteToken := mustFilesystemPathWriteGrant(t, executor, "frozen-access-other", command, workspace, other)
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "frozen-access-other", workspace, command,
		[]string{otherCommandToken, otherWriteToken}); err != nil {
		t.Fatalf("RunCommandWithGrants (unrelated lease): %v", err)
	}

	after := prepared.EffectiveAccess()
	if after.Kind != before.Kind || len(after.WritePaths()) != len(before.WritePaths()) || after.WritePaths()[0] != before.WritePaths()[0] {
		t.Fatalf("EffectiveAccess changed after an unrelated later lease: before=%+v after=%+v", before, after)
	}
	if containsStr(after.WritePaths(), other) {
		t.Fatalf("EffectiveAccess absorbed an unrelated later lease's path: %v", after.WritePaths())
	}
}

func TestPreparedProcessCloseReleasesUnusedGrantWithoutReplay(t *testing.T) {
	executor := newProcessTestExecutor(t, Gated)
	dir := t.TempDir()
	command := portableSuccessCommand()
	token := mustCommandStartGrant(t, executor, "close-unused", command, dir)

	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: command, ExecutionID: "close-unused", Grants: []string{token},
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatalf("second Close (idempotent): %v", err)
	}
	if proc, err := prepared.Start(context.Background()); !errors.Is(err, ErrProcessClosed) || proc != nil {
		t.Fatalf("Start after Close = (%v, %v), want (nil, ErrProcessClosed)", proc, err)
	}
	// The single-spawn grant is burned the moment PrepareProcess consumed it,
	// regardless of whether Start was ever called: Close cannot resurrect it.
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "close-unused", dir, command, []string{token}); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("reusing a token from a closed-unstarted preparation = %v, want ErrGrantReplay", err)
	}
}

func TestPreparedProcessCompiledSpecReleasesOnlyAfterProcessTerminates(t *testing.T) {
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Allow, Network: Deny, Command: Gated,
	})
	var released atomic.Bool
	backend := &captureBackend{
		bits:    GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		release: func() error { released.Store(true); return nil },
	}
	executor, err := newTestExecutor(prof, withBackend(backend))
	if err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(workspace, "started")
	completed := filepath.Join(workspace, "completed")
	command := portableWriteSleepWriteCommand(started, completed, 1)
	token := mustCommandStartGrant(t, executor, "release-timing", command, workspace)

	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: command, ExecutionID: "release-timing", Grants: []string{token},
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })

	waitForMarker(t, started, 2*time.Second)
	if released.Load() {
		t.Fatal("compiled backend spec released before the process terminated")
	}

	result, err := proc.Wait(context.Background())
	if err != nil || result.ExitCode != 0 {
		t.Fatalf("Wait = (%+v, %v), want (ExitCode 0, nil)", result, err)
	}
	if _, statErr := os.Stat(completed); statErr != nil {
		t.Fatalf("completed marker: %v, want the process to have run to completion", statErr)
	}

	deadline := time.Now().Add(2 * time.Second)
	for !released.Load() {
		if time.Now().After(deadline) {
			t.Fatal("compiled backend spec was never released after process termination")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// waitForMarker polls until path exists or the timeout elapses.
func waitForMarker(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if _, err := os.Stat(path); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("marker %q was never written within %s", path, timeout)
		}
		time.Sleep(5 * time.Millisecond)
	}
}
