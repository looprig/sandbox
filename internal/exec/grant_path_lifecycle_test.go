package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIssueGrantRetainsPathUntilSuccessfulConsumption(t *testing.T) {
	now := time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	target := filepath.Join(workspace, "target.txt")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Gated, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	executor, err := newTestExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
		withClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	token, err := executor.IssueGrant(context.Background(), "retained", "true", workspace,
		"filesystem.read", target, GrantClassFilesystemPathRead, target, now.Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	id := grantID(token)
	if _, ok := executor.retainedGrantPaths[id]; !ok {
		t.Fatal("issued filesystem grant has no retained path handle")
	}
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "retained", workspace, "true", []string{token}); err != nil {
		t.Fatal(err)
	}
	if _, ok := executor.retainedGrantPaths[id]; ok {
		t.Fatal("consumed filesystem grant still owns registry handle")
	}
	if _, ok := executor.usedGrants[id]; !ok {
		t.Fatal("consumed filesystem grant lacks replay marker")
	}
}

func TestRetainedGrantPathConcurrentConsumptionFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 21, 18, 30, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	target := filepath.Join(workspace, "target.txt")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Gated, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	executor, err := newTestExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
		withClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	token, err := executor.IssueGrant(context.Background(), "concurrent", "true", workspace,
		"filesystem.read", target, GrantClassFilesystemPathRead, target, now.Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	errorsCh := make(chan error, 2)
	for range 2 {
		go func() {
			_, _, err := executor.RunCommandWithGrants(context.Background(), "concurrent", workspace, "true", []string{token})
			errorsCh <- err
		}()
	}
	var successes, replays int
	for range 2 {
		err := <-errorsCh
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrGrantReplay):
			replays++
		default:
			t.Fatalf("concurrent consumption error = %v", err)
		}
	}
	if successes != 1 || replays != 1 {
		t.Fatalf("concurrent results: successes=%d replays=%d, want 1/1", successes, replays)
	}
}

func TestRetainedGrantPathExpiresAndClosesWithExecutor(t *testing.T) {
	now := time.Date(2026, 7, 21, 18, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	target := filepath.Join(workspace, "target.txt")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Gated, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	executor, err := newTestExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
		withClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	token, err := executor.IssueGrant(context.Background(), "expires", "true", workspace,
		"filesystem.read", target, GrantClassFilesystemPathRead, target, now.Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	id := grantID(token)
	now = now.Add(time.Minute + time.Millisecond)
	if _, err := executor.IssueGrant(context.Background(), "prune", "true", workspace,
		"filesystem.read", target, GrantClassFilesystemPathRead, target, now.Add(time.Minute).UnixMilli()); err != nil {
		t.Fatal(err)
	}
	if _, ok := executor.retainedGrantPaths[id]; ok {
		t.Fatal("expired retained path was not pruned")
	}

	now = now.Add(time.Second)
	token, err = executor.IssueGrant(context.Background(), "close", "true", workspace,
		"filesystem.read", target, GrantClassFilesystemPathRead, target, now.Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	id = grantID(token)
	executor.revokeResources()
	if _, ok := executor.retainedGrantPaths[id]; ok || len(executor.retainedGrantPaths) != 0 {
		t.Fatal("executor close did not revoke retained paths")
	}
}
