package sandbox_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/looprig/sandbox"
)

func TestGrantTTLIsExecutorSetOption(t *testing.T) {
	workspace := t.TempDir()
	profile, err := sandbox.NewProfile(sandbox.ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: sandbox.Allow, WorkspaceWrite: sandbox.Allow,
		HostRead: sandbox.Allow, HostWrite: sandbox.Allow, Network: sandbox.Allow,
		Command: sandbox.Gated, Isolation: sandbox.Unconfined, AckUnconfined: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if set, err := sandbox.NewExecutorSet(profile,
		sandbox.WithScratchRoot(t.TempDir()), sandbox.WithMaxExecutors(1), sandbox.WithGrantTTL(0)); err == nil {
		_ = set.Close()
		t.Fatal("NewExecutorSet accepted an explicitly non-positive grant TTL")
	}

	const ttl = 2 * time.Hour
	set, err := sandbox.NewExecutorSet(profile,
		sandbox.WithScratchRoot(t.TempDir()), sandbox.WithMaxExecutors(1), sandbox.WithGrantTTL(ttl))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("external-api")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := executor.IssueGrant(context.Background(), "within-ttl", "true", workspace,
		"command.execute", "", "command.start.v1", "true", now.Add(time.Hour).UnixMilli()); err != nil {
		t.Fatalf("IssueGrant within configured TTL: %v", err)
	}
	if _, err := executor.IssueGrant(context.Background(), "beyond-ttl", "true", workspace,
		"command.execute", "", "command.start.v1", "true", now.Add(3*time.Hour).UnixMilli()); !errors.Is(err, sandbox.ErrGrantExpired) {
		t.Fatalf("IssueGrant beyond configured TTL error = %v, want ErrGrantExpired", err)
	}
}
