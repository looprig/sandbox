//go:build !windows

package exec

import (
	"testing"

	"github.com/looprig/sandbox/pkg/sandboxtest"
)

func requireLiveConformanceBackend(*testing.T) {}

func newLiveConformanceExecutor(t *testing.T, workspace string) sandboxtest.SUT {
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1))
	if err != nil {
		t.Fatalf("NewExecutorSet(live): %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("conformance")
	if err != nil {
		t.Fatalf("ExecutorSet.For(live): %v", err)
	}
	return executor
}
