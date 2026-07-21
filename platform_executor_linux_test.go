//go:build linux

package sandbox

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/linux"
	"github.com/looprig/sandbox/internal/platform"
	"github.com/looprig/sandbox/internal/policy"
)

// These live with the executor rather than with internal/platform: they build
// real Executors, and the package the platform selector resolves TO cannot
// import the executor that resolves through it. The pure selection matrix
// (TestSelectLinuxBackend) stayed in internal/platform.

func TestLinuxBackendsNeverClaimTargetNetwork(t *testing.T) {
	pol := policy.Effective{
		Net:       policy.NetPolicy{ProxyPort: 43123},
		Env:       policy.EnvPolicy{Set: map[string]string{}},
		Isolation: Sandboxed,
	}
	for _, backend := range []*linux.Backend{{Rung: linux.RungOne}, {Rung: linux.RungTwo}} {
		_, _, _, bits, err := backend.Compile(pol)
		if err != nil {
			t.Fatalf("linux.Rung %d compile: %v", backend.Rung, err)
		}
		if bits&GuaranteeTargetNetwork != 0 {
			t.Errorf("linux.Rung %d claimed GuaranteeTargetNetwork for parent proxy port", backend.Rung)
		}
	}
}

func TestLinuxTargetGrantFailsClosed(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Gated, Command: Allow,
	})
	route, err := NewDirectEgressRoute()
	if err != nil {
		t.Fatal(err)
	}
	set, err := NewExecutorSet(profile,
		WithScratchRoot(t.TempDir()), WithMaxExecutors(1), WithEgressRoute(route),
		withExecutorSetConfig(withBackend(&linux.Backend{Rung: linux.RungTwo}), withClock(func() time.Time { return now })),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("linux-target")
	if err != nil {
		t.Fatal(err)
	}
	if executor.Guarantees().TargetNetwork {
		t.Fatal("Linux executor claimed target network enforcement")
	}
	_, err = executor.IssueGrant(context.Background(), "exec-linux", "true", workspace,
		"network", "", "network.proxy-target.v1", "tcp:github.com:443", now.Add(time.Minute).UnixMilli())
	if !errors.Is(err, ErrGrantGuaranteeMismatch) {
		t.Fatalf("Linux target grant error = %v, want ErrGrantGuaranteeMismatch", err)
	}
}

// TestUnpinnedExecutorUsesLinuxBackend confirms an executor built WITHOUT the
// withBackend seam (the production path) reports the rung-2 posture — proving the
// wiring flows end to end through NewExecutor.
func TestUnpinnedExecutorUsesLinuxBackend(t *testing.T) {
	requireLandlockV4(t)
	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	if e.Level() != LevelDegraded {
		t.Errorf("Level() = %d, want LevelDegraded (linux.Rung-2 linux enforce.Backend)", e.Level())
	}
	if !e.Guarantees().WriteBoundary {
		t.Errorf("Guarantees().WriteBoundary = false, want true (linux.Rung-2 FS confinement live)")
	}
	// And it actually runs a command through the stage-2 re-exec + Landlock.
	out, code, err := e.RunArgv(context.Background(), ws, []string{"echo", "wired"})
	if err != nil || code != 0 {
		t.Fatalf("RunArgv: err=%v code=%d out=%q", err, code, out)
	}
}

// TestPlatformBackendLiveOnThisHost asserts the real selector picks the re-exec
// linux backend on this ABI-v4 (rung-2) host — Init() was called by the package
// TestMain, so the gate is satisfied. This is the proof that the Linux backend is
// WIRED LIVE (platform.Backend no longer returns null on linux).
func TestPlatformBackendLiveOnThisHost(t *testing.T) {
	requireLandlockV4(t)
	b, err := platform.Backend()
	if err != nil {
		t.Fatalf("platform.Backend: %v", err)
	}
	if _, ok := b.(*linux.Backend); !ok {
		t.Fatalf("Backend = %T, want *linux.Backend (rung 2 live on this host)", b)
	}
}
