//go:build linux

package sandbox

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestSelectLinuxBackend covers the rung × Init-called matrix that platformBackend
// uses: a re-exec rung (1/2) needs Init() and yields the linuxBackend, else
// ErrInitNotCalled; rung none yields the null backend regardless of Init.
func TestSelectLinuxBackend(t *testing.T) {
	tests := []struct {
		name       string
		rung       rung
		initCalled bool
		wantErr    error
		wantType   string // "linux" | "null"
	}{
		{"rung2 with Init -> linux backend", rungTwo, true, nil, "linux"},
		{"rung1 with Init -> linux backend", rungOne, true, nil, "linux"},
		{"rung2 without Init -> ErrInitNotCalled", rungTwo, false, ErrInitNotCalled, ""},
		{"rung1 without Init -> ErrInitNotCalled", rungOne, false, ErrInitNotCalled, ""},
		{"rung none with Init -> unavailable", rungNone, true, ErrSandboxUnavailable, ""},
		{"rung none without Init -> unavailable", rungNone, false, ErrSandboxUnavailable, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, err := selectLinuxBackend(tt.rung, tt.initCalled)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("selectLinuxBackend err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				if b != nil {
					t.Errorf("backend = %v, want nil on error", b)
				}
				return
			}
			switch tt.wantType {
			case "linux":
				if _, ok := b.(*linuxBackend); !ok {
					t.Errorf("backend = %T, want *linuxBackend", b)
				}
			}
		})
	}
}

func TestLinuxBackendsNeverClaimTargetNetwork(t *testing.T) {
	policy := effectivePolicy{
		Net:       effectiveNetPolicy{ProxyPort: 43123},
		Env:       effectiveEnvPolicy{Set: map[string]string{}},
		Isolation: Sandboxed,
	}
	for _, backend := range []*linuxBackend{{rung: rungOne}, {rung: rungTwo}} {
		_, _, _, bits, err := backend.compile(policy)
		if err != nil {
			t.Fatalf("rung %d compile: %v", backend.rung, err)
		}
		if bits&GuaranteeTargetNetwork != 0 {
			t.Errorf("rung %d claimed GuaranteeTargetNetwork for parent proxy port", backend.rung)
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
		withExecutorSetExecOptions(withBackend(&linuxBackend{rung: rungTwo}), withClock(func() time.Time { return now })),
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

// TestPlatformBackendLiveOnThisHost asserts the real selector picks the re-exec
// linux backend on this ABI-v4 (rung-2) host — Init() was called by the package
// TestMain, so the gate is satisfied. This is the proof that the Linux backend is
// WIRED LIVE (platformBackend no longer returns null on linux).
func TestPlatformBackendLiveOnThisHost(t *testing.T) {
	requireLandlockV4(t)
	b, err := platformBackend()
	if err != nil {
		t.Fatalf("platformBackend: %v", err)
	}
	if _, ok := b.(*linuxBackend); !ok {
		t.Fatalf("platformBackend = %T, want *linuxBackend (rung 2 live on this host)", b)
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
		t.Errorf("Level() = %d, want LevelDegraded (rung-2 linux backend)", e.Level())
	}
	if !e.Guarantees().WriteBoundary {
		t.Errorf("Guarantees().WriteBoundary = false, want true (rung-2 FS confinement live)")
	}
	// And it actually runs a command through the stage-2 re-exec + Landlock.
	out, code, err := e.RunArgv(context.Background(), ws, []string{"echo", "wired"})
	if err != nil || code != 0 {
		t.Fatalf("RunArgv: err=%v code=%d out=%q", err, code, out)
	}
}
