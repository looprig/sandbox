//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os/exec"
	"testing"
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
		{"rung none with Init -> null backend", rungNone, true, nil, "null"},
		{"rung none without Init -> null backend (no re-exec needed)", rungNone, false, nil, "null"},
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
			case "null":
				if _, ok := b.(*nullBackend); !ok {
					t.Errorf("backend = %T, want *nullBackend", b)
				}
			}
		})
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
	e, err := newExecutorForEffectivePolicy(PolicyFor(Write, ws))
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

// TestWrapFailsClosedOnReexecBackend documents that Wrap is intentionally
// unsupported on the re-exec linux backend: its wrap returns a per-spawn cleanup
// (pipe teardown) that Wrap cannot own, so Wrap fails closed rather than leaking
// the pipe. Consumers use RunCommand/RunArgv on Linux.
func TestWrapFailsClosedOnReexecBackend(t *testing.T) {
	requireLandlockV4(t)
	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(PolicyFor(Write, ws), withBackend(newLinuxBackend()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	if _, err := e.Wrap(exec.Command("echo", "hi")); err == nil {
		t.Error("Wrap on the re-exec linux backend succeeded, want a fail-closed error")
	}
}
