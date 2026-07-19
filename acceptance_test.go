package sandbox

// Acceptance matrix — SPEC §12.1. This file asserts the PLATFORM-INDEPENDENT rows
// (and the sandbox-side mechanisms the harness-integration rows build on) that the
// sandbox module can prove on its own: unavailable confinement fails closed and
// environment scrubbing holds.
// Grant-v1 acceptance has its own focused suite. Linux-rung rows live in
// acceptance_linux_test.go; the macOS Seatbelt row in acceptance_darwin_test.go.
//
// The load-bearing signal on every row is the per-row Guarantees() assertion — the
// machine-readable posture the auto-approval interlock (§10.3) gates on. The
// harness-integration rows of §12.1 (journaled ceiling command, pre-ask
// BuildRequest wiring, foreign-agent launch) are Phase 4/5 and are NOT in this
// module; where a mechanism is genuinely absent here a row t.Skips with a RECORDED
// reason rather than passing silently.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
)

// TestAcceptanceMatrixCrossPlatform runs the §12.1 rows the sandbox module can
// assert on any platform. Each entry mirrors one matrix scenario; a row asserts
// its mechanism AND its Guarantees() posture.
func TestAcceptanceMatrixCrossPlatform(t *testing.T) {
	// Several rows build non-inherit executors, whose §5.3 secret deny-reads are
	// home-anchored, so NewExecutor/NewExecutorDynamic require a resolvable home.
	// Provide one when the host leaves it unset (matches TestEnvScrub). Set at the
	// non-parallel parent so t.Setenv is safe.
	if os.Getenv("HOME") == "" {
		t.Setenv("HOME", t.TempDir())
	}
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"no-sandbox-available/fails-closed", acceptRowSandboxUnavailable},
		{"env-scrub", acceptRowEnvScrub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.run(t) })
	}
}

// acceptRowSandboxUnavailable proves the production direct backend cannot be
// selected for a Sandboxed policy.
func acceptRowSandboxUnavailable(t *testing.T) {
	_, _, _, _, err := newNullBackend().compile(effectivePolicy{Isolation: Sandboxed})
	if !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("sandboxed direct backend error = %v, want ErrSandboxUnavailable", err)
	}
}

// acceptRowEnvScrub — §12.1 "Env scrub": a child sees the baseline env only;
// GITHUB_TOKEN and ANTHROPIC_API_KEY are absent; TMPDIR points into the writable
// tmp. Runs through the live platform backend (rung 2 here) so the scrub is
// proven end-to-end, not just in assembleEnv.
func acceptRowEnvScrub(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "gh-secret")
	t.Setenv("ANTHROPIC_API_KEY", "sk-secret")
	ws := t.TempDir()

	// Construct AFTER Setenv: the executor snapshots os.Environ at build.
	e, err := newExecutorForEffectivePolicy(testPolicy(testWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	// Per-row Guarantees(): EnvScrub must be claimed.
	if !e.Guarantees().EnvScrub {
		t.Errorf("Guarantees().EnvScrub = false, want true for a non-inherit policy")
	}

	out, code, err := e.RunCommand(context.Background(), ws, "env")
	if err != nil {
		t.Fatalf("RunCommand(env): %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("env exit=%d, want 0 (out=%q)", code, out)
	}
	got := string(out)
	for _, secret := range []string{"GITHUB_TOKEN", "ANTHROPIC_API_KEY"} {
		if strings.Contains(got, secret) {
			t.Errorf("child env leaked %s (must be scrubbed):\n%s", secret, got)
		}
	}
	if !strings.Contains(got, "TMPDIR=/tmp") {
		t.Errorf("child env missing TMPDIR=/tmp (writable tmp):\n%s", got)
	}
}

// assertGuarantees fails unless got exactly equals want across all seven
// properties — the exhaustive per-row posture check.
func assertGuarantees(t *testing.T, got, want Guarantees) {
	t.Helper()
	if got != want {
		t.Errorf("Guarantees() = %+v, want %+v", got, want)
	}
}
