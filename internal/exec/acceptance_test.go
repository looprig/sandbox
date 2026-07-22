package exec

// This file asserts the platform-independent acceptance rows
// (and the sandbox-side mechanisms the harness-integration rows build on) that the
// sandbox module can prove on its own: unavailable confinement fails closed and
// environment scrubbing holds.
// Grant-v1 acceptance has its own focused suite. Linux-rung rows live in
// acceptance_linux_test.go; the macOS Seatbelt row in acceptance_darwin_test.go.
//
// The load-bearing signal on every row is the per-row Guarantees() assertion — the
// machine-readable posture consumers gate on. Where a mechanism is genuinely
// absent here, a row skips with a recorded reason rather than passing silently.

import (
	"context"
	"errors"
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"os"
	"strings"
	"testing"
)

// TestAcceptanceMatrixCrossPlatform runs the rows the sandbox module can
// assert on any platform. Each entry mirrors one matrix scenario; a row asserts
// its mechanism AND its Guarantees() posture.
func TestAcceptanceMatrixCrossPlatform(t *testing.T) {
	// Several rows build non-inherit executors whose policy is home-anchored, so
	// executor construction requires a resolvable home.
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
	_, _, _, _, err := enforce.NewNull().Compile(policy.Effective{Isolation: Sandboxed})
	if !errors.Is(err, enforce.ErrUnavailable) {
		t.Fatalf("sandboxed direct backend error = %v, want enforce.ErrUnavailable", err)
	}
}

// acceptRowEnvScrub proves a child sees the baseline env only;
// GITHUB_TOKEN and ANTHROPIC_API_KEY are absent; TMPDIR points into the writable
// tmp. Runs through the live platform backend (rung 2 here) so the scrub is
// proven end-to-end, not just in assembleEnv.
func acceptRowEnvScrub(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "gh-secret")
	t.Setenv("ANTHROPIC_API_KEY", "sk-secret")
	ws := t.TempDir()

	// Construct AFTER Setenv: the executor snapshots os.Environ at build.
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	// Per-row Guarantees(): EnvScrub must be claimed.
	if !e.Guarantees().EnvScrub {
		t.Errorf("Guarantees().EnvScrub = false, want true for a non-inherit policy")
	}

	command := portableEnvironmentCommand()
	out, code, err := e.RunCommand(context.Background(), ws, command)
	if err != nil {
		t.Fatalf("RunCommand(%s): %v (out=%q)", command, err, out)
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
