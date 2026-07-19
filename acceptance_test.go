package sandbox

// Acceptance matrix — SPEC §12.1. This file asserts the PLATFORM-INDEPENDENT rows
// (and the sandbox-side mechanisms the harness-integration rows build on) that the
// sandbox module can prove on its own: the null / rung-3 fallback and env scrub.
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
		{"no-sandbox-available/rung3-null", acceptRowNullBackend},
		{"env-scrub", acceptRowEnvScrub},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.run(t) })
	}
}

// acceptRowNullBackend — §12.1 "No sandbox available (rung 3 / nil runner)": with
// no OS mechanism the command STILL runs (direct exec), but the executor reports
// LevelNone with EnvScrub as its only guarantee — the honest posture the interlock
// reads to route to ask-a-human rather than auto-approve.
func acceptRowNullBackend(t *testing.T) {
	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(PolicyFor(Write, ws), withBackend(newNullBackend()))
	if err != nil {
		t.Fatalf("NewExecutor(null): %v", err)
	}

	if lvl := e.Level(); lvl != LevelNone {
		t.Errorf("Level() = %d, want LevelNone (%d)", lvl, LevelNone)
	}
	// Per-row Guarantees(): EnvScrub only (scrub is executor-side); everything else
	// fail-closed false because nothing is OS-enforced.
	assertGuarantees(t, e.Guarantees(), Guarantees{EnvScrub: true})

	// The command still runs.
	out, code, err := e.RunCommand(context.Background(), ws, "printf ran")
	if err != nil {
		t.Fatalf("RunCommand under null: %v (out=%q)", err, out)
	}
	if code != 0 || string(out) != "ran" {
		t.Errorf("null-backend run: code=%d out=%q, want 0 / %q", code, out, "ran")
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
	e, err := newExecutorForEffectivePolicy(PolicyFor(Write, ws))
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
