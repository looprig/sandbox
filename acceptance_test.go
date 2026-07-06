package sandbox

// Acceptance matrix — SPEC §12.1. This file asserts the PLATFORM-INDEPENDENT rows
// (and the sandbox-side mechanisms the harness-integration rows build on) that the
// sandbox module can prove on its own: the null / rung-3 fallback, env scrub,
// dynamic-mode generation bump (the sandbox side of a ceiling downgrade), and
// grant retry + fabricated-token rejection. Linux-rung rows live in
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
	"time"
)

// acceptTime is a fixed instant for grant-expiry determinism (no time.Now in
// assertions): TTLs are computed against it via withClock so a minted token never
// expires mid-test.
var acceptTime = time.Unix(1_700_000_000, 0)

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
		{"dynamic-downgrade/generation-bump", acceptRowDynamicDowngrade},
		{"grant-retry-and-fabricated-token", acceptRowGrantRetry},
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
	e, err := NewExecutor(PolicyFor(Write, ws), withBackend(newNullBackend()))
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
	e, err := NewExecutor(PolicyFor(Write, ws))
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

// acceptRowDynamicDowngrade — §12.1 "Dynamic downgrade trusted → readonly": the
// SANDBOX-SIDE mechanism a ceiling downgrade relies on (§8, §9.2) is that any mode
// change bumps the policy generation, so a grant minted before the change no longer
// verifies (stale session grants become inert). Demonstrated across a genuine
// downgrade between two net-blocked modes (Write → ReadOnly) so a mintable net
// grant exists to be invalidated — Trusted mints none (its egress is open).
func acceptRowDynamicDowngrade(t *testing.T) {
	ws := t.TempDir()
	src := &fakeSrc{mode: Write} // net blocked → a net grant can be minted
	e, err := NewExecutorDynamic(src, ws)
	if err != nil {
		t.Fatalf("NewExecutorDynamic: %v", err)
	}
	e.clock = func() time.Time { return acceptTime } // white-box: dynamic ctor takes no ExecOption

	// Env scrub holds across the flip regardless of backend — the stable per-row
	// Guarantee to assert before and after.
	if !e.Guarantees().EnvScrub {
		t.Errorf("pre-downgrade Guarantees().EnvScrub = false, want true")
	}

	dir, cmd := ws, "true"
	grants := e.PlanGrants(dir, cmd)
	if len(grants) != 1 {
		t.Fatalf("PlanGrants at Write: got %d grants, want 1 (net blocked)", len(grants))
	}
	genBefore := e.policyGen

	// Downgrade Write → ReadOnly: the next spawn recompiles and bumps the
	// generation, so the pre-downgrade grant fails verification and does NOT run.
	src.mode = ReadOnly
	_, _, err = e.RunCommandWithGrants(context.Background(), dir, cmd, grants)
	if err == nil {
		t.Fatal("RunCommandWithGrants after downgrade: err = nil, want a grant error (stale grant must be inert)")
	}
	if !errors.Is(err, ErrGrantWrongGeneration) {
		t.Errorf("after downgrade: err = %v, want ErrGrantWrongGeneration", err)
	}
	if e.policyGen == genBefore {
		t.Errorf("policyGen did not bump across the downgrade: still %d", e.policyGen)
	}
	if !e.Guarantees().EnvScrub {
		t.Errorf("post-downgrade Guarantees().EnvScrub = false, want true")
	}
}

// acceptRowGrantRetry — §12.1 "Grant retry (post-denial)" + the fabricated-token
// defense: PlanGrants mints a candidate token for the net-denied policy; a genuine
// minted token verifies and the command runs a SINGLE spawn; a fabricated/garbage
// token returns a TYPED error and never runs (so it can never even reach a prompt).
// Pinned to the null backend + a fixed clock for determinism.
func acceptRowGrantRetry(t *testing.T) {
	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws),
		withBackend(newNullBackend()),
		withClock(func() time.Time { return acceptTime }),
	)
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	// Per-row Guarantees(): the null posture the grant flow runs under.
	assertGuarantees(t, e.Guarantees(), Guarantees{EnvScrub: true})

	dir, cmd := ws, "printf CONFORMANCE_RAN"
	grants := e.PlanGrants(dir, cmd)
	if len(grants) != 1 {
		t.Fatalf("PlanGrants (net blocked): got %d, want 1", len(grants))
	}
	// The genuine token describes for the prompt.
	if desc, ok := e.DescribeGrant(grants[0]); !ok || desc == "" {
		t.Errorf("DescribeGrant(genuine) = (%q,%v), want a non-empty description and true", desc, ok)
	}

	// Fabricated token: no description, a typed error, and NO spawn.
	const fabricated = "lrsx1.garbage.garbage"
	if _, ok := e.DescribeGrant(fabricated); ok {
		t.Error("DescribeGrant(fabricated) = (,true), want (,false) — a forged token must never reach a prompt")
	}
	out, code, err := e.RunCommandWithGrants(context.Background(), dir, cmd, []string{fabricated})
	if err == nil {
		t.Fatal("RunCommandWithGrants(fabricated): err = nil, want a typed grant error")
	}
	if !errors.Is(err, ErrGrantBadMAC) {
		t.Errorf("RunCommandWithGrants(fabricated): err = %v, want ErrGrantBadMAC", err)
	}
	if strings.Contains(string(out), "CONFORMANCE_RAN") || code != -1 {
		t.Errorf("fabricated token RAN the command (out=%q code=%d) — FAIL-OPEN", out, code)
	}

	// Genuine token: verifies and runs exactly one spawn.
	out, code, err = e.RunCommandWithGrants(context.Background(), dir, cmd, grants)
	if err != nil {
		t.Fatalf("RunCommandWithGrants(genuine): %v (out=%q)", err, out)
	}
	if code != 0 || !strings.Contains(string(out), "CONFORMANCE_RAN") {
		t.Errorf("genuine grant run: code=%d out=%q, want 0 / contains CONFORMANCE_RAN", code, out)
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
