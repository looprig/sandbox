package sandbox

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestNewExecutorNullBackendGuarantees pins the null-backend posture: no OS
// enforcement was achieved (LevelNone) and the ONLY property the executor can
// honestly guarantee is env scrubbing — which it performs itself, independent of
// any backend. Every other guarantee must be false (fail-closed): with no OS
// backend, nothing else is enforced.
func TestNewExecutorNullBackendGuarantees(t *testing.T) {
	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	if e.Level() != LevelNone {
		t.Errorf("Level() = %d, want LevelNone (%d)", e.Level(), LevelNone)
	}

	g := e.Guarantees()
	if !g.EnvScrub {
		t.Error("Guarantees().EnvScrub = false, want true (executor always scrubs env)")
	}
	if g.ProcessBoundary || g.WriteBoundary || g.ReadDenies ||
		g.NetworkBoundary || g.AddressNetwork || g.ResourceLimits {
		t.Errorf("Guarantees() = %+v, want only EnvScrub true (null backend enforces nothing else)", g)
	}

	if got := e.GuaranteeBits(); got != GuaranteeEnvScrub {
		t.Errorf("GuaranteeBits() = %d, want GuaranteeEnvScrub (%d)", got, GuaranteeEnvScrub)
	}

	// Report is empty for the null backend: it neither enforces nor narrows.
	if len(e.Report().Entries) != 0 {
		t.Errorf("Report().Entries = %+v, want empty for null backend", e.Report().Entries)
	}
}

// TestRunCommand covers the shell-string path and the RAN-vs-failed exit-code
// convention: a process that runs returns (output, exitCode, nil) with the real
// code even when non-zero; only a spawn/setup failure returns a non-nil error.
func TestRunCommand(t *testing.T) {
	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	ctx := context.Background()

	out, code, err := e.RunCommand(ctx, ws, "echo hi")
	if err != nil {
		t.Fatalf("RunCommand(echo hi): unexpected err %v", err)
	}
	if code != 0 {
		t.Errorf("RunCommand(echo hi): exit = %d, want 0", code)
	}
	if !strings.Contains(string(out), "hi") {
		t.Errorf("RunCommand(echo hi): output = %q, want to contain %q", out, "hi")
	}

	// A non-zero exit is a successful RUN, not an error.
	_, code, err = e.RunCommand(ctx, ws, "exit 3")
	if err != nil {
		t.Fatalf("RunCommand(exit 3): got err %v, want nil (the process ran)", err)
	}
	if code != 3 {
		t.Errorf("RunCommand(exit 3): exit = %d, want 3", code)
	}
}

// TestRunArgv covers the direct-argv path: no shell is interposed, so shell
// metacharacters are literal arguments rather than syntax.
func TestRunArgv(t *testing.T) {
	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	ctx := context.Background()

	out, code, err := e.RunArgv(ctx, ws, []string{"echo", "hi"})
	if err != nil {
		t.Fatalf("RunArgv(echo hi): unexpected err %v", err)
	}
	if code != 0 {
		t.Errorf("RunArgv(echo hi): exit = %d, want 0", code)
	}
	if !strings.Contains(string(out), "hi") {
		t.Errorf("RunArgv(echo hi): output = %q, want to contain %q", out, "hi")
	}

	// No shell: a would-be shell substitution is passed through literally.
	out, _, err = e.RunArgv(ctx, ws, []string{"echo", "$HOME"})
	if err != nil {
		t.Fatalf("RunArgv(echo $HOME): unexpected err %v", err)
	}
	if !strings.Contains(string(out), "$HOME") {
		t.Errorf("RunArgv: output = %q, want the literal %q (no shell expansion)", out, "$HOME")
	}
}

// TestRunCommandSpawnFailure asserts the other side of the convention: a genuine
// spawn/setup failure (working directory does not exist) returns a non-nil error.
func TestRunCommandSpawnFailure(t *testing.T) {
	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	_, _, err = e.RunCommand(context.Background(), ws+"/does-not-exist", "echo hi")
	if err == nil {
		t.Error("RunCommand into a missing dir: err = nil, want a spawn error")
	}
}

// TestEnvScrub is the load-bearing security test: the child sees the §5.5
// baseline plus the forced TMPDIR, and harness secrets such as GITHUB_TOKEN are
// absent. PolicyFor(Write) uses the baseline allowlist (no inheritance) with
// TMPDIR forced to /tmp.
func TestEnvScrub(t *testing.T) {
	if os.Getenv("PATH") == "" {
		t.Setenv("PATH", "/usr/bin:/bin")
	}
	if os.Getenv("HOME") == "" {
		t.Setenv("HOME", t.TempDir())
	}
	t.Setenv("GITHUB_TOKEN", "secret")

	ws := t.TempDir()
	// Construct AFTER Setenv: assembleEnv snapshots os.Environ() at build time.
	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	out, _, err := e.RunCommand(context.Background(), ws, "env")
	if err != nil {
		t.Fatalf("RunCommand(env): %v", err)
	}
	got := string(out)

	if !strings.Contains(got, "TMPDIR=/tmp") {
		t.Errorf("env output missing TMPDIR=/tmp:\n%s", got)
	}
	if !strings.Contains(got, "PATH=") {
		t.Errorf("env output missing PATH= (baseline allowlist should keep it):\n%s", got)
	}
	if strings.Contains(got, "GITHUB_TOKEN") {
		t.Errorf("env output leaked GITHUB_TOKEN (should be scrubbed):\n%s", got)
	}
}

// TestEnvAllowAndInherit covers the two other assembleEnv branches: an explicit
// Allow glob lets a named var through the baseline, and Inherit passes the whole
// parent environment (with Set overrides still forced on top).
func TestEnvAllowAndInherit(t *testing.T) {
	t.Setenv("CARGO_HOME", "/cargo")
	t.Setenv("GITHUB_TOKEN", "secret")

	// Allow: CARGO_* is admitted; GITHUB_TOKEN still is not.
	allowed := assembleEnv(Policy{Env: EnvPolicy{Allow: []string{"CARGO_*"}}})
	if !containsEnv(allowed, "CARGO_HOME=/cargo") {
		t.Errorf("Allow CARGO_*: CARGO_HOME missing from %v", allowed)
	}
	if hasEnvName(allowed, "GITHUB_TOKEN") {
		t.Errorf("Allow CARGO_*: GITHUB_TOKEN should still be scrubbed, got %v", allowed)
	}

	// Inherit: everything passes through, and Set is forced on top.
	inherited := assembleEnv(Policy{Env: EnvPolicy{
		Inherit: true,
		Set:     map[string]string{"GITHUB_TOKEN": "forced"},
	}})
	if !hasEnvName(inherited, "CARGO_HOME") {
		t.Errorf("Inherit: CARGO_HOME missing from inherited env")
	}
	if !containsEnv(inherited, "GITHUB_TOKEN=forced") {
		t.Errorf("Inherit: Set override not applied; want GITHUB_TOKEN=forced in %v", inherited)
	}
	// The override replaced the inherited value rather than duplicating the key.
	if n := countEnvName(inherited, "GITHUB_TOKEN"); n != 1 {
		t.Errorf("Inherit: GITHUB_TOKEN appears %d times, want exactly 1 (override in place)", n)
	}
}

// TestGuaranteesFromBitsRoundTrip asserts the bit<->field mapping is a faithful
// bijection over all 7 bits, and that each single bit lights exactly its one
// matching field (bit order agrees with field order).
func TestGuaranteesFromBitsRoundTrip(t *testing.T) {
	// Round-trip every combination of the 7 defined bits.
	const all = GuaranteeProcessBoundary | GuaranteeWriteBoundary | GuaranteeReadDenies |
		GuaranteeEnvScrub | GuaranteeNetworkBoundary | GuaranteeAddressNetwork | GuaranteeResourceLimits
	for bits := uint64(0); bits <= all; bits++ {
		if bits&^all != 0 {
			continue // skip values with bits outside the defined set
		}
		if got := guaranteesFromBits(bits).bits(); got != bits {
			t.Fatalf("round-trip bits %#b -> struct -> %#b, want identity", bits, got)
		}
	}

	// Each single bit maps to exactly its one field.
	cases := []struct {
		bit uint64
		get func(Guarantees) bool
	}{
		{GuaranteeProcessBoundary, func(g Guarantees) bool { return g.ProcessBoundary }},
		{GuaranteeWriteBoundary, func(g Guarantees) bool { return g.WriteBoundary }},
		{GuaranteeReadDenies, func(g Guarantees) bool { return g.ReadDenies }},
		{GuaranteeEnvScrub, func(g Guarantees) bool { return g.EnvScrub }},
		{GuaranteeNetworkBoundary, func(g Guarantees) bool { return g.NetworkBoundary }},
		{GuaranteeAddressNetwork, func(g Guarantees) bool { return g.AddressNetwork }},
		{GuaranteeResourceLimits, func(g Guarantees) bool { return g.ResourceLimits }},
	}
	for _, c := range cases {
		g := guaranteesFromBits(c.bit)
		if !c.get(g) {
			t.Errorf("bit %#b did not set its matching field: %+v", c.bit, g)
		}
		if g.bits() != c.bit {
			t.Errorf("single-bit %#b lit extra fields: %+v", c.bit, g)
		}
	}
}

// TestExecOptions asserts the ExecOption surface exists and NewExecutor accepts
// it. The values are stored for later tasks (grants, cgroups); here we only
// verify construction succeeds with them applied.
func TestExecOptions(t *testing.T) {
	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws),
		WithGrantTTL(30*time.Second),
		WithCgroupParent("/sys/fs/cgroup/looprig"),
	)
	if err != nil {
		t.Fatalf("NewExecutor with options: %v", err)
	}
	if e == nil {
		t.Fatal("NewExecutor returned nil executor")
	}
}

// TestInit asserts the initialization stub is callable and returns (no-op today,
// load-bearing on Linux later).
func TestInit(t *testing.T) {
	Init() // must not panic; no-op
}

// --- env test helpers ---

func containsEnv(env []string, kv string) bool {
	for _, e := range env {
		if e == kv {
			return true
		}
	}
	return false
}

func hasEnvName(env []string, name string) bool {
	return countEnvName(env, name) > 0
}

func countEnvName(env []string, name string) int {
	n := 0
	for _, e := range env {
		if k, _, ok := strings.Cut(e, "="); ok && k == name {
			n++
		}
	}
	return n
}
