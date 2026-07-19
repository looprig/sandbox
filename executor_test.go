package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
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
	// pin null: this asserts null-backend semantics (LevelNone, EnvScrub-only bits,
	// empty report), not the platform backend that platformBackend() selects here.
	e, err := NewExecutor(PolicyFor(Write, ws), withBackend(newNullBackend()))
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

// TestRunCommandContextTimeout asserts a deadline that fires DURING the run is a
// visible error (ctx.Err()) with code -1, symmetric with cancel-before-start —
// not a silent nil-error signal kill.
func TestRunCommandContextTimeout(t *testing.T) {
	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, code, err := e.RunCommand(ctx, ws, "sleep 5")
	if err == nil {
		t.Fatal("RunCommand under a short deadline: err = nil, want ctx.Err()")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("RunCommand timeout: err = %v, want context.DeadlineExceeded", err)
	}
	if code != -1 {
		t.Errorf("RunCommand timeout: code = %d, want -1", code)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("RunCommand timeout: took %v, want the deadline to kill it promptly", elapsed)
	}
}

// TestRunArgvNonexistentBinary asserts a missing binary is a spawn error (non-nil
// err), the other side of the RAN-vs-failed convention for the argv path.
func TestRunArgvNonexistentBinary(t *testing.T) {
	ws := t.TempDir()
	// pin null: this asserts null-backend spawn semantics — argv[0] is the missing
	// binary, so exec fails with a Go spawn error. A real OS backend wraps argv[0]
	// with sandbox-exec, which RUNS and exits nonzero (a ran-but-nonzero, not a
	// spawn error), so the convention this test pins holds only for the null backend.
	e, err := NewExecutor(PolicyFor(Write, ws), withBackend(newNullBackend()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	_, _, err = e.RunArgv(context.Background(), ws, []string{"/no/such/bin"})
	if err == nil {
		t.Error("RunArgv(/no/such/bin): err = nil, want a spawn error")
	}
}

// TestAssembleEnvBadAllowGlob asserts a malformed Allow glob fails closed:
// path.Match returns ErrBadPattern, envNameMatches treats it as a non-match, and
// the call neither panics nor admits anything through the bad pattern.
func TestAssembleEnvBadAllowGlob(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret")

	env := assembleEnv(Policy{Env: EnvPolicy{Allow: []string{"LC_["}}})
	if env == nil {
		t.Fatal("assembleEnv(scrub) = nil for a bad-glob scrub policy; want non-nil")
	}
	if hasEnvName(env, "GITHUB_TOKEN") {
		t.Errorf("bad Allow glob admitted GITHUB_TOKEN (must fail closed): %v", env)
	}
}

// TestAssembleEnvScrubNeverNil is the C1 fail-open regression guard: a directly
// constructed scrub policy with no matching var and no Set must yield a non-nil,
// empty slice — never nil, which would make exec.Cmd inherit the ENTIRE parent
// environment and leak every secret. It also checks end-to-end that a planted
// secret never reaches the child, without relying on PolicyFor's incidental
// TMPDIR-in-Set masking.
func TestAssembleEnvScrubNeverNil(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret")

	env := assembleEnv(Policy{Env: EnvPolicy{}})
	if env == nil {
		t.Fatal("assembleEnv(scrub) = nil; want non-nil empty slice (nil => exec inherits ALL parent env)")
	}
	if hasEnvName(env, "GITHUB_TOKEN") {
		t.Errorf("scrub env leaked GITHUB_TOKEN: %v", env)
	}

	// End-to-end: a scrub Policy with an EMPTY EnvPolicy (no TMPDIR in Set) must
	// still keep the secret out of the child's environment.
	ws := t.TempDir()
	e, err := NewExecutor(Policy{Workspace: ws, Env: EnvPolicy{}})
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	out, _, err := e.RunCommand(context.Background(), ws, "env")
	if err != nil {
		t.Fatalf("RunCommand(env): %v", err)
	}
	if strings.Contains(string(out), "GITHUB_TOKEN") {
		t.Errorf("scrub policy leaked GITHUB_TOKEN to child:\n%s", out)
	}
}

// --- Task 6b: external executor, dynamic mode, grants, read-only view, home guard, Wrap ---

// fakeSrc is a mutable ModeSource for the dynamic-mode tests: flipping mode lets
// a test drive a mode change between spawns and observe the policy-generation
// bump that invalidates stale grants.
type fakeSrc struct{ mode Mode }

func (f *fakeSrc) Current() Mode { return f.mode }

// allGuaranteeBits is every defined guarantee bit — the FULL posture an external
// executor asserts by explicit deployment declaration.
const allGuaranteeBits = GuaranteeProcessBoundary | GuaranteeWriteBoundary | GuaranteeReadDenies |
	GuaranteeEnvScrub | GuaranteeNetworkBoundary | GuaranteeAddressNetwork | GuaranteeResourceLimits

// TestExternalExecutor pins §11: an external executor passes commands through
// (same as null), still scrubs the environment, reports LevelExternal, and
// asserts the FULL set of guarantees (trust by explicit declaration).
func TestExternalExecutor(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret")
	ws := t.TempDir()

	e := NewExternalExecutor(ExternalDecl{Boundary: "docker", Env: EnvPolicy{}})

	if e.Level() != LevelExternal {
		t.Errorf("Level() = %d, want LevelExternal (%d)", e.Level(), LevelExternal)
	}
	if bits := e.GuaranteeBits(); bits != allGuaranteeBits {
		t.Errorf("GuaranteeBits() = %#b, want all bits %#b", bits, allGuaranteeBits)
	}
	g := e.Guarantees()
	if !(g.ProcessBoundary && g.WriteBoundary && g.ReadDenies && g.EnvScrub &&
		g.NetworkBoundary && g.AddressNetwork && g.ResourceLimits) {
		t.Errorf("Guarantees() = %+v, want every field true", g)
	}

	// Passthrough run works.
	out, code, err := e.RunCommand(context.Background(), ws, "echo hi")
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if code != 0 || !strings.Contains(string(out), "hi") {
		t.Errorf("RunCommand: code=%d out=%q, want 0 / contains hi", code, out)
	}

	// Scrub still applies inside the external boundary: the baseline keeps PATH
	// but drops harness secrets.
	out, _, err = e.RunCommand(context.Background(), ws, "env")
	if err != nil {
		t.Fatalf("RunCommand(env): %v", err)
	}
	if strings.Contains(string(out), "GITHUB_TOKEN") {
		t.Errorf("external child leaked GITHUB_TOKEN:\n%s", out)
	}

	// An external executor never offers escalation tokens: it is fully trusted and
	// egress is infra-handled, so a "net" candidate (which its zero-Net policy
	// would otherwise trip) must not be minted.
	if g := e.PlanGrants(ws, "curl https://example.com"); g != nil {
		t.Errorf("external PlanGrants = %v, want nil (no escalation from LevelExternal)", g)
	}
}

// TestExecutorDynamicGenBumpInvalidatesGrants is the load-bearing dynamic test:
// a grant minted under mode A verifies and runs, but after the ModeSource flips
// to a different mode the recompile bumps the policy generation, so the SAME
// grant now fails verification with ErrGrantWrongGeneration and does not run.
func TestExecutorDynamicGenBumpInvalidatesGrants(t *testing.T) {
	ws := t.TempDir()
	src := &fakeSrc{mode: Write} // net blocked → PlanGrants offers a net delta

	e, err := NewExecutorDynamic(src, ws)
	if err != nil {
		t.Fatalf("NewExecutorDynamic: %v", err)
	}
	// Deterministic time so TTL never expires mid-test (white-box injection: the
	// dynamic constructor takes only PolicyOptions).
	e.clock = func() time.Time { return time.Unix(1_700_000_000, 0) }

	dir, cmd := ws, "true"
	grants := e.PlanGrants(dir, cmd)
	if len(grants) != 1 {
		t.Fatalf("PlanGrants at Write: got %d grants, want 1 (net blocked)", len(grants))
	}

	// Under the minting mode the grant verifies and the command runs.
	genA := e.policyGen
	if _, _, err := e.RunCommandWithGrants(context.Background(), dir, cmd, grants); err != nil {
		t.Fatalf("RunCommandWithGrants at mode A: %v", err)
	}

	// Same-mode stability: repeated same-mode spawns must NOT bump the generation
	// (a no-op recompile that bumped would spuriously void live grants).
	if _, _, err := e.RunCommand(context.Background(), dir, cmd); err != nil {
		t.Fatalf("RunCommand same mode: %v", err)
	}
	if e.policyGen != genA {
		t.Errorf("policyGen bumped on a same-mode spawn: %d -> %d, want stable", genA, e.policyGen)
	}

	// Flip the mode: the next spawn recompiles and bumps policyGen, voiding the
	// grant minted under the old generation.
	src.mode = Trusted
	_, _, err = e.RunCommandWithGrants(context.Background(), dir, cmd, grants)
	if err == nil {
		t.Fatal("RunCommandWithGrants after mode flip: err = nil, want a grant error")
	}
	if !errors.Is(err, ErrGrantWrongGeneration) {
		t.Errorf("after mode flip: err = %v, want ErrGrantWrongGeneration", err)
	}
	if e.policyGen == genA {
		t.Errorf("policyGen did not bump across a mode change: still %d", e.policyGen)
	}
}

// atomicSrc is a goroutine-safe ModeSource for the concurrency stress test. The
// executor's mutex guards its OWN compiled state, not the ModeSource; a real
// source is responsible for its own synchronization, so the test uses an atomic
// one to keep the race detector focused on the executor rather than flagging the
// test harness's own unsynchronized field.
type atomicSrc struct{ m atomic.Uint32 }

func (a *atomicSrc) Current() Mode { return Mode(a.m.Load()) }
func (a *atomicSrc) set(mode Mode) { a.m.Store(uint32(mode)) }

// TestExecutorDynamicConcurrentRace makes the dynamic-mutex claim load-bearing:
// many goroutines hammer the spawn/plan/inspect paths of one dynamic executor
// while another goroutine flips the mode in a tight loop. Run under -race it
// proves the per-spawn recompile and the compiled-snapshot reads are properly
// serialized (no torn reads, no data race, no panic).
func TestExecutorDynamicConcurrentRace(t *testing.T) {
	ws := t.TempDir()
	src := &atomicSrc{}
	src.set(Write)

	e, err := NewExecutorDynamic(src, ws)
	if err != nil {
		t.Fatalf("NewExecutorDynamic: %v", err)
	}
	ctx := context.Background()

	stop := make(chan struct{})
	var flipper sync.WaitGroup
	flipper.Add(1)
	go func() {
		defer flipper.Done()
		modes := []Mode{ZeroTrust, ReadOnly, Write, Trusted}
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
				src.set(modes[i%len(modes)])
			}
		}
	}()

	const workers = 8
	var work sync.WaitGroup
	for w := 0; w < workers; w++ {
		work.Add(1)
		go func() {
			defer work.Done()
			for i := 0; i < 100; i++ {
				// Lock-heavy, cheap paths dominate; an occasional real spawn keeps
				// the run path in the mix without spawning thousands of processes.
				_ = e.PlanGrants(ws, "true")
				_ = e.Level()
				_ = e.GuaranteeBits()
				_ = e.Report()
				if i%20 == 0 {
					_, _, _ = e.RunCommand(ctx, ws, "true")
				}
			}
		}()
	}

	work.Wait()
	close(stop)
	flipper.Wait()

	// Sanity: the executor is still usable and reports a valid level after the storm.
	if lvl := e.Level(); lvl > LevelExternal {
		t.Errorf("post-storm Level() = %d, out of range", lvl)
	}
}

// TestExecutorGrantRoundTrip covers the mint→describe→run happy path plus the
// two rejection paths: a fabricated token never describes and never runs, and an
// expired token fails with ErrGrantExpired.
func TestExecutorGrantRoundTrip(t *testing.T) {
	ws := t.TempDir()
	base := time.Unix(1_700_000_000, 0)
	now := base
	e, err := NewExecutor(PolicyFor(Write, ws), withClock(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	dir, cmd := ws, "true"
	grants := e.PlanGrants(dir, cmd)
	if len(grants) != 1 {
		t.Fatalf("PlanGrants: got %d grants, want 1", len(grants))
	}

	// DescribeGrant returns the MAC-bound description.
	desc, ok := e.DescribeGrant(grants[0])
	if !ok {
		t.Fatal("DescribeGrant(valid) = (,false), want (,true)")
	}
	if !strings.Contains(desc, cmd) {
		t.Errorf("DescribeGrant desc = %q, want to mention command %q", desc, cmd)
	}

	// A valid grant runs.
	if _, _, err := e.RunCommandWithGrants(context.Background(), dir, cmd, grants); err != nil {
		t.Fatalf("RunCommandWithGrants(valid): %v", err)
	}

	// A fabricated token cannot describe and cannot run.
	if _, ok := e.DescribeGrant("lrsx1.garbage.garbage"); ok {
		t.Error("DescribeGrant(fabricated) = (,true), want (,false)")
	}
	_, _, err = e.RunCommandWithGrants(context.Background(), dir, cmd, []string{"lrsx1.garbage.garbage"})
	if err == nil {
		t.Error("RunCommandWithGrants(fabricated): err = nil, want a grant error")
	}

	// An expired token fails with ErrGrantExpired once the clock advances past TTL.
	now = base.Add(16 * time.Minute) // default TTL is 15m
	_, _, err = e.RunCommandWithGrants(context.Background(), dir, cmd, grants)
	if !errors.Is(err, ErrGrantExpired) {
		t.Errorf("RunCommandWithGrants(expired): err = %v, want ErrGrantExpired", err)
	}
}

// TestReadOnlyViewStatic asserts a read-only view of a Write-mode executor
// strips writes, forces network blocked, and disables granting — the read path
// never escalates — while reusing the parent's backend.
func TestReadOnlyViewStatic(t *testing.T) {
	ws := t.TempDir()
	parent, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	view := parent.ReadOnlyView()

	if view.backend != parent.backend {
		t.Error("ReadOnlyView re-probed a backend; want the parent's backend reused")
	}

	acc := Resolve(view.policy.FS, ws)
	if acc&WriteAccess != 0 {
		t.Errorf("ReadOnlyView resolved access for workspace = %v, has WriteAccess (want stripped)", acc)
	}
	if acc&ReadAccess == 0 {
		t.Errorf("ReadOnlyView resolved access for workspace = %v, missing ReadAccess", acc)
	}
	if acc := Resolve(view.policy.FS, "/dev/null"); acc&WriteAccess == 0 {
		t.Errorf("ReadOnlyView resolved access for /dev/null = %v, missing non-persistent WriteAccess", acc)
	}
	if !netBlocked(view.policy) {
		t.Errorf("ReadOnlyView Net = %+v, want blocked", view.policy.Net)
	}
	if g := view.PlanGrants(ws, "curl https://example.com"); g != nil {
		t.Errorf("ReadOnlyView.PlanGrants = %v, want nil (granting disabled)", g)
	}

	// Fail closed on redeem too: even a grant the PARENT minted (shared key, same
	// generation) cannot loosen the view — the read path never escalates.
	parentGrants := parent.PlanGrants(ws, "curl https://example.com")
	if len(parentGrants) == 0 {
		t.Fatal("parent PlanGrants returned no grant; expected one for net-blocked Write")
	}
	if _, _, err := view.RunCommandWithGrants(context.Background(), ws, "curl https://example.com", parentGrants); err == nil {
		t.Error("ReadOnlyView.RunCommandWithGrants: err = nil, want fail-closed error")
	}
}

// TestReadOnlyViewDynamic asserts the read-only mask is applied on each recompile
// for a dynamic parent: even at a write-capable mode the view resolves no write,
// blocks net, and grants nothing.
func TestReadOnlyViewDynamic(t *testing.T) {
	ws := t.TempDir()
	src := &fakeSrc{mode: Trusted} // write + open-ish net at the parent
	parent, err := NewExecutorDynamic(src, ws)
	if err != nil {
		t.Fatalf("NewExecutorDynamic: %v", err)
	}
	view := parent.ReadOnlyView()
	if view.backend != parent.backend {
		t.Error("ReadOnlyView re-probed a backend; want the parent's backend reused")
	}

	// Force a recompile at the current mode and inspect the masked policy.
	s, err := view.resolve()
	if err != nil {
		t.Fatalf("view.resolve: %v", err)
	}
	if acc := Resolve(s.policy.FS, ws); acc&WriteAccess != 0 {
		t.Errorf("dynamic ReadOnlyView resolved access = %v, has WriteAccess", acc)
	}
	if !netBlocked(s.policy) {
		t.Errorf("dynamic ReadOnlyView Net = %+v, want blocked", s.policy.Net)
	}
	if g := view.PlanGrants(ws, "curl x"); g != nil {
		t.Errorf("dynamic ReadOnlyView.PlanGrants = %v, want nil", g)
	}
}

// TestHomeGuard pins the fail-closed home guard: with an unresolvable home a
// non-unconfined NewExecutor refuses to build (its secret denials could not
// materialize), unconfined is exempt (Inherit, no secret denials), and
// NewExecutorDynamic always refuses.
func TestHomeGuard(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("HOME", "")

	if _, err := NewExecutor(PolicyFor(Write, ws)); err == nil {
		t.Error("NewExecutor(Write) with unresolvable HOME: err = nil, want error")
	}
	if _, err := NewExecutor(PolicyFor(Unconfined, ws, WithAckUnconfined())); err != nil {
		t.Errorf("NewExecutor(Unconfined) with unresolvable HOME: err = %v, want nil (exempt)", err)
	}
	if _, err := NewExecutorDynamic(&fakeSrc{mode: Write}, ws); err == nil {
		t.Error("NewExecutorDynamic with unresolvable HOME: err = nil, want error (always)")
	}
	// External is exempt: construction cannot fail.
	if e := NewExternalExecutor(ExternalDecl{Boundary: "docker"}); e == nil {
		t.Error("NewExternalExecutor with unresolvable HOME: nil, want a built executor")
	}
}

// TestWrap asserts Wrap applies the scrubbed environment to a caller-built cmd:
// a planted GITHUB_TOKEN is absent from the wrapped command's Env. It pins the
// null backend via withBackend: Wrap is only supported on backends with no
// per-spawn cleanup (null/seatbelt/external), and on Linux the real platform
// backend is the re-exec linuxBackend, whose wrap returns a cleanup — so Wrap
// there fails closed by design (see TestWrapFailsClosedOnReexecBackend). This unit
// test exercises Wrap's env-scrub logic on the null backend, backend-independently.
func TestWrap(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret")
	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws), withBackend(newNullBackend()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	cmd := exec.Command("echo", "hi")
	wrapped, err := e.Wrap(cmd)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if hasEnvName(wrapped.Env, "GITHUB_TOKEN") {
		t.Errorf("Wrap did not scrub env; GITHUB_TOKEN present in %v", wrapped.Env)
	}
	// The scrubbed env is exactly the executor's assembled env.
	if len(wrapped.Env) != len(e.env) {
		t.Errorf("Wrap Env length = %d, want %d (executor env)", len(wrapped.Env), len(e.env))
	}
}

// --- Task 7: unconfined ack gate + EnvScrub guarantee honesty ---

// TestUnconfinedRequiresAck pins the construction-time gate: an Unconfined preset
// policy WITHOUT AckUnconfined must refuse to build (SPEC §4, §6). Running
// unconfined is stepping off the ladder — it requires an explicit acknowledgement.
func TestUnconfinedRequiresAck(t *testing.T) {
	ws := t.TempDir()
	_, err := NewExecutor(PolicyFor(Unconfined, ws))
	if err == nil {
		t.Fatal("NewExecutor(Unconfined) without ack: err = nil, want ErrUnconfinedNotAcked")
	}
	if !errors.Is(err, ErrUnconfinedNotAcked) {
		t.Errorf("NewExecutor(Unconfined) without ack: err = %v, want ErrUnconfinedNotAcked", err)
	}
}

// TestUnconfinedAckedRunsWithNoGuarantees asserts the acked path: with
// WithAckUnconfined the executor builds and runs a command (passthrough), and its
// Guarantees() are ALL false — including EnvScrub, because Env.Inherit means the
// child inherits everything and nothing is actually scrubbed (guarantee honesty).
func TestUnconfinedAckedRunsWithNoGuarantees(t *testing.T) {
	ws := t.TempDir()
	// pin null: this asserts null-backend guarantee semantics (ALL guarantees false,
	// bits == 0 for an Inherit/Open unconfined policy). The Seatbelt backend always
	// sets GuaranteeProcessBoundary (sandbox-exec still wraps the spawn), so this
	// "no guarantees" assertion is a null-backend property, not the platform's.
	e, err := NewExecutor(PolicyFor(Unconfined, ws, WithAckUnconfined()), withBackend(newNullBackend()))
	if err != nil {
		t.Fatalf("NewExecutor(Unconfined, ack): %v", err)
	}

	out, code, err := e.RunCommand(context.Background(), ws, "echo hi")
	if err != nil {
		t.Fatalf("RunCommand: %v", err)
	}
	if code != 0 || !strings.Contains(string(out), "hi") {
		t.Errorf("RunCommand: code=%d out=%q, want 0 / contains hi", code, out)
	}

	g := e.Guarantees()
	if g.EnvScrub {
		t.Error("unconfined Guarantees().EnvScrub = true, want false (Inherit => not scrubbed)")
	}
	if g.ProcessBoundary || g.WriteBoundary || g.ReadDenies ||
		g.NetworkBoundary || g.AddressNetwork || g.ResourceLimits {
		t.Errorf("unconfined Guarantees() = %+v, want ALL false", g)
	}
	if bits := e.GuaranteeBits(); bits != 0 {
		t.Errorf("unconfined GuaranteeBits() = %#b, want 0 (no guarantees for unconfined)", bits)
	}
}

// TestWriteStillScrubsEnv is the honesty-fix regression guard for the normal
// (confined) case: a Write policy does NOT inherit, so the null backend still
// asserts EnvScrub. This confirms making EnvScrub conditional on !Inherit did not
// disturb the scrubbed path.
func TestWriteStillScrubsEnv(t *testing.T) {
	ws := t.TempDir()
	// pin null: this asserts the null-backend EnvScrub-honesty semantics (a confined
	// Write policy still asserts EnvScrub). It is a backend-derived Guarantee, so it
	// is pinned to null to stay deterministic and platform-independent.
	e, err := NewExecutor(PolicyFor(Write, ws), withBackend(newNullBackend()))
	if err != nil {
		t.Fatalf("NewExecutor(Write): %v", err)
	}
	if !e.Guarantees().EnvScrub {
		t.Error("Write Guarantees().EnvScrub = false, want true (env is scrubbed)")
	}
}

// TestUnconfinedAckDynamicFailsClosed pins the dynamic (recompile) side of the
// gate: a ModeSource that flips to Unconfined with NO WithAckUnconfined in popts
// makes the spawn fail CLOSED via resolve (ErrUnconfinedNotAcked) rather than
// silently running unconfined; with WithAckUnconfined in popts the unconfined
// spawn succeeds.
func TestUnconfinedAckDynamicFailsClosed(t *testing.T) {
	ws := t.TempDir()

	// Start at Write so construction succeeds, then flip to Unconfined.
	src := &fakeSrc{mode: Write}
	e, err := NewExecutorDynamic(src, ws) // no WithAckUnconfined in popts
	if err != nil {
		t.Fatalf("NewExecutorDynamic: %v", err)
	}
	src.mode = Unconfined
	if _, _, err := e.RunCommand(context.Background(), ws, "echo hi"); !errors.Is(err, ErrUnconfinedNotAcked) {
		t.Errorf("dynamic flip to Unconfined w/o ack: err = %v, want ErrUnconfinedNotAcked", err)
	}

	// With WithAckUnconfined in popts the unconfined spawn runs.
	src2 := &fakeSrc{mode: Write}
	e2, err := NewExecutorDynamic(src2, ws, WithAckUnconfined())
	if err != nil {
		t.Fatalf("NewExecutorDynamic(acked): %v", err)
	}
	src2.mode = Unconfined
	out, code, err := e2.RunCommand(context.Background(), ws, "echo hi")
	if err != nil {
		t.Fatalf("acked unconfined spawn: %v", err)
	}
	if code != 0 || !strings.Contains(string(out), "hi") {
		t.Errorf("acked unconfined spawn: code=%d out=%q, want 0 / contains hi", code, out)
	}
}

// TestManualUnconfinedRequiresAck proves the gate catches consumer-constructed
// policies, not just the Unconfined preset, and that grantsUnconfined is
// Inherit OR Open (either flag alone means no meaningful confinement). Inherit
// exempts the home guard, so the ack check is the one that fires; HOME is set so
// the Net.Open case (which does NOT exempt the home guard) surfaces the ack error
// too rather than a home error.
func TestManualUnconfinedRequiresAck(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("HOME", t.TempDir())

	if _, err := NewExecutor(Policy{Workspace: ws, Env: EnvPolicy{Inherit: true}}); !errors.Is(err, ErrUnconfinedNotAcked) {
		t.Errorf("manual Inherit without ack: err = %v, want ErrUnconfinedNotAcked", err)
	}
	if _, err := NewExecutor(Policy{Workspace: ws, Net: NetPolicy{Open: true}}); !errors.Is(err, ErrUnconfinedNotAcked) {
		t.Errorf("manual Net.Open without ack: err = %v, want ErrUnconfinedNotAcked", err)
	}
	// With the ack, a manual Inherit policy builds fine.
	if _, err := NewExecutor(Policy{Workspace: ws, Env: EnvPolicy{Inherit: true}, AckUnconfined: true}); err != nil {
		t.Errorf("manual Inherit WITH ack: err = %v, want nil", err)
	}
}

// TestExternalEnvScrubHonesty pins the external-executor guarantee-honesty fix
// (same bug as the null backend, one path over): NewExternalExecutor hardcodes the
// FULL guarantee set by deployment declaration, but EnvScrub is the one property it
// can actually check against decl.Env. An ExternalDecl with Env.Inherit passes the
// whole parent environment through unscrubbed, so EnvScrub must be false while the
// other 6 (trust-by-declaration) stay true; a scrubbing decl.Env keeps all 7.
func TestExternalEnvScrubHonesty(t *testing.T) {
	// Inherit: EnvScrub honestly false, the other 6 still true.
	inh := NewExternalExecutor(ExternalDecl{Boundary: "docker", Env: EnvPolicy{Inherit: true}})
	g := inh.Guarantees()
	if g.EnvScrub {
		t.Error("external Inherit Guarantees().EnvScrub = true, want false (env not scrubbed)")
	}
	if !(g.ProcessBoundary && g.WriteBoundary && g.ReadDenies &&
		g.NetworkBoundary && g.AddressNetwork && g.ResourceLimits) {
		t.Errorf("external Inherit Guarantees() = %+v, want the other 6 all true", g)
	}
	if bits := inh.GuaranteeBits(); bits != allGuaranteeBits&^GuaranteeEnvScrub {
		t.Errorf("external Inherit GuaranteeBits() = %#b, want all-but-EnvScrub %#b", bits, allGuaranteeBits&^GuaranteeEnvScrub)
	}

	// Scrubbing decl.Env (zero EnvPolicy = baseline scrub): all 7 true.
	scr := NewExternalExecutor(ExternalDecl{Boundary: "docker", Env: EnvPolicy{}})
	if bits := scr.GuaranteeBits(); bits != allGuaranteeBits {
		t.Errorf("external scrub GuaranteeBits() = %#b, want all 7 %#b", bits, allGuaranteeBits)
	}
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
