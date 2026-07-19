//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// --- Fork-bomb target dispatch (runs in the re-exec'd, cgroup-joined target) ---
//
// The e2e proof re-runs THIS test binary as the stage-2 TARGET: the linuxBackend
// creates a transient cgroup v2 scope with pids.max=N, joins the stage-2 child at
// clone via CLONE_INTO_CGROUP, and execve's /proc/self/exe (the target). In the
// target the fork-bomb sentinel is set (via the policy's Env.Set) and the dispatch
// sentinel is NOT (it is scrubbed out of the target env), so cgroupForkbombDispatch
// runs a bounded fork loop UNDER the pids cap inherited from the join and prints
// markers the parent asserts on. This proves a fork bomb is capped at pids.max in a
// real post-execve target, composed with the rung-2 Landlock+seccomp confinement.

const (
	// cgroupForkbombEnv marks a process that should run the fork loop and exit. It
	// is injected into the TARGET env via Env.Set, so it is present only after the
	// stage-2 execve — not in the stage-2 helper (which additionally carries
	// stage2SentinelEnv, the distinguisher checked below).
	cgroupForkbombEnv = "LRSANDBOX_CGROUP_FORKBOMB"
	// cgroupForkbombSleep passes the resolved sleep binary path to the target, so
	// the fork loop needs no PATH lookup under confinement.
	cgroupForkbombSleep = "LRSANDBOX_CGROUP_FORKBOMB_SLEEP"
)

// Marker keys the target prints (one KEY=VALUE line each) and the parent parses.
const (
	cgKeySpawned     = "SPAWNED"
	cgKeyOutcome     = "OUTCOME"
	cgKeyPidsCurrent = "PIDS_CURRENT"
	cgKeyPidsMax     = "PIDS_MAX"
)

// Fork-loop outcomes.
const (
	cgOutcomeEAGAIN  = "EAGAIN"  // hit pids.max: a fork failed with EAGAIN
	cgOutcomeNoLimit = "NOLIMIT" // ran the full loop without ever hitting the cap
)

// Tunables mirror the M5 spike. cgMaxSpawnAttempts is the bounded fork-bomb size;
// cgCappedPidsMax is small enough to cap the loop yet large enough to leave the
// target's own Go-runtime threads room (with GOMAXPROCS=1); cgControlPidsMax is
// high enough that the identical loop runs to completion — proving the cap, not
// some ambient limit, is what stopped the capped case.
const (
	cgMaxSpawnAttempts = 60
	cgCappedPidsMax    = 20
	cgControlPidsMax   = 200
	cgSleepSeconds     = "30" // spawned children sleep; teardown kills them
	cgHelperExitConfig = 4    // distinct from a fork-loop outcome (reported via stdout)
)

// cgroupForkbombDispatch runs at package init in the re-exec'd TARGET only: the
// fork-bomb sentinel is set AND the stage-2 dispatch sentinel is NOT (the latter
// is present in the stage-2 helper but scrubbed out of the target env). It runs
// the fork loop under the inherited pids cap, prints markers, and exits — it never
// returns to the test framework. In the parent or in a stage-2 helper it is inert.
func cgroupForkbombDispatch() {
	if os.Getenv(cgroupForkbombEnv) != "1" {
		return // not a fork-bomb target
	}
	if os.Getenv(stage2SentinelEnv) == stage2SentinelValue {
		return // this is the stage-2 helper (pre-execve); let Init()/runStage2 run
	}
	os.Exit(runCgroupForkbomb())
}

// init dispatches the fork-bomb target. It runs before TestMain (which calls
// Init()); guarding on the two sentinels keeps it inert in every process except
// the intended post-execve fork-bomb target.
func init() { cgroupForkbombDispatch() }

// runCgroupForkbomb runs inside the transient cgroup (joined at clone via
// CLONE_INTO_CGROUP). It attempts up to cgMaxSpawnAttempts short-lived sleep
// children, counting how many start before a fork fails with EAGAIN (pids.max
// reached), then reports the count, the outcome, and pids.current / pids.max read
// from its OWN cgroup at that instant. It does not wait for the children — the
// parent's spawn teardown (cgroup.kill) reaps them.
func runCgroupForkbomb() int {
	sleepPath := os.Getenv(cgroupForkbombSleep)
	if sleepPath == "" {
		fmt.Printf("%s=ERR:missing-sleep-path\n", cgKeyOutcome)
		return cgHelperExitConfig
	}
	selfDir, ok := selfCgroupDir()
	if !ok {
		fmt.Printf("%s=ERR:self-cgroup\n", cgKeyOutcome)
		return cgHelperExitConfig
	}

	outcome := cgOutcomeNoLimit
	spawned := 0
	// Keep references so the children stay alive (not GC'd) for the loop; they run
	// until teardown kills them. Their stdout is os.DevNull (exec default), so they
	// never touch the marker stream on the target's stdout pipe.
	started := make([]*exec.Cmd, 0, cgMaxSpawnAttempts)
	for i := 0; i < cgMaxSpawnAttempts; i++ {
		c := exec.Command(sleepPath, cgSleepSeconds)
		// Point the child's stdout/stderr at fd 0 — the read-only /dev/null the
		// (unsandboxed) parent opened for the target's stdin. Two reasons: (1) letting
		// os/exec open os.DevNull ITSELF for the child is DENIED by the rung-2 Landlock
		// ruleset (a write open outside policy roots), which would mask the pids cap as
		// a spurious per-child failure; (2) inheriting the target's stdout pipe would
		// keep it open in the long-lived sleep children after the target exits, so the
		// parent's CombinedOutput would block until WaitDelay. sleep writes nothing, so
		// a read-only sink is harmless and the marker stream stays clean.
		c.Stdout = os.Stdin
		c.Stderr = os.Stdin
		if err := c.Start(); err != nil {
			if errors.Is(err, syscall.EAGAIN) {
				outcome = cgOutcomeEAGAIN
			} else {
				outcome = "ERR:" + err.Error()
			}
			break
		}
		started = append(started, c)
		spawned++
	}

	cur := readCgroupFieldTest(selfDir, "pids.current")
	mx := readCgroupFieldTest(selfDir, "pids.max")
	fmt.Printf("%s=%d\n", cgKeySpawned, spawned)
	fmt.Printf("%s=%s\n", cgKeyOutcome, outcome)
	fmt.Printf("%s=%s\n", cgKeyPidsCurrent, cur)
	fmt.Printf("%s=%s\n", cgKeyPidsMax, mx)
	_ = started // referenced above to keep children alive; nothing else to do
	return 0
}

// readCgroupFieldTest reads a single-value cgroup control file and trims it.
func readCgroupFieldTest(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "ERR:" + err.Error()
	}
	return strings.TrimSpace(string(b))
}

// parseCgroupMarkers turns the target's KEY=VALUE lines into a map.
func parseCgroupMarkers(out []byte) map[string]string {
	m := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			m[k] = v
		}
	}
	return m
}

// requireCgroupPids skips a test on a host without cgroup v2 pids delegation.
// This host has it, so these tests RUN for real; the skip keeps the suite honest
// on hosts where a fork-bomb cap cannot be enforced rather than passing silently.
func requireCgroupPids(t *testing.T) {
	t.Helper()
	if probeDelegatedPidsAncestor() == "" {
		t.Skip("cgroup v2 pids delegation unavailable on this host; resource-limit spawn tests cannot run")
	}
}

// runForkbombUnderSandbox builds a rung-2 executor with the given pids cap and
// runs the fork-bomb target (/proc/self/exe) under it, returning the parsed
// markers. GOMAXPROCS=1 keeps the target's own Go-runtime thread footprint small
// so the cap budget is spent on the fork loop, not runtime threads.
func runForkbombUnderSandbox(t *testing.T, pidsMax int, sleepPath string) map[string]string {
	t.Helper()
	ws := t.TempDir()
	e := newFSExecutor(t, testPolicy(testWorkspaceWrite, ws,
		WithLimits(effectiveLimits{MaxPIDs: pidsMax}),
		WithEnv(effectiveEnvPolicy{Set: map[string]string{
			cgroupForkbombEnv:   "1",
			cgroupForkbombSleep: sleepPath,
			"GOMAXPROCS":        "1",
		}}),
	))
	out, code, err := e.RunArgv(context.Background(), ws, []string{"/proc/self/exe"})
	if err != nil {
		t.Fatalf("RunArgv fork-bomb target: err=%v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("fork-bomb target exit=%d, want 0 (out=%q)", code, out)
	}
	return parseCgroupMarkers(out)
}

// TestLinuxCgroupForkBombCapped is the headline runtime proof: a fork bomb run in
// a rung-2 target joined to a transient cgroup with pids.max=20 is capped (its
// N+1-th fork hits EAGAIN while pids.current == pids.max == 20), while the same
// loop under pids.max=200 runs to completion — proving the cap, not an ambient
// limit, is what stopped the capped case. Anti-fail-open (mirroring the M5 spike):
// the capped case asserts it hit EAGAIN AND real forks succeeded (>=1, <60) AND
// pids.max reads back as configured AND pids.current == pids.max.
func TestLinuxCgroupForkBombCapped(t *testing.T) {
	requireLandlockV4(t) // the rung-2 backend needs Landlock v4 to spawn
	requireSeccomp(t)
	requireCgroupPids(t)
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("fork-bomb test needs a sleep binary: %v", err)
	}

	tests := []struct {
		name       string
		pidsMax    int
		wantCapped bool
	}{
		{"fork bomb capped at pids.max=20", cgCappedPidsMax, true},
		{"control: high pids.max=200 runs to completion", cgControlPidsMax, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := runForkbombUnderSandbox(t, tt.pidsMax, sleepPath)
			t.Logf("markers: %s=%s %s=%s %s=%s %s=%s",
				cgKeyOutcome, m[cgKeyOutcome], cgKeySpawned, m[cgKeySpawned],
				cgKeyPidsCurrent, m[cgKeyPidsCurrent], cgKeyPidsMax, m[cgKeyPidsMax])
			spawned, serr := strconv.Atoi(m[cgKeySpawned])
			if serr != nil {
				t.Fatalf("target did not report a numeric %s: %q (markers=%v)", cgKeySpawned, m[cgKeySpawned], m)
			}

			if tt.wantCapped {
				if m[cgKeyOutcome] != cgOutcomeEAGAIN {
					t.Errorf("outcome = %q, want %q (fork bomb was NOT capped)", m[cgKeyOutcome], cgOutcomeEAGAIN)
				}
				if spawned >= cgMaxSpawnAttempts {
					t.Errorf("spawned = %d, want < %d (cap did not limit the loop)", spawned, cgMaxSpawnAttempts)
				}
				if spawned < 1 {
					t.Errorf("spawned = %d, want >= 1 (0 forks would mask an unrelated failure as a cap)", spawned)
				}
				if m[cgKeyPidsMax] != strconv.Itoa(cgCappedPidsMax) {
					t.Errorf("pids.max readback = %q, want %q", m[cgKeyPidsMax], strconv.Itoa(cgCappedPidsMax))
				}
				if m[cgKeyPidsCurrent] != m[cgKeyPidsMax] {
					t.Errorf("pids.current = %q, pids.max = %q; want equal (cgroup not at its configured cap)", m[cgKeyPidsCurrent], m[cgKeyPidsMax])
				}
			} else {
				if m[cgKeyOutcome] != cgOutcomeNoLimit {
					t.Errorf("outcome = %q, want %q (control unexpectedly hit a limit)", m[cgKeyOutcome], cgOutcomeNoLimit)
				}
				if spawned != cgMaxSpawnAttempts {
					t.Errorf("spawned = %d, want %d (control did not run the full loop)", spawned, cgMaxSpawnAttempts)
				}
				if spawned <= cgCappedPidsMax {
					t.Errorf("spawned = %d, want > %d (control did not exceed the capped limit, so the cap is unproven)", spawned, cgCappedPidsMax)
				}
				if m[cgKeyPidsMax] != strconv.Itoa(cgControlPidsMax) {
					t.Errorf("pids.max readback = %q, want %q", m[cgKeyPidsMax], strconv.Itoa(cgControlPidsMax))
				}
			}
		})
	}
}

// TestLinuxCgroupGuaranteeAndLevel asserts that, on a host with pids delegation,
// the ResourceLimits guarantee holds and a resource-limits/enforced report entry
// exists — and that the isolation Level is UNCHANGED versus a limits-disabled
// executor (resource limits are containment-of-cost, not authority, §7.4).
func TestLinuxCgroupGuaranteeAndLevel(t *testing.T) {
	requireLandlockV4(t)
	requireCgroupPids(t)
	ws := t.TempDir()

	limited := newFSExecutor(t, testPolicy(testWorkspaceWrite, ws))
	if !limited.Guarantees().ResourceLimits {
		t.Errorf("ResourceLimits guarantee = false; want true on a host with cgroup v2 pids delegation")
	}
	if !reportHas(limited.Report(), "resource-limits", "enforced") {
		t.Errorf("missing resource-limits/enforced report entry; report=%+v", limited.Report())
	}

	// A limits-disabled executor: no scope, no guarantee, an unenforced entry — but
	// the SAME Level (limits never move the ladder).
	disabled := newFSExecutor(t, testPolicy(testWorkspaceWrite, ws, WithLimits(effectiveLimits{Disabled: true})))
	if disabled.Guarantees().ResourceLimits {
		t.Errorf("disabled policy reports ResourceLimits guarantee; want false")
	}
	if !reportHas(disabled.Report(), "resource-limits", "unenforced") {
		t.Errorf("disabled policy missing resource-limits/unenforced report entry; report=%+v", disabled.Report())
	}
	if limited.Level() != disabled.Level() {
		t.Errorf("Level changed by resource limits: limited=%d disabled=%d; want equal (§7.4)", limited.Level(), disabled.Level())
	}
}

// TestLinuxCgroupUnavailablePathFailSecure exercises the no-delegation branch on
// THIS host by pinning the backend's probed ancestor to "" (the exact state
// probeDelegatedPidsAncestor returns on a host without pids delegation). The
// guarantee is cleared, the report records it unenforced, the Level is unchanged,
// and a spawn STILL RUNS — limits are best-effort, their absence is never fatal.
func TestLinuxCgroupUnavailablePathFailSecure(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)
	ws := t.TempDir()

	e, err := newExecutorForEffectivePolicy(testPolicy(testWorkspaceWrite, ws), withBackend(&linuxBackend{cgroupPids: ""}))
	if err != nil {
		t.Fatalf("NewExecutor (no delegation): %v", err)
	}
	if e.Guarantees().ResourceLimits {
		t.Errorf("ResourceLimits guarantee set with no delegation; want false (fail-secure)")
	}
	if !reportHas(e.Report(), "resource-limits", "unenforced") {
		t.Errorf("missing resource-limits/unenforced report entry; report=%+v", e.Report())
	}

	out, code, err := e.RunCommand(context.Background(), ws, "printf ok")
	if err != nil {
		t.Fatalf("spawn without limits errored (should be best-effort, not fatal): %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("spawn without limits exit=%d, want 0 (out=%q)", code, out)
	}
	if string(out) != "ok" {
		t.Fatalf("spawn without limits out=%q, want %q", out, "ok")
	}

	avail := newFSExecutor(t, testPolicy(testWorkspaceWrite, ws))
	if e.Level() != avail.Level() {
		t.Errorf("Level differs by delegation availability: unavailable=%d available=%d; want equal (§7.4)", e.Level(), avail.Level())
	}
}

// TestLinuxCgroupNoDanglingScopes proves teardown works: after a capped fork bomb,
// no lrsb-* transient cgroup remains under the delegated ancestor. It is
// non-parallel, so no concurrent spawn's live scope can race the scan (parallel
// tests are deferred until the sequential phase completes), and the spawn's own
// teardown is synchronous within RunArgv's cleanup.
func TestLinuxCgroupNoDanglingScopes(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)
	requireCgroupPids(t)
	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("no-dangling test needs a sleep binary: %v", err)
	}
	ancestor := probeDelegatedPidsAncestor()

	_ = runForkbombUnderSandbox(t, cgCappedPidsMax, sleepPath)

	leaked := listLrsbScopes(t, ancestor)
	if len(leaked) != 0 {
		t.Errorf("dangling transient cgroups after teardown under %s: %v", ancestor, leaked)
	}
}

// listLrsbScopes returns the names of every lrsb-* directory directly under dir.
func listLrsbScopes(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read delegated ancestor %s: %v", dir, err)
	}
	var scopes []string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), cgroupScopePrefix) {
			scopes = append(scopes, e.Name())
		}
	}
	return scopes
}

// --- Pure unit tests (no kernel; fast) ---------------------------------------

// TestCompileCgroupPolicy exercises limit resolution: defaults, explicit values,
// the fail-secure branches (no ancestor / disabled), and boundary/negative inputs.
func TestCompileCgroupPolicy(t *testing.T) {
	t.Parallel()
	const anc = "/sys/fs/cgroup/session.slice"
	tests := []struct {
		name         string
		limits       effectiveLimits
		ancestor     string
		wantEnforced bool
		wantPids     int64
		wantMem      int64
		wantCPU      int
		wantDisabled bool
	}{
		{"defaults apply on available ancestor", effectiveLimits{}, anc, true, defaultMaxPIDs, 0, 0, false},
		{"explicit MaxPIDs overrides the default", effectiveLimits{MaxPIDs: 20}, anc, true, 20, 0, 0, false},
		{"memory and cpu carried when set", effectiveLimits{MaxPIDs: 100, MaxMemBytes: 1 << 30, MaxCPUPct: 150}, anc, true, 100, 1 << 30, 150, false},
		{"zero MaxPIDs falls back to default", effectiveLimits{MaxMemBytes: 4096}, anc, true, defaultMaxPIDs, 4096, 0, false},
		{"disabled applies no limits (fail-secure)", effectiveLimits{MaxPIDs: 99, Disabled: true}, anc, false, 0, 0, 0, true},
		{"disabled wins even with no ancestor", effectiveLimits{Disabled: true}, "", false, 0, 0, 0, true},
		{"no ancestor -> unenforced (fail-secure)", effectiveLimits{MaxPIDs: 20}, "", false, 0, 0, 0, false},
		{"negative mem/cpu ignored", effectiveLimits{MaxMemBytes: -5, MaxCPUPct: -1}, anc, true, defaultMaxPIDs, 0, 0, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cg := compileCgroupPolicy(tt.limits, tt.ancestor)
			if cg.enforced() != tt.wantEnforced {
				t.Errorf("enforced() = %v, want %v", cg.enforced(), tt.wantEnforced)
			}
			if cg.pidsMax != tt.wantPids {
				t.Errorf("pidsMax = %d, want %d", cg.pidsMax, tt.wantPids)
			}
			if cg.memMax != tt.wantMem {
				t.Errorf("memMax = %d, want %d", cg.memMax, tt.wantMem)
			}
			if cg.cpuPct != tt.wantCPU {
				t.Errorf("cpuPct = %d, want %d", cg.cpuPct, tt.wantCPU)
			}
			if cg.disabled != tt.wantDisabled {
				t.Errorf("disabled = %v, want %v", cg.disabled, tt.wantDisabled)
			}
		})
	}
}

// TestFormatCPUMax checks the cpu.max ("<quota> <period>") rendering across the
// single-core boundary and above it.
func TestFormatCPUMax(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		pct  int
		want string
	}{
		{"one full core", 100, "100000 100000"},
		{"half a core", 50, "50000 100000"},
		{"two cores", 200, "200000 100000"},
		{"quarter core", 25, "25000 100000"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := formatCPUMax(tt.pct); got != tt.want {
				t.Errorf("formatCPUMax(%d) = %q, want %q", tt.pct, got, tt.want)
			}
		})
	}
}

// TestCgroupCompileReport asserts the single resource-limits entry's status for
// the enforced, disabled, and delegation-absent cases (the detail must
// distinguish disabled from absent).
func TestCgroupCompileReport(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		cg         compiledCgroup
		wantStatus string
		wantDetail string // substring the detail must contain
	}{
		{"enforced", compiledCgroup{ancestor: "/x", pidsMax: 512}, "enforced", "pids.max=512"},
		{"disabled unenforced", compiledCgroup{disabled: true}, "unenforced", "disabled by policy"},
		{"absent unenforced", compiledCgroup{}, "unenforced", "delegation absent"},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			e := cgroupCompileReport(tt.cg)
			if e.Feature != "resource-limits" {
				t.Errorf("Feature = %q, want %q", e.Feature, "resource-limits")
			}
			if e.Status != tt.wantStatus {
				t.Errorf("Status = %q, want %q", e.Status, tt.wantStatus)
			}
			if !strings.Contains(e.Detail, tt.wantDetail) {
				t.Errorf("Detail = %q, want substring %q", e.Detail, tt.wantDetail)
			}
		})
	}
}

// TestCreateTransientCgroupNoop verifies the disabled/absent plan creates nothing
// (returns (nil, nil)) so the caller simply spawns without a cgroup — the
// fail-secure spawn-time counterpart to the cleared compile-time guarantee.
func TestCreateTransientCgroupNoop(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		cg   compiledCgroup
	}{
		{"no ancestor", compiledCgroup{}},
		{"disabled", compiledCgroup{disabled: true}},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tc, err := createTransientCgroup(tt.cg)
			if err != nil {
				t.Fatalf("createTransientCgroup(no-op) err = %v, want nil", err)
			}
			if tc != nil {
				tc.teardown()
				t.Fatalf("createTransientCgroup(no-op) returned a scope %+v, want nil", tc)
			}
		})
	}
}
