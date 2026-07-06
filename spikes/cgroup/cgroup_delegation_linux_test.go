//go:build linux

// Package cgroup is a THROWAWAY Phase 0.5 spike (Task M5). It proves that a
// transient cgroup v2 scope, created under a delegated (user-owned) ancestor
// that distributes the `pids` controller, can cap a fork bomb at `pids.max`:
// a helper child joined into the scope via CLONE_INTO_CGROUP (SysProcAttr.
// UseCgroupFD) cannot exceed the configured process limit — its N+1-th fork
// fails with EAGAIN while `pids.current == pids.max`. It also proves the
// capability gate: when cgroup v2 pids delegation is unavailable the test
// SKIPS with a specific recorded reason (never silently passes).
//
// This validates Task 14 (cgroup v2 resource limits), where the real backend
// joins the stage-2 child to a transient scope with the same mechanism.
//
// It is NOT shipped code. It lives in its own package, isolated from the root
// `package sandbox`, and runs only as a capability-gated test.
//
// SAFETY: every mutation is confined to a fresh, empty child cgroup this test
// creates itself under the delegated ancestor. It NEVER writes to an existing
// cgroup's cgroup.subtree_control and NEVER moves a pre-existing process, so
// the user's live desktop session is untouched. The fork bomb is capped at 20
// processes inside an isolated cgroup — pids limits are per-cgroup, so it can
// affect nothing outside the transient scope. Cleanup (recursive kill + rmdir)
// runs unconditionally via t.Cleanup, even on assertion failure.
package cgroup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Environment vars that flag helper (fork-bomb) mode and pass it the sleep
// binary path. When envHelper is set, THIS invocation is the joined child and
// must run the fork loop instead of the test suite.
const (
	envHelper    = "LRSANDBOX_CGROUP_SPIKE_HELPER"
	envSleepPath = "LRSANDBOX_CGROUP_SPIKE_SLEEP"
)

// Marker keys the helper prints (one "KEY=VALUE" line each) and the parent
// parses. Shared constants stop the two halves from drifting.
const (
	keySpawned     = "SPAWNED"
	keyOutcome     = "OUTCOME"
	keyPidsCurrent = "PIDS_CURRENT"
	keyPidsMax     = "PIDS_MAX"
)

// Fork-loop outcome values.
const (
	outcomeEAGAIN  = "EAGAIN"  // hit pids.max: a fork failed with EAGAIN
	outcomeNoLimit = "NOLIMIT" // ran the full loop without ever hitting a cap
)

// Tunables. maxSpawnAttempts is the bounded fork-bomb size; cappedPidsMax is
// small enough to cap the loop yet large enough to leave the helper's own Go
// runtime threads room to live; controlPidsMax is high enough that the same
// loop runs to completion (proving the cap — not some ambient limit — is what
// stopped the capped case).
const (
	maxSpawnAttempts = 60
	cappedPidsMax    = 20
	controlPidsMax   = 200
	sleepSeconds     = "30" // helper children sleep; cleanup kills them
	cgroupMount      = "/sys/fs/cgroup"
)

// Helper exit codes (distinct from the fork-loop outcome, which is reported via
// stdout markers).
const exitHelperConfig = 4

// TestMain multiplexes: when the helper sentinel is set this invocation is the
// child joined into the transient cgroup and must run the fork loop, NOT the
// suite; otherwise run tests normally.
func TestMain(m *testing.M) {
	if os.Getenv(envHelper) != "" {
		os.Exit(runForkBombHelper())
	}
	os.Exit(m.Run())
}

// applyPidsMax sets pids.max on the transient cgroup at dir. The pids.max file
// exists because dir was created under an ancestor whose cgroup.subtree_control
// distributes the pids controller.
func applyPidsMax(dir string, max int) error {
	return os.WriteFile(filepath.Join(dir, "pids.max"), []byte(strconv.Itoa(max)), 0)
}

// runForkBombHelper runs inside the transient cgroup (it was joined at clone
// time via CLONE_INTO_CGROUP). It attempts up to maxSpawnAttempts short-lived
// sleep children, counting how many start before a fork fails with EAGAIN
// (pids.max reached), then reports the count, the outcome, and pids.current /
// pids.max read from its OWN cgroup at that instant. It does not wait for the
// children — the parent's cleanup kills them.
func runForkBombHelper() int {
	sleepPath := os.Getenv(envSleepPath)
	if sleepPath == "" {
		fmt.Printf("%s=ERR:missing-sleep-path\n", keyOutcome)
		return exitHelperConfig
	}
	selfDir, err := selfCgroupDir()
	if err != nil {
		fmt.Printf("%s=ERR:self-cgroup:%v\n", keyOutcome, err)
		return exitHelperConfig
	}

	outcome := outcomeNoLimit
	spawned := 0
	// Keep references so the children stay alive (not garbage-collected) for
	// the duration of the loop; they remain running until cleanup kills them.
	started := make([]*exec.Cmd, 0, maxSpawnAttempts)
	for i := 0; i < maxSpawnAttempts; i++ {
		c := exec.Command(sleepPath, sleepSeconds)
		if serr := c.Start(); serr != nil {
			if errors.Is(serr, syscall.EAGAIN) {
				outcome = outcomeEAGAIN
			} else {
				outcome = "ERR:" + serr.Error()
			}
			break
		}
		started = append(started, c)
		spawned++
	}

	// Snapshot the cgroup's pids accounting at the moment we stopped. On a real
	// cap this is pids.current == pids.max.
	cur := readCgroupField(selfDir, "pids.current")
	mx := readCgroupField(selfDir, "pids.max")

	fmt.Printf("%s=%d\n", keySpawned, spawned)
	fmt.Printf("%s=%s\n", keyOutcome, outcome)
	fmt.Printf("%s=%s\n", keyPidsCurrent, cur)
	fmt.Printf("%s=%s\n", keyPidsMax, mx)
	_ = started // referenced above to keep children alive; nothing else to do
	return 0
}

// selfCgroupDir resolves the absolute directory of the process's own cgroup v2
// node from the unified ("0::") line of /proc/self/cgroup.
func selfCgroupDir() (string, error) {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rel, ok := strings.CutPrefix(strings.TrimSpace(line), "0::"); ok {
			return filepath.Join(cgroupMount, filepath.Clean("/"+rel)), nil
		}
	}
	return "", fmt.Errorf("no unified (0::) line in /proc/self/cgroup")
}

// readCgroupField reads a single-value cgroup control file and trims it.
func readCgroupField(dir, name string) string {
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "ERR:" + err.Error()
	}
	return strings.TrimSpace(string(b))
}

// subtreeHasPids reports whether dir distributes the pids controller to its
// children via cgroup.subtree_control.
func subtreeHasPids(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
	if err != nil {
		return false
	}
	for _, f := range strings.Fields(string(b)) {
		if f == "pids" {
			return true
		}
	}
	return false
}

// resolveDelegatedAncestor discovers, at runtime, the nearest ancestor of the
// process's own cgroup that is (a) writable AND (b) distributes the pids
// controller — i.e. a delegated node under which a fresh child immediately has
// a working pids.max. It returns that directory, or an empty string and a
// specific human-readable reason the capability is unavailable (for t.Skip).
func resolveDelegatedAncestor() (dir, reason string) {
	// Unified (v2) hierarchy check: the root must expose cgroup.controllers.
	// Its absence means cgroup v1 or hybrid, where this delegation model and
	// the pids-controller layout do not apply.
	rootCtl := filepath.Join(cgroupMount, "cgroup.controllers")
	if _, err := os.Stat(rootCtl); err != nil {
		return "", fmt.Sprintf("cgroup v2 unified hierarchy not present: %s missing (%v)", rootCtl, err)
	}
	selfDir, err := selfCgroupDir()
	if err != nil {
		return "", fmt.Sprintf("cannot resolve own cgroup: %v", err)
	}
	for cur := selfDir; ; {
		if unix.Access(cur, unix.W_OK) == nil && subtreeHasPids(cur) {
			return cur, ""
		}
		if cur == cgroupMount {
			break
		}
		parent := filepath.Dir(cur)
		// Guard against escaping the mount root.
		if len(parent) < len(cgroupMount) || !strings.HasPrefix(parent, cgroupMount) {
			break
		}
		cur = parent
	}
	return "", "no writable ancestor distributes the pids controller via cgroup.subtree_control (cgroup v2 pids delegation unavailable)"
}

// destroyCgroup unconditionally tears down a transient cgroup: it kills every
// process inside it (v2 recursive cgroup.kill first, then SIGKILL any stragglers
// listed in cgroup.procs) and rmdir's it, retrying briefly while procs drain.
// All errors are best-effort and intentionally swallowed — this is teardown of
// a throwaway cgroup and nothing downstream depends on the outcome; the only
// goal is to leave no dangling cgroup and no processes we spawned.
func destroyCgroup(dir string) {
	// Recursive kill of everything in the subtree (cgroup v2 feature).
	_ = os.WriteFile(filepath.Join(dir, "cgroup.kill"), []byte("1"), 0) // best-effort
	for i := 0; i < 100; i++ {
		pids := readProcs(dir)
		if len(pids) == 0 {
			if err := os.Remove(dir); err == nil || errors.Is(err, os.ErrNotExist) {
				return
			}
			// EBUSY: children/threads still draining from the kernel's view.
		}
		for _, p := range pids {
			_ = unix.Kill(p, unix.SIGKILL) // best-effort: only pids in OUR cgroup
		}
		time.Sleep(10 * time.Millisecond) // drain wait; not part of any assertion
	}
	_ = os.Remove(dir) // final best-effort
}

// readProcs returns the pids currently listed in dir/cgroup.procs.
func readProcs(dir string) []int {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var pids []int
	for _, line := range strings.Fields(string(b)) {
		if p, perr := strconv.Atoi(line); perr == nil {
			pids = append(pids, p)
		}
	}
	return pids
}

// parseMarkers turns the helper's "KEY=VALUE" lines into a map.
func parseMarkers(out []byte) map[string]string {
	markers := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		key, val, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		markers[key] = val
	}
	return markers
}

// runForkBomb creates a transient child cgroup under ancestor, applies pidsMax,
// joins a helper child into it via UseCgroupFD, and returns the parsed markers.
// It registers unconditional cleanup on t before doing anything that could fail.
func runForkBomb(t *testing.T, ancestor, tag, sleepPath string, pidsMax int) map[string]string {
	t.Helper()
	// Unique, deterministic name from the pid (no time.Now/rand per conventions).
	dir := filepath.Join(ancestor, fmt.Sprintf("lrsb-spike-%d-%s", os.Getpid(), tag))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("create transient cgroup %s: %v", dir, err)
	}
	// Register teardown BEFORE anything else can fail, so a later Fatalf still
	// cleans up the cgroup and any processes we spawned into it.
	t.Cleanup(func() { destroyCgroup(dir) })

	if err := applyPidsMax(dir, pidsMax); err != nil {
		t.Fatalf("apply pids.max=%d on %s: %v", pidsMax, dir, err)
	}

	// Join the helper at clone time via CLONE_INTO_CGROUP (the mechanism the
	// real Task 14 backend uses), so it is capped from its very first fork.
	fd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open cgroup dir %s: %v", dir, err)
	}
	defer func() { _ = unix.Close(fd) }() // fd only needed through Start

	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		envHelper+"=1",
		envSleepPath+"="+sleepPath,
		"GOMAXPROCS=1", // keep the helper's own thread footprint small
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}

	out, cerr := cmd.CombinedOutput()
	if cerr != nil {
		t.Fatalf("helper (tag=%s) exited non-zero: %v\nhelper output:\n%s", tag, cerr, out)
	}
	return parseMarkers(out)
}

// TestCgroupPidsDelegation proves cgroup v2 pids delegation caps a fork bomb.
// Capped case: a helper joined into a cgroup with pids.max=20 hits EAGAIN and
// pids.current == pids.max == 20 (anti-fail-open: it must ALSO have started at
// least one child, so a spurious "0 forks" failure can't masquerade as a cap).
// Control case: the identical loop under pids.max=200 runs to completion,
// proving the cap — not some ambient limit — is what stopped the capped case.
func TestCgroupPidsDelegation(t *testing.T) {
	ancestor, reason := resolveDelegatedAncestor()
	if ancestor == "" {
		t.Skipf("cgroup v2 pids delegation unavailable: %s", reason)
	}
	t.Logf("resolved delegated ancestor: %s", ancestor)

	sleepPath, err := exec.LookPath("sleep")
	if err != nil {
		t.Skipf("cgroup v2 pids delegation spike needs a sleep binary: %v", err)
	}

	tests := []struct {
		name       string
		tag        string
		pidsMax    int
		wantCapped bool
	}{
		{"fork bomb capped at pids.max=20", "capped", cappedPidsMax, true},
		{"control: high pids.max=200 is not capped", "control", controlPidsMax, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := runForkBomb(t, ancestor, tt.tag, sleepPath, tt.pidsMax)
			t.Logf("helper markers: %s=%s %s=%s %s=%s %s=%s",
				keyOutcome, m[keyOutcome], keySpawned, m[keySpawned],
				keyPidsCurrent, m[keyPidsCurrent], keyPidsMax, m[keyPidsMax])
			spawned, serr := strconv.Atoi(m[keySpawned])
			if serr != nil {
				t.Fatalf("helper did not report a numeric %s: %q (markers=%v)", keySpawned, m[keySpawned], m)
			}

			if tt.wantCapped {
				// 1. It hit the cap.
				if m[keyOutcome] != outcomeEAGAIN {
					t.Errorf("outcome = %q, want %q (fork bomb was NOT capped)", m[keyOutcome], outcomeEAGAIN)
				}
				// 2. It was genuinely capped BELOW the attempt count...
				if spawned >= maxSpawnAttempts {
					t.Errorf("spawned = %d, want < %d (cap did not limit the loop)", spawned, maxSpawnAttempts)
				}
				// 3. ...yet real forks DID succeed (anti-fail-open: not 0).
				if spawned < 1 {
					t.Errorf("spawned = %d, want >= 1 (0 forks would mask an unrelated failure as a cap)", spawned)
				}
				// 4. The cgroup was at its configured cap: current == max == 20.
				if m[keyPidsMax] != strconv.Itoa(cappedPidsMax) {
					t.Errorf("pids.max readback = %q, want %q", m[keyPidsMax], strconv.Itoa(cappedPidsMax))
				}
				if m[keyPidsCurrent] != m[keyPidsMax] {
					t.Errorf("pids.current = %q, pids.max = %q; want equal (not at the cap)", m[keyPidsCurrent], m[keyPidsMax])
				}
			} else {
				// Control: same loop, high cap, runs to completion.
				if m[keyOutcome] != outcomeNoLimit {
					t.Errorf("outcome = %q, want %q (control unexpectedly hit a limit)", m[keyOutcome], outcomeNoLimit)
				}
				if spawned != maxSpawnAttempts {
					t.Errorf("spawned = %d, want %d (control did not run the full loop)", spawned, maxSpawnAttempts)
				}
				if spawned <= cappedPidsMax {
					t.Errorf("spawned = %d, want > %d (control did not exceed the capped limit, so the cap is unproven)", spawned, cappedPidsMax)
				}
				if m[keyPidsMax] != strconv.Itoa(controlPidsMax) {
					t.Errorf("pids.max readback = %q, want %q", m[keyPidsMax], strconv.Itoa(controlPidsMax))
				}
			}
		})
	}
}
