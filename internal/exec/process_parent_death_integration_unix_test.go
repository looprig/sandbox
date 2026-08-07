//go:build integration && (darwin || linux)

package exec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
)

// This file is Task 12's real, deliberate Unix process-tree escape proof: a
// live Executor built through the REAL platform backend selector (no
// withBackend test seam — on Linux this exercises whichever Rung this host
// actually achieves; on Darwin, Task 12c's separate fail-closed contract is
// exercised instead of a success path, see below) runs a target that forks a
// detached grandchild — closing stdio, calling setsid, double-forking — and
// this test proves that grandchild does NOT survive the supervised spawn's
// teardown, even though a plain process-group SIGKILL-and-poll (the
// mechanism this microtask replaces for a Supervised spawn) can be defeated
// by exactly this shape of descendant.
//
// Run with: go test -tags integration -race ./internal/exec -run
// 'TestIntegrationProcessTreeParentDeath|TestIntegrationProcessTreeDoubleFork|TestIntegrationProcessTreeSetsidEscape'

// escapeGrandchildDelay is how long the detached grandchild sleeps before
// writing its delayed marker. It must comfortably exceed how long real
// containment teardown (PID-namespace reap, or cgroup.kill + cgroup.procs
// poll) takes, so "the marker was never written" is unambiguous proof of
// containment rather than a race that happened to finish first.
const escapeGrandchildDelay = 3 * time.Second

// escapeObservationWindow is how long the test waits, after the supervised
// spawn is confirmed torn down, before asserting the marker was never
// written — comfortably longer than escapeGrandchildDelay.
const escapeObservationWindow = escapeGrandchildDelay + 4*time.Second

// integrationEscapeExecutor builds a real ExecutorSet/Executor through the
// production platform backend selector (platform.Backend, via
// NewExecutorSet with no withBackend override) so this test exercises
// whatever containment this host and process actually provide — exactly the
// production path a real long-running supervised command takes. HostRead is
// Allow so /bin/sh, sleep, and setsid stay visible even under Rung 1's
// restricted-read mount view (invisible-by-default), matching the profile
// shape this package's other live async tests already use.
func integrationEscapeExecutor(t *testing.T) (*ExecutorSet, *Executor, string) {
	t.Helper()
	workspace := t.TempDir()
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1))
	if err != nil {
		skipIfNoRealBackend(t, "NewExecutorSet", err)
	}
	executor, err := set.For("parent-death-escape")
	if err != nil {
		_ = set.Close()
		skipIfNoRealBackend(t, "For", err)
	}
	return set, executor, workspace
}

// skipIfNoRealBackend now lives in process_grant_integration_test.go: that
// file carries only the `//go:build integration` constraint (no darwin ||
// linux restriction, unlike this one), so a helper every platform's own
// `-tags integration` build needs to resolve — this file's own callers
// included — must live somewhere Windows compiles it too, not here.

// requireSettidHelper skips the test on a host/image without the setsid
// binary (util-linux) — needed for a genuine session-detach escape, rather
// than approximating it and understating the proof.
func requireSetsidHelper(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("setsid"); err != nil {
		t.Skip("setsid binary unavailable on this host/image; cannot exercise a real session-detach escape")
	}
}

// pidFileAlive reads a pid previously written to path and reports whether
// that pid is still alive (signal 0). A missing pid file is treated as "not
// yet observed" (false) rather than an error, since the caller polls.
func pidFileAlive(path string) bool {
	raw, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
	if err != nil || pid <= 0 {
		return false
	}
	err = syscall.Kill(pid, 0)
	return err == nil || !errors.Is(err, syscall.ESRCH)
}

// startEscapeTarget prepares and starts an async supervised spawn running
// script, skipping (rather than failing) when this host cannot provide the
// mandatory containment the plan requires for a Rung-2 spawn with no
// delegated cgroup — that is this microtask's own documented fail-closed
// contract, not a bug this test should report.
func startEscapeTarget(t *testing.T, executor *Executor, workspace, script string) *Process {
	t.Helper()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: script, ExecutionID: "parent-death-escape",
	})
	if err != nil {
		if errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Skipf("lifetime containment unavailable on this host (PrepareProcess): %v", err)
		}
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		if errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Skipf("lifetime containment unavailable on this host (Start): %v", err)
		}
		t.Fatalf("Start: %v", err)
	}
	return proc
}

// assertEscapeContained waits past escapeGrandchildDelay and asserts the
// detached grandchild never wrote its marker and (when a pid file was
// captured) is no longer alive — the core "descendant PID disappears; a
// delayed marker is never written" proof.
func assertEscapeContained(t *testing.T, marker, pidPath string) {
	t.Helper()
	time.Sleep(escapeObservationWindow)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("detached grandchild's delayed marker exists (escape succeeded): stat err = %v", err)
	}
	if pidPath != "" && pidFileAlive(pidPath) {
		t.Fatalf("detached grandchild pid (from %s) is still alive after containment teardown", pidPath)
	}
}

// setsidEscapeScript builds a target command: it backgrounds a `setsid`-
// detached grandchild (new session — escapes THIS run's Unix process group,
// the exact vector a plain process-group signal cannot reach), closing its
// stdio (</dev/null >/dev/null 2>&1), recording the detached process's real
// pid, then exits immediately itself so the immediate child is reaped
// quickly while the grandchild is still sleeping.
func setsidEscapeScript(marker, pidPath string) string {
	grandchild := "sleep " + strconv.Itoa(int(escapeGrandchildDelay.Seconds())) + "; printf 1 > " + portableShellQuote(marker)
	return "setsid sh -c " + portableShellQuote(grandchild) + " </dev/null >/dev/null 2>&1 & echo $! > " +
		portableShellQuote(pidPath) + "; exit 0"
}

// doubleForkEscapeScript adds one extra layer of forking (an outer
// backgrounded subshell) on top of setsidEscapeScript's session detach —
// characterizing the double-fork idiom (fork, fork again, exit the
// intermediate) rather than only a single setsid detach.
//
// The trailing `wait` (before the outer script's own `exit 0`) is
// load-bearing, not decorative: without it, the pid-file write
// (`echo $! > pidPath`) happens *inside* the backgrounded intermediate
// subshell, racing the outer script's own near-instant exit — unlike
// setsidEscapeScript, whose pid-file write runs synchronously in the OUTER
// (foreground) shell before it exits. Once the outer process (this run's
// Supervised spawn root) exits, the supervisor's teardown SIGKILLs the whole
// process group essentially immediately (no grace delay); on a sufficiently
// fast teardown (empirically, darwin's best-effort proof) that can reap the
// intermediate before it schedules its own echo, so pidPath is never
// written and the test times out waiting for it — a race in this script,
// not a containment gap. `wait` (no args) blocks the outer shell on its one
// background job — the intermediate subshell — which itself finishes almost
// immediately after backgrounding the real (setsid-detached) grandchild and
// writing pidPath, so this still exits fast (it does NOT wait out the
// grandchild's own escapeGrandchildDelay sleep) while guaranteeing pidPath
// exists before the outer process, and therefore the supervised spawn's
// root, ever exits.
func doubleForkEscapeScript(marker, pidPath string) string {
	grandchild := "sleep " + strconv.Itoa(int(escapeGrandchildDelay.Seconds())) + "; printf 1 > " + portableShellQuote(marker)
	return "( setsid sh -c " + portableShellQuote(grandchild) + " </dev/null >/dev/null 2>&1 & echo $! > " +
		portableShellQuote(pidPath) + " ) & wait; exit 0"
}

// TestIntegrationProcessTreeSetsidEscape proves a grandchild that detaches
// into its own session (setsid) and closes stdio does not survive a
// supervised spawn's normal (natural-exit) teardown.
func TestIntegrationProcessTreeSetsidEscape(t *testing.T) {
	requireSetsidHelper(t)
	set, executor, workspace := integrationEscapeExecutor(t)
	defer func() { _ = set.Close() }()

	marker := filepath.Join(workspace, "setsid-marker")
	pidPath := filepath.Join(workspace, "setsid-pid")
	proc := startEscapeTarget(t, executor, workspace, setsidEscapeScript(marker, pidPath))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := proc.Wait(ctx); err != nil {
		t.Fatalf("Wait (immediate child): %v", err)
	}
	waitForPath(t, pidPath)
	assertEscapeContained(t, marker, pidPath)
}

// TestIntegrationProcessTreeDoubleFork proves the same containment holds for
// a double-forked, session-detached grandchild.
func TestIntegrationProcessTreeDoubleFork(t *testing.T) {
	requireSetsidHelper(t)
	set, executor, workspace := integrationEscapeExecutor(t)
	defer func() { _ = set.Close() }()

	marker := filepath.Join(workspace, "doublefork-marker")
	pidPath := filepath.Join(workspace, "doublefork-pid")
	proc := startEscapeTarget(t, executor, workspace, doubleForkEscapeScript(marker, pidPath))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := proc.Wait(ctx); err != nil {
		t.Fatalf("Wait (immediate child): %v", err)
	}
	waitForPath(t, pidPath)
	assertEscapeContained(t, marker, pidPath)
}

// TestIntegrationProcessTreeParentDeath proves containment holds even when
// the supervising process is force-killed instead of exiting naturally: the
// immediate child is killed via Process.Signal(ProcessSignalKill) while its
// setsid-detached grandchild is still alive, and the grandchild still does
// not survive — the general "supervising helper is force-killed; descendant
// PID disappears; a delayed marker is never written" acceptance case.
func TestIntegrationProcessTreeParentDeath(t *testing.T) {
	requireSetsidHelper(t)
	set, executor, workspace := integrationEscapeExecutor(t)
	defer func() { _ = set.Close() }()

	marker := filepath.Join(workspace, "parentdeath-marker")
	pidPath := filepath.Join(workspace, "parentdeath-pid")
	started := filepath.Join(workspace, "parentdeath-started")
	// The immediate child stays alive (sleeping) after detaching its
	// grandchild, so this test can force-kill it while both are still
	// running — proving the escape is contained on an ABRUPT supervisor
	// kill, not merely on the immediate child's own cooperative exit (which
	// TestIntegrationProcessTreeSetsidEscape already covers).
	grandchild := "sleep " + strconv.Itoa(int(escapeGrandchildDelay.Seconds())) + "; printf 1 > " + portableShellQuote(marker)
	script := "setsid sh -c " + portableShellQuote(grandchild) + " </dev/null >/dev/null 2>&1 & echo $! > " +
		portableShellQuote(pidPath) + "; : > " + portableShellQuote(started) + "; sleep 30"
	proc := startEscapeTarget(t, executor, workspace, script)

	waitForPath(t, started)
	waitForPath(t, pidPath)
	if err := proc.Signal(context.Background(), ProcessSignalKill); err != nil {
		t.Fatalf("Signal(Kill) on the supervising helper: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := proc.Wait(ctx); err != nil {
		t.Fatalf("Wait (force-killed immediate child): %v", err)
	}
	assertEscapeContained(t, marker, pidPath)
}

// TestIntegrationProcessTreeDarwinSetsidEscapeContained is Task 6's
// replacement for the deleted TestIntegrationProcessTreeDarwinSetsidFailsClosed:
// the 2026-08-06 best-effort containment decision (process_tree_darwin.go's
// attachSupervisedProof) stopped rejecting Darwin Supervised spawns and
// instead attaches a best-effort process-tree teardown prover — the
// proc-table-closure descendant tracker (process_descendants_darwin.go) —
// alongside the plain process-group signal-and-poll every other platform
// already had. This test proves that prover actually holds for real, under
// real Seatbelt confinement: a setsid-detached grandchild (the exact escape
// vector TestIntegrationProcessTreeSetsidEscape above already proves on every
// platform this real-backend pattern reaches, darwin included since Task 4)
// does not survive the supervised spawn's normal teardown, and the spawn
// self-reports exactly the containment level it actually achieved
// (LifetimeContainmentBestEffort) rather than silently claiming more. Kept as
// an explicit darwin-gated test — rather than folded into the generic
// TestIntegrationProcessTreeSetsidEscape above — so this specific contract
// (self-reported best-effort, not kernel-enforced) stays independently named
// and discoverable, exactly like the deleted fail-closed test it replaces
// was.
func TestIntegrationProcessTreeDarwinSetsidEscapeContained(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("darwin-specific best-effort containment proof; see TestIntegrationProcessTree(SetsidEscape|DoubleFork|ParentDeath) above for the platform-neutral escape proof, which (since Task 4) also runs for real against darwin's own backend")
	}
	requireSetsidHelper(t)
	set, executor, workspace := integrationEscapeExecutor(t)
	defer func() { _ = set.Close() }()

	marker := filepath.Join(workspace, "darwin-escape-marker")
	pidPath := filepath.Join(workspace, "darwin-escape-pid")
	proc := startEscapeTarget(t, executor, workspace, setsidEscapeScript(marker, pidPath))

	// The self-reported contract: darwin has no kernel-enforced tree
	// teardown, so this spawn must honestly report BestEffort, never
	// Enforced (which would misreport a guarantee darwin cannot make; see
	// LifetimeContainment, lifetime_containment.go) and never Unspecified
	// (which would misreport that no containment attempt was even made).
	if got := proc.LifetimeContainment(); got != LifetimeContainmentBestEffort {
		t.Fatalf("LifetimeContainment() = %v, want LifetimeContainmentBestEffort (darwin's best-effort descendant-tracker prover)", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := proc.Wait(ctx); err != nil {
		t.Fatalf("Wait (immediate child): %v", err)
	}
	waitForPath(t, pidPath)
	// The core proof: after the supervised spawn's own teardown, the
	// setsid-detached grandchild the descendant tracker is specifically
	// responsible for discovering (it left the process group, so the plain
	// group SIGKILL alone cannot reach it) is gone too — same proof
	// assertEscapeContained already performs for the platform-neutral tests.
	assertEscapeContained(t, marker, pidPath)
}
