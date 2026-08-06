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
func doubleForkEscapeScript(marker, pidPath string) string {
	grandchild := "sleep " + strconv.Itoa(int(escapeGrandchildDelay.Seconds())) + "; printf 1 > " + portableShellQuote(marker)
	return "( setsid sh -c " + portableShellQuote(grandchild) + " </dev/null >/dev/null 2>&1 & echo $! > " +
		portableShellQuote(pidPath) + " ) & exit 0"
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

// TestIntegrationProcessTreeDarwinSetsidFailsClosed is Task 12c's Phase-Gate-3
// selector. Unlike the three tests above — which exercise real containment on
// whatever this host provides, and already skip themselves on Darwin via
// startEscapeTarget's errors.Is(enforce.ErrLifetimeContainmentUnavailable)
// check — this test asserts Darwin's fail-closed CONTRACT directly: a real
// Executor (built through the production platform backend selector, exactly
// like integrationEscapeExecutor's other callers) asked to run a command that
// would, if it ever ran, setsid-detach a grandchild and write a delayed
// marker (setsidEscapeScript) is instead rejected with
// enforce.ErrLifetimeContainmentUnavailable before any process — target or
// grandchild — is ever created. "Before any process is created" is proved two
// ways: the call that fails returns no Process at all, and the delayed marker
// together with the target's own pid file are polled for and never appear —
// past escapeGrandchildDelay, so absence is unambiguous non-execution, not an
// unfinished wait (mirrors assertEscapeContained's proof exactly).
//
// On this codebase's current architecture the rejection surfaces from
// PreparedProcess.Start (newProcessTree -> attachSupervisedProof,
// process_tree_darwin.go), not from PrepareProcess itself: PrepareProcess
// only performs grant/resource reservation and never touches the process
// tree. Both are "before spawn" (strictly before cmd.Start()'s syscall), so
// this test accepts either call failing with the sentinel, exactly like
// startEscapeTarget's own dual check above — but Start is what actually fails
// on this codebase today, and is asserted to return no Process when it does.
func TestIntegrationProcessTreeDarwinSetsidFailsClosed(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Darwin-only fail-closed contract; see TestIntegrationProcessTree(SetsidEscape|DoubleFork|ParentDeath) for real containment proof on other platforms")
	}
	set, executor, workspace := integrationEscapeExecutor(t)
	defer func() { _ = set.Close() }()

	marker := filepath.Join(workspace, "darwin-failclosed-marker")
	pidPath := filepath.Join(workspace, "darwin-failclosed-pid")
	script := setsidEscapeScript(marker, pidPath)

	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: script, ExecutionID: "darwin-failclosed",
	})
	switch {
	case err != nil:
		if !errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Fatalf("PrepareProcess failed with an unexpected error: %v, want enforce.ErrLifetimeContainmentUnavailable", err)
		}
	default:
		defer func() { _ = prepared.Close() }()
		proc, startErr := prepared.Start(context.Background())
		if startErr == nil {
			// Defensive only: if a future change makes Start succeed without a
			// real containment primitive, do not leak the process this test
			// never expected to exist.
			_ = proc.Signal(context.Background(), ProcessSignalKill)
			_, _ = proc.Wait(context.Background())
			t.Fatal("Start unexpectedly succeeded on darwin; want enforce.ErrLifetimeContainmentUnavailable before any spawn")
		}
		if !errors.Is(startErr, enforce.ErrLifetimeContainmentUnavailable) {
			t.Fatalf("Start error = %v, want it to wrap enforce.ErrLifetimeContainmentUnavailable", startErr)
		}
		if proc != nil {
			t.Fatalf("Start returned a non-nil Process alongside a fail-closed error: %v", proc)
		}
	}

	// The core proof: the spawn was rejected before cmd.Start ever ran, so
	// neither the immediate target (pidPath) nor its would-be setsid-detached
	// grandchild (marker) ever executed.
	time.Sleep(escapeObservationWindow)
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("delayed marker exists even though the spawn was rejected before it started: stat err = %v", statErr)
	}
	if _, statErr := os.Stat(pidPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("target pid file exists even though the spawn was rejected before it started: stat err = %v", statErr)
	}
}
