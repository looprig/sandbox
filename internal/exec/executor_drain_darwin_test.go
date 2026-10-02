//go:build darwin

package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/testsupport"
	"golang.org/x/sys/unix"
)

// M10 (docs/reviews/2026-10-01-windows-and-module-review.md): a descendant
// that calls setsid(2) leaves the run's process group, so the group sweep in
// run()'s tree.terminateAndWait cannot see it. If that descendant inherited
// the run's stdout pipe and keeps it open, the drain goroutines never observe
// EOF, drainWG.Wait() blocks forever, run never returns, its execution lease
// never finishes, and ExecutorSet.Close parks in lifecycle.wait() behind it.
// exec.Cmd's own WaitDelay cannot help: run wires stdout/stderr through its
// own os.Pipe, so exec.Cmd owns no copying goroutine and no pipe to close.
//
// The escapee command below is the reviewer's shape: perl detaches with
// POSIX::setsid() and execs a long sleep WITHOUT redirecting stdout, so the
// sleep holds the write end of the run's output pipe for 30 seconds.

// setsidEscapeeCommand backgrounds a setsid'd, stdout-inheriting sleep that
// writes its own pid to pidFile first (so the test can check it afterwards),
// then — when parentSleeps is set — keeps the shell itself alive so the run
// ends by cancellation rather than by normal exit.
func setsidEscapeeCommand(pidFile string, parentSleeps bool) string {
	script := `/usr/bin/perl -MPOSIX -e 'POSIX::setsid(); open(my $f, ">", $ARGV[0]) or die; print $f "$$\n"; close $f; exec "/bin/sleep", "30"' ` + portableShellQuote(pidFile) + ` &`
	if parentSleeps {
		script += ` /bin/sleep 30`
	}
	return script
}

// readEscapeePID waits briefly for the escapee to publish its pid.
func readEscapeePID(t *testing.T, pidFile string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(pidFile)
		if err == nil && strings.HasSuffix(string(raw), "\n") {
			pid, convErr := strconv.Atoi(strings.TrimSpace(string(raw)))
			if convErr == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("escapee never published its pid to %s", pidFile)
	return 0
}

// escapeeGone reports whether pid no longer names a live process. A zombie
// awaiting launchd's reap counts as gone; kill(pid, 0) still succeeds on one,
// so the process table's state is consulted too.
func escapeeGone(pid int) bool {
	if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
		return true
	}
	info, err := processStateForTest(pid)
	return err != nil || info == darwinZombieState
}

// processStateForTest returns pid's kernel process state (P_stat).
func processStateForTest(pid int) (int8, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, err
	}
	if info == nil || int(info.Proc.P_pid) != pid {
		return 0, syscall.ESRCH
	}
	return info.Proc.P_stat, nil
}

// runWithHangGuard runs fn and fails the test (rather than hanging the whole
// suite) when fn does not return within bound.
func runWithHangGuard(t *testing.T, bound time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(bound):
		t.Fatalf("run did not return within %s: a setsid'd descendant holding the output pipe hangs the drain (M10)", bound)
	}
}

// TestSeatbeltRunReturnsAndKillsSetsidEscapeeOnCancel is M10's confined case:
// the real Seatbelt backend, a cancelled run, and a setsid'd escapee holding
// stdout. The descendant tracker now attached to synchronous confined spawns
// discovers the escapee through its ppid link while the shell is alive and
// kills it at teardown, so the run returns promptly AND the escapee is dead —
// not merely abandoned with its pipe closed underneath it.
func TestSeatbeltRunReturnsAndKillsSetsidEscapeeOnCancel(t *testing.T) {
	requireSandboxExec(t)
	ws := t.TempDir()
	pidFile := filepath.Join(ws, "escapee.pid")
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// Cancel only once the escapee is running and the tracker has had
		// several sampling intervals to see it.
		readEscapeePID(t, pidFile)
		time.Sleep(5 * descendantSampleInterval)
		cancel()
	}()
	var runErr error
	start := time.Now()
	runWithHangGuard(t, 10*time.Second, func() {
		_, _, runErr = e.RunCommand(ctx, ws, setsidEscapeeCommand(pidFile, true))
	})
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("RunCommand error = %v, want context.Canceled", runErr)
	}
	if elapsed := time.Since(start); elapsed > 8*time.Second {
		t.Fatalf("RunCommand took %s to return after cancel", elapsed)
	}
	pid := readEscapeePID(t, pidFile)
	if !escapeeGone(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("setsid escapee pid %d survived a confined run's teardown; the synchronous path must arm the descendant tracker", pid)
	}
}

// TestSeatbeltRunReturnsAndKillsSetsidEscapeeAfterNormalExit is the same
// escapee behind a shell that exits normally at once (no cancellation): the
// group is gone immediately, so only the tracker — armed before the shell's
// first sample — can still name the escapee.
func TestSeatbeltRunReturnsAndKillsSetsidEscapeeAfterNormalExit(t *testing.T) {
	requireSandboxExec(t)
	ws := t.TempDir()
	pidFile := filepath.Join(ws, "escapee.pid")
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}
	// The shell waits for the pid file so the tracker's ppid link to the
	// escapee exists for at least one sample before the shell exits.
	command := setsidEscapeeCommand(pidFile, false) + ` while [ ! -s ` + portableShellQuote(pidFile) + ` ]; do /bin/sleep 0.05; done; /bin/sleep 0.5`
	var runErr error
	runWithHangGuard(t, 10*time.Second, func() {
		_, _, runErr = e.RunCommand(context.Background(), ws, command)
	})
	pid := readEscapeePID(t, pidFile)
	if !escapeeGone(pid) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
		t.Fatalf("setsid escapee pid %d survived (run err %v)", pid, runErr)
	}
	// The tracker killed the escapee, so the pipe closed and the drain
	// completed: this is a normal, complete run, not a drain timeout.
	if runErr != nil {
		t.Fatalf("RunCommand error = %v, want nil (the escapee was killed, so the drain completed)", runErr)
	}
}

// TestUnconfinedRunDrainIsBoundedWhenEscapeeHoldsPipe covers the path with NO
// tracker: an Unconfined executor (null backend) makes no containment claim,
// so the escapee survives teardown. The drain must still be bounded: run
// closes its read ends after the grace period and returns the partial output
// with ErrOutputDrainIncomplete instead of blocking forever, and an
// ExecutorSet holding the executor can then close.
func TestUnconfinedRunDrainIsBoundedWhenEscapeeHoldsPipe(t *testing.T) {
	ws := t.TempDir()
	pidFile := filepath.Join(ws, "escapee.pid")
	prof := mustProfile(t, testsupport.UnconfinedConfig(ws, true))
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	e, err := set.For("drain")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	command := `echo before; ` + setsidEscapeeCommand(pidFile, false) + ` while [ ! -s ` + portableShellQuote(pidFile) + ` ]; do /bin/sleep 0.05; done`
	var (
		out    []byte
		code   int
		runErr error
	)
	runWithHangGuard(t, 10*time.Second, func() {
		out, code, runErr = e.RunCommand(context.Background(), ws, command)
	})
	pid := readEscapeePID(t, pidFile)
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	if !errors.Is(runErr, ErrOutputDrainIncomplete) {
		t.Fatalf("RunCommand error = %v, want ErrOutputDrainIncomplete", runErr)
	}
	if code != -1 {
		t.Fatalf("RunCommand code = %d, want -1 alongside the error", code)
	}
	if !strings.Contains(string(out), "before") {
		t.Fatalf("partial output %q lost the bytes written before teardown", out)
	}
	closed := make(chan error, 1)
	go func() { closed <- set.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("ExecutorSet.Close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ExecutorSet.Close blocked behind the escapee's run (M10)")
	}
}
