//go:build darwin || linux

package exec

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// This file covers Task 21's Step 1 test list for the Unix PTY-backed async
// process path: real interactive echo, combined stdout/stderr, `stty size`,
// resize, input, EOF (closing stdin), Ctrl-D (the in-band VEOF byte),
// interrupt delivered to the terminal's foreground process group, PTY EIO
// normalization, allocation failure, no silent pipe fallback, and Setsid's
// coexistence with this package's existing Setpgid-based process-tree
// containment (newProcessTree, process_tree_unix.go).
//
// Every test here spawns through the production PreparedProcess/Start path
// (ProcessOptions.TTY: true) under captureBackend — a test double, not the
// real Seatbelt/Landlock backend — exactly like this package's other
// _unix_test.go async lifecycle tests (e.g. process_parent_death_unix_test.go's
// spawnSupervisedSleep). That keeps this file runnable for real inside the
// managed development sandbox on darwin, with no dependency on real OS
// confinement: attachSupervisedProof only attaches Darwin's best-effort
// prover to a Supervised spawn compiled through the REAL Seatbelt backend
// (process_tree_darwin.go), and captureBackend is not that, so every spawn
// here reports LifetimeContainmentUnspecified rather than BestEffort. A REAL
// Seatbelt-confined PTY spawn's best-effort containment is proved for real,
// under the real backend, by process_pty_integration_unix_test.go's
// TestIntegrationProcessPTYLifecycle — not this file's job.

// startPTYProcess prepares and starts a real TTY-backed Process running
// command, failing the test on any error. Both the Process and the
// ExecutorSet are closed via t.Cleanup.
func startPTYProcess(t *testing.T, command string) *Process {
	t.Helper()
	workspace := t.TempDir()
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(&captureBackend{
			bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		})))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("pty-test")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: command, ExecutionID: "pty-test", TTY: true,
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })
	return proc
}

// readUntilContains reads r in a background goroutine, accumulating bytes,
// until the accumulated text contains substr, r.Read returns an error, or
// timeout elapses (in which case the goroutine is abandoned — acceptable in
// test code, since abandoning only happens on the already-failing path this
// helper is about to report). It never uses a read deadline: creack/pty
// master files do not support one on darwin ("file type does not support
// deadline"), confirmed empirically against this exact Go toolchain.
func readUntilContains(t *testing.T, r io.Reader, substr string, timeout time.Duration) string {
	t.Helper()
	done := make(chan string, 1)
	go func() {
		var collected []byte
		buf := make([]byte, 256)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				collected = append(collected, buf[:n]...)
				if strings.Contains(string(collected), substr) {
					done <- string(collected)
					return
				}
			}
			if err != nil {
				done <- string(collected)
				return
			}
		}
	}()
	select {
	case got := <-done:
		if !strings.Contains(got, substr) {
			t.Fatalf("read %q before EOF/error, want it to contain %q", got, substr)
		}
		return got
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for %q", timeout, substr)
		return ""
	}
}

// readUntilEOF reads r to completion (io.EOF or another error) in a
// background goroutine, bounded by timeout exactly like readUntilContains.
func readUntilEOF(t *testing.T, r io.Reader, timeout time.Duration) (string, error) {
	t.Helper()
	type result struct {
		data string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		var collected []byte
		buf := make([]byte, 256)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				collected = append(collected, buf[:n]...)
			}
			if err != nil {
				done <- result{string(collected), err}
				return
			}
		}
	}()
	select {
	case res := <-done:
		return res.data, res.err
	case <-time.After(timeout):
		t.Fatalf("timed out after %s waiting for EOF", timeout)
		return "", nil
	}
}

// TestProcessPTYInteractiveEcho proves a real, live, interactive round trip:
// bytes written to Stdin arrive at the child (cat) and its echoed response
// arrives back on Stdout, all through one real PTY. It checks ExitCode, not
// just that Wait returns promptly: closing Stdin here must deliver EOF
// in-band (see terminalStdin, terminal.go) rather than hanging up the
// terminal, so cat exits 0 by observing EOF on its own read — a
// SIGHUP-killed child would also make Wait return promptly (with a
// negative/non-zero ExitCode), silently masking a regression in that fix.
func TestProcessPTYInteractiveEcho(t *testing.T) {
	proc := startPTYProcess(t, "cat")
	if _, err := proc.Stdin().Write([]byte("hello-pty\n")); err != nil {
		t.Fatalf("Stdin.Write: %v", err)
	}
	readUntilContains(t, proc.Stdout(), "hello-pty", 5*time.Second)
	if err := proc.Stdin().Close(); err != nil {
		t.Fatalf("Stdin.Close: %v", err)
	}
	result, err := proc.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (a non-zero/negative exit here means the child died of SIGHUP instead of observing in-band EOF)", result.ExitCode)
	}
}

// TestProcessPTYInput proves multiple successive writes to Stdin all reach
// the child, not just a single one-shot write.
func TestProcessPTYInput(t *testing.T) {
	proc := startPTYProcess(t, "cat")
	for _, line := range []string{"first-line\n", "second-line\n", "third-line\n"} {
		if _, err := proc.Stdin().Write([]byte(line)); err != nil {
			t.Fatalf("Stdin.Write(%q): %v", line, err)
		}
	}
	readUntilContains(t, proc.Stdout(), "third-line", 5*time.Second)
	if err := proc.Stdin().Close(); err != nil {
		t.Fatalf("Stdin.Close: %v", err)
	}
	result, err := proc.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
}

// TestProcessPTYCombinedOutput proves stdout and stderr are combined into
// Stdout's one stream, and that Stderr is the synthetic, permanently-empty
// reader — never a second live pipe.
func TestProcessPTYCombinedOutput(t *testing.T) {
	proc := startPTYProcess(t, "sh -c 'echo out-marker; echo err-marker 1>&2'")
	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	got, err := readUntilEOF(t, proc.Stdout(), 5*time.Second)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Stdout drain error = %v, want io.EOF", err)
	}
	if !strings.Contains(got, "out-marker") || !strings.Contains(got, "err-marker") {
		t.Fatalf("combined output = %q, want it to contain both out-marker and err-marker", got)
	}

	buf := make([]byte, 8)
	n, err := proc.Stderr().Read(buf)
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Stderr().Read = (%d, %v), want (0, io.EOF)", n, err)
	}
	if proc.StreamMode() != ProcessStreamModePTY {
		t.Fatalf("StreamMode() = %v, want ProcessStreamModePTY", proc.StreamMode())
	}
}

// TestProcessPTYWindowSize proves the spawned process has a genuine
// controlling terminal: `stty size` only succeeds (exit 0, two integers) on
// a real tty, never on a plain pipe.
func TestProcessPTYWindowSize(t *testing.T) {
	proc := startPTYProcess(t, "stty size")
	result, err := proc.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("`stty size` ExitCode = %d, want 0 (a plain pipe would fail this)", result.ExitCode)
	}
	got, err := readUntilEOF(t, proc.Stdout(), 5*time.Second)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Stdout drain error = %v, want io.EOF", err)
	}
	fields := strings.Fields(got)
	if len(fields) != 2 {
		t.Fatalf("`stty size` output = %q, want exactly two fields (rows, cols)", got)
	}
	for _, field := range fields {
		if _, err := strconv.Atoi(field); err != nil {
			t.Fatalf("`stty size` field %q is not an integer: %v", field, err)
		}
	}
}

// TestProcessPTYResize proves Process.Resize actually changes the window
// size an already-running process observes: the child blocks on `read`
// until the test writes a line to Stdin, so Resize is guaranteed to run
// before `stty size` executes.
func TestProcessPTYResize(t *testing.T) {
	proc := startPTYProcess(t, "sh -c 'read _; stty size'")
	if err := proc.Resize(context.Background(), 42, 111); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if _, err := proc.Stdin().Write([]byte("\n")); err != nil {
		t.Fatalf("Stdin.Write: %v", err)
	}
	result, err := proc.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
	got, err := readUntilEOF(t, proc.Stdout(), 5*time.Second)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Stdout drain error = %v, want io.EOF", err)
	}
	if !strings.Contains(got, "42 111") {
		t.Fatalf("`stty size` output = %q, want it to contain the resized \"42 111\"", got)
	}
}

// TestProcessPTYEOF proves closing Stdin delivers EOF to the child IN-BAND
// (the VEOF control byte written to the master — see terminalStdin,
// terminal.go) rather than hanging up the whole terminal, and the child
// observes that as its own read returning EOF and exits cleanly. ExitCode is
// checked, not just Wait's promptness: a SIGHUP-killed child (the pre-fix
// behavior, when Stdin.Close() closed the master outright) also makes Wait
// return promptly, just with a non-zero/negative exit instead of a clean 0.
func TestProcessPTYEOF(t *testing.T) {
	proc := startPTYProcess(t, "cat")
	if err := proc.Stdin().Close(); err != nil {
		t.Fatalf("Stdin.Close: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := proc.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait after closing Stdin did not return in time (EOF was not really propagated): %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (the child died of SIGHUP instead of observing in-band EOF)", result.ExitCode)
	}
}

// TestProcessPTYCtrlD proves the in-band VEOF control character (0x04) ends
// the CHILD's own read call without closing anything on this side: the
// terminal stays fully open (no explicit Stdin.Close here), the echoed input
// still arrives, and the child (cat) exits gracefully in response to the
// EOF condition the kernel's line discipline delivers to its read call.
func TestProcessPTYCtrlD(t *testing.T) {
	proc := startPTYProcess(t, "cat")
	if _, err := proc.Stdin().Write([]byte("before-eof\n")); err != nil {
		t.Fatalf("Stdin.Write: %v", err)
	}
	readUntilContains(t, proc.Stdout(), "before-eof", 5*time.Second)
	if _, err := proc.Stdin().Write([]byte{0x04}); err != nil {
		t.Fatalf("Stdin.Write(Ctrl-D): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := proc.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait after Ctrl-D did not return in time (VEOF was not really delivered): %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (cat should exit cleanly on VEOF, not die of a signal)", result.ExitCode)
	}
}

// TestProcessPTYInterruptForegroundGroup proves the terminal's own line
// discipline — not Process.Signal, which is never called here — delivers
// SIGINT to the spawned process's foreground process group when the in-band
// INTR control character (0x03, Ctrl-C) is written to the terminal. This
// only works if prepareTerminalSysProcAttr's Setsid/Setctty setup genuinely
// established a job-control-capable session: `sleep 30` has no custom signal
// handling, so only a real, kernel-delivered SIGINT explains a prompt exit.
func TestProcessPTYInterruptForegroundGroup(t *testing.T) {
	proc := startPTYProcess(t, "sleep 30")
	if _, err := proc.Stdin().Write([]byte{0x03}); err != nil {
		t.Fatalf("Stdin.Write(Ctrl-C): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := proc.Wait(ctx); err != nil {
		t.Fatalf("Wait after in-band interrupt did not return in time (SIGINT was not really delivered to the foreground group): %v", err)
	}
}

// TestProcessPTYEIONormalization proves Process.Stdout's Read reports
// io.EOF, never a raw platform errno, once the child has fully exited and
// this package's own parent-side slave reference is already gone (dropped
// right after Start — see startConfinedTTY, process.go). Linux reports this
// condition as EIO on the master; Darwin already reports a clean EOF for the
// identical condition, so this assertion is meaningful (and holds) on both.
func TestProcessPTYEIONormalization(t *testing.T) {
	proc := startPTYProcess(t, "sh -c 'echo done'")
	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	_, err := readUntilEOF(t, proc.Stdout(), 5*time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("final Stdout Read error = %v, want io.EOF (not a raw platform errno)", err)
	}
}

// TestProcessPTYAllocationFailure proves a PTY allocation failure is
// propagated as a real Start error — no Process is ever returned, and no
// child is ever spawned (proved by a marker file that never appears) —
// rather than panicking or silently falling back to anything.
func TestProcessPTYAllocationFailure(t *testing.T) {
	injected := errors.New("injected pty allocation failure")
	original := openPTY
	openPTY = func() (*os.File, *os.File, error) { return nil, nil, injected }
	t.Cleanup(func() { openPTY = original })

	workspace := t.TempDir()
	marker := workspace + string(os.PathSeparator) + "marker"
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(&captureBackend{
			bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		})))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("pty-alloc-failure")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: portableWriteCommand(marker, "spawned"),
		ExecutionID: "pty-alloc-failure", TTY: true,
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if !errors.Is(err, injected) {
		t.Fatalf("Start error = %v, want the injected allocation failure", err)
	}
	if proc != nil {
		t.Fatal("Start returned a non-nil Process alongside an allocation failure")
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("marker exists even though PTY allocation failed before spawn: stat err = %v", statErr)
	}
}

// TestProcessPTYNoPipeFallback proves a successful TTY spawn never silently
// mixes in pipe-shaped streams. It checks the CONTRACT through observable
// behavior rather than Stdout()'s dynamic type: Fix 1 (Task 21's PTY-hang
// fix) interposes an output-draining pump between the real terminal master
// and Process.Stdout, so Stdout()'s dynamic type is now the pump's own pipe
// read end, not *terminalMaster — asserting pointer/type identity against
// the master would fail even though there is still exactly one real PTY and
// no silent second pipe. What must still hold, and is what this test proves
// instead: StreamMode reports PTY; Stdout carries stdout AND stderr combined
// into ONE interleaved stream (a real second pipe would keep err-marker off
// Stdout entirely); Stderr is the synthetic, already-closed, empty reader;
// and Resize still reaches a genuine terminal on a still-running process
// (proving Stdin/Stdout/resize all still ride the same underlying PTY).
func TestProcessPTYNoPipeFallback(t *testing.T) {
	proc := startPTYProcess(t, "sh -c 'read _; echo out-marker; echo err-marker 1>&2'")
	if proc.StreamMode() != ProcessStreamModePTY {
		t.Fatalf("StreamMode() = %v, want ProcessStreamModePTY", proc.StreamMode())
	}
	if _, ok := proc.Stderr().(closedEmptyReadCloser); !ok {
		t.Fatalf("Stderr() dynamic type = %T, want closedEmptyReadCloser", proc.Stderr())
	}
	buf := make([]byte, 8)
	if n, err := proc.Stderr().Read(buf); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("Stderr().Read = (%d, %v), want (0, io.EOF)", n, err)
	}
	if err := proc.Resize(context.Background(), 42, 111); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if _, err := proc.Stdin().Write([]byte("\n")); err != nil {
		t.Fatalf("Stdin.Write: %v", err)
	}
	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	got, err := readUntilEOF(t, proc.Stdout(), 5*time.Second)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Stdout drain error = %v, want io.EOF", err)
	}
	if !strings.Contains(got, "out-marker") || !strings.Contains(got, "err-marker") {
		t.Fatalf("combined output = %q, want it to contain both out-marker and err-marker (a silent second pipe would leave err-marker off Stdout entirely)", got)
	}
}

// TestProcessPTYCloseAfterNaturalExit proves Close() returns nil on the
// most common, well-behaved sequence — run to completion, Wait, then Close —
// even though terminalStdin.Close() (terminal.go) writes the VEOF byte to
// the master unconditionally: by the time the child has already exited, this
// package's own parent-side slave reference is already gone (dropped right
// after Start — see openProcessTerminal's doc, terminal_unix.go), so that
// write fails with EIO. terminalStdin.Close() must normalize that to nil —
// there is nothing left to signal EOF to — rather than let it surface as
// Process.Close's returned error, mirroring the pipe-backed path, which
// never errors on closing your own pipe end regardless of the peer's state.
// startPTYProcess's own t.Cleanup ignores Close's error (`_ =
// proc.Close(...)`), so this regression would be invisible to every other
// test in this file; this test calls Close directly and checks it.
func TestProcessPTYCloseAfterNaturalExit(t *testing.T) {
	proc := startPTYProcess(t, "true")
	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if err := proc.Close(context.Background()); err != nil {
		t.Fatalf("Close after natural exit = %v, want nil (EIO from writing VEOF to an already-gone slave must be normalized away)", err)
	}
}

// TestTerminalMasterReadNormalizesEIOToEOF is a direct unit-level proof of
// terminalMaster.Read's own contract — exercised against Read itself, not
// only transitively through Process.Stdout()/the output-draining pump (see
// that method's own doc comment for why the two are independent guarantees).
// It never spawns a Process or a child at all: opening a PTY and closing its
// only slave reference, in this test's own process, already reproduces "every
// slave-side reference is gone" — the exact condition the doc contract is
// about. Mirrors TestProcessPTYEIONormalization's own caveat: Linux reports
// this condition as EIO on the master (which Read must normalize), Darwin
// already reports a clean EOF for the identical condition, so the assertion
// is meaningful — and holds — on both, even though only Linux actually
// exercises the normalization branch itself.
func TestTerminalMasterReadNormalizesEIOToEOF(t *testing.T) {
	master, slave, err := openPTY()
	if err != nil {
		t.Fatalf("openPTY: %v", err)
	}
	tm := newTerminalMaster(master)
	t.Cleanup(func() { _ = tm.Close() })

	if err := slave.Close(); err != nil {
		t.Fatalf("slave.Close: %v", err)
	}

	buf := make([]byte, 8)
	if _, err := tm.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("Read once every slave reference is gone = %v, want io.EOF (never a raw platform errno)", err)
	}
}

// TestProcessPTYResizeCloseRace exercises Process.Resize concurrently with
// Process.Close under -race. terminalMaster.resize (terminal_unix.go) now
// drives the TIOCSWINSZ ioctl through (*os.File).SyscallConn().Control
// instead of github.com/creack/pty's own Setsize (which issues its ioctl
// against a raw Fd(), forfeiting the safe-concurrent-close protection Read/
// Write/Close already get) specifically so a resize (e.g. forwarding a
// SIGWINCH) racing session teardown — a realistic usage pattern for this
// module, not a contrived one — can never land on an already-closed or
// already-reused file descriptor. This test cannot, from this package,
// observe internal/poll's reference counting directly; it proves this fix's
// stated minimum bar instead: concurrent Resize/Close neither deadlocks nor
// panics nor is flagged by the race detector, and the process still reaches
// a confirmed terminal state promptly afterward.
func TestProcessPTYResizeCloseRace(t *testing.T) {
	proc := startPTYProcess(t, "sleep 5")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			_ = proc.Resize(context.Background(), uint16(20+i%10), uint16(80+i%10))
		}
	}()

	if err := proc.Close(context.Background()); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()

	// A generous timeout, not a tight one: this test's point is the absence
	// of a deadlock/panic/race, not exact timing, and -race's instrumentation
	// overhead on 200 rapid ioctl syscalls plus a real child spawn/reap can
	// legitimately push this well past the other tests' usual 5s under load.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := proc.Wait(ctx); err != nil {
		t.Fatalf("Wait after concurrent Resize/Close did not return in time: %v", err)
	}
}

// TestProcessPTYSessionSetupNoSetpgidConflict is the direct unit-level proof
// that newProcessTree (process_tree_unix.go) skips its own Setpgid when
// prepareTerminalSysProcAttr (terminal_unix.go) already set Setsid: POSIX
// forbids setpgid on a session leader (EPERM unconditionally), so layering
// both would make every real PTY spawn fail to start. Mirrors
// TestDarwinLifetimeCapabilityBestEffort's (process_tree_darwin_test.go)
// style of exercising newProcessTree/attachSupervisedProof directly, without
// spawning a real process.
func TestProcessPTYSessionSetupNoSetpgidConflict(t *testing.T) {
	cmd := exec.Command("true")
	prepareTerminalSysProcAttr(cmd)
	if !cmd.SysProcAttr.Setsid {
		t.Fatal("prepareTerminalSysProcAttr did not set Setsid")
	}
	if !cmd.SysProcAttr.Setctty {
		t.Fatal("prepareTerminalSysProcAttr did not set Setctty")
	}
	if cmd.SysProcAttr.Ctty != 0 {
		t.Fatalf("Ctty = %d, want 0 (the PTY slave is attached as fd 0)", cmd.SysProcAttr.Ctty)
	}

	tree, err := newProcessTree(cmd, processTreeOptions{Supervised: false})
	if err != nil {
		t.Fatalf("newProcessTree: %v", err)
	}
	if tree == nil {
		t.Fatal("newProcessTree returned a nil tree")
	}
	if cmd.SysProcAttr.Setpgid {
		t.Fatal("newProcessTree layered Setpgid on top of an already-requested Setsid; POSIX forbids setpgid on a session leader (EPERM)")
	}
}

// TestProcessPTYSetsidSetpgidRealSpawnSucceeds is
// TestProcessPTYSessionSetupNoSetpgidConflict's empirical companion: it
// proves the combined Setsid/Setctty/Setpgid-skip decision actually works at
// the real kernel syscall level (a genuine `fork/exec: operation not
// permitted` from the conflict this package works around would surface here
// as a Start failure, not merely as an unexpected SysProcAttr field).
func TestProcessPTYSetsidSetpgidRealSpawnSucceeds(t *testing.T) {
	proc := startPTYProcess(t, portableSuccessCommand())
	result, err := proc.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
}
