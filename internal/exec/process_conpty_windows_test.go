//go:build windows

package exec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

// This file covers Task 22B's Windows ConPTY-backed async process path,
// mirroring process_pty_unix_test.go's own test list, translated to the
// primitives Windows actually offers (there is no `stty size`, no VINTR
// control byte a kernel line discipline recognizes, and no
// GenerateConsoleCtrlEvent path that can reach a ConPTY-attached child — see
// each test's own doc comment for the specific translation and why it is
// faithful): CreatePseudoConsole setup and typed unavailable behavior,
// interactive echo, combined output, resize, input and terminal EOF,
// interrupt, no pipe fallback, plus direct unit-level proofs of the two
// mechanisms this platform's implementation leans on that Unix's does not
// (Go's own ERROR_BROKEN_PIPE-to-io.EOF pipe normalization, and
// conPTYTerminal.Write's exact-match VEOF-byte interception) and the
// Job-before-Resume containment proof (mirroring
// TestProcessTreeWindowsJobBeforeResume, process_tree_windows_test.go,
// exactly, routed through the ConPTY dispatch instead of the plain
// cmd.Start() path).
//
// Every test that goes through the production PreparedProcess/Start path
// (ProcessOptions.TTY: true) uses captureBackend — a test double, not the
// real restricted/elevated backend — exactly like process_pty_unix_test.go's
// own startPTYProcess: newProcessTree (process_tree_windows.go) still
// creates a REAL Windows Job regardless of which enforce.Backend compiled
// the spec, since the Job/process-tree layer is backend-independent, so
// this still exercises this task's real ConPTY code end to end.
//
// findstr "^" (a regex matching every line) is this file's cat/`sh -c
// 'read...'`-equivalent portable interactive echo command: a well-
// established trick for exercising line-buffered stdin/stdout round trips
// through a Windows console (including ConPTY) with no dependency on any
// custom helper binary. set /p x= is this file's `read _`-equivalent
// portable "block for exactly one line of input" command.

// startConPTYProcess prepares and starts a real ConPTY-backed Process
// running command, failing the test on any error. Mirrors startPTYProcess
// (process_pty_unix_test.go) exactly; both the Process and the ExecutorSet
// are closed via t.Cleanup.
func startConPTYProcess(t *testing.T, command string) *Process {
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
	executor, err := set.For("conpty-test")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: command, ExecutionID: "conpty-test", TTY: true,
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

// conPTYReadUntilContains mirrors readUntilContains (process_pty_unix_test.go)
// exactly; duplicated here rather than shared because that file's build tag
// excludes windows.
func conPTYReadUntilContains(t *testing.T, r io.Reader, substr string, timeout time.Duration) string {
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

// conPTYReadUntilEOF mirrors readUntilEOF (process_pty_unix_test.go) exactly;
// duplicated for the same reason as conPTYReadUntilContains above.
func conPTYReadUntilEOF(t *testing.T, r io.Reader, timeout time.Duration) (string, error) {
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

// TestProcessConPTYInteractive is Task 22B's named phase-gate test: a real,
// live, interactive round trip through a real ConPTY — bytes written to
// Stdin arrive at the child (findstr "^", this file's cat-equivalent — see
// this file's own top-of-file doc comment) and its echoed response arrives
// back on Stdout. It checks ExitCode, not just that Wait returns promptly:
// closing Stdin here must deliver EOF via conPTYTerminal.Write's veofByte
// interception — closing the retained input pipe write end (see terminal_
// windows.go's own "VEOF/EOF design decision" doc comment) — rather than
// tearing down the pseudo console, so findstr exits 0 by observing EOF on
// its own read; a torn-down pseudo console killing the child instead would
// also make Wait return promptly, just with a non-zero/negative exit
// instead of a clean 0, silently masking a regression in that design
// decision exactly like the Unix analogue's own doc comment explains for
// SIGHUP.
func TestProcessConPTYInteractive(t *testing.T) {
	proc := startConPTYProcess(t, `findstr "^"`)
	if _, err := proc.Stdin().Write([]byte("hello-conpty\r\n")); err != nil {
		t.Fatalf("Stdin.Write: %v", err)
	}
	conPTYReadUntilContains(t, proc.Stdout(), "hello-conpty", 5*time.Second)
	if err := proc.Stdin().Close(); err != nil {
		t.Fatalf("Stdin.Close: %v", err)
	}
	result, err := proc.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (a non-zero exit here means the pseudo console was torn down instead of the child observing a clean EOF)", result.ExitCode)
	}
}

// TestProcessConPTYInput proves multiple successive writes to Stdin all
// reach the child, not just a single one-shot write.
func TestProcessConPTYInput(t *testing.T) {
	proc := startConPTYProcess(t, `findstr "^"`)
	for _, line := range []string{"first-line\r\n", "second-line\r\n", "third-line\r\n"} {
		if _, err := proc.Stdin().Write([]byte(line)); err != nil {
			t.Fatalf("Stdin.Write(%q): %v", line, err)
		}
	}
	conPTYReadUntilContains(t, proc.Stdout(), "third-line", 5*time.Second)
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

// TestProcessConPTYCombinedOutput proves stdout and stderr are combined into
// Stdout's one stream (both console output streams a ConPTY-attached
// process writes to route through the SAME pseudo console output pipe —
// there is no separate stderr channel to a console at all, unlike a plain
// pipe-backed spawn's independent os.Pipe pair), and that Stderr is the
// synthetic, permanently-empty reader — never a second live pipe.
func TestProcessConPTYCombinedOutput(t *testing.T) {
	proc := startConPTYProcess(t, "echo out-marker & echo err-marker 1>&2")
	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	got, err := conPTYReadUntilEOF(t, proc.Stdout(), 5*time.Second)
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

// TestProcessConPTYResize proves Process.Resize succeeds against a live,
// genuinely blocked process and does not disturb it: the child (set /p x=,
// this file's `read _`-equivalent) blocks until the test writes a line to
// Stdin, so Resize is guaranteed to run before the child ever unblocks.
// Unlike TestProcessPTYResize (process_pty_unix_test.go), which independently
// re-verifies the resulting geometry via `stty size`, Windows has no
// cmd.exe-builtin equivalent this file can rely on without pulling in
// PowerShell or a dedicated helper binary; this test instead proves what IS
// observable without extra tooling. TestProcessConPTYNoPipeFallback, below,
// additionally proves Resize/Stdin/Stdout still ride the SAME pseudo
// console on a still-running process.
func TestProcessConPTYResize(t *testing.T) {
	proc := startConPTYProcess(t, "set /p x=")
	if err := proc.Resize(context.Background(), 42, 111); err != nil {
		t.Fatalf("Resize: %v", err)
	}
	if _, err := proc.Stdin().Write([]byte("unblock\r\n")); err != nil {
		t.Fatalf("Stdin.Write: %v", err)
	}
	result, err := proc.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0", result.ExitCode)
	}
}

// TestProcessConPTYEOF proves closing Stdin delivers EOF to the child by
// closing the pseudo console's retained input pipe write end (see terminal_
// windows.go's conPTYTerminal.Write) rather than tearing down the whole
// pseudo console, and the child observes that as its own read returning EOF
// and exits cleanly. ExitCode is checked, not just Wait's promptness — see
// TestProcessConPTYInteractive's own doc comment for why that matters.
func TestProcessConPTYEOF(t *testing.T) {
	proc := startConPTYProcess(t, `findstr "^"`)
	if err := proc.Stdin().Close(); err != nil {
		t.Fatalf("Stdin.Close: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := proc.Wait(ctx)
	if err != nil {
		t.Fatalf("Wait after closing Stdin did not return in time (EOF was not really propagated through the pseudo console's input pipe): %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("ExitCode = %d, want 0 (the child was torn down instead of observing a clean EOF)", result.ExitCode)
	}
}

// TestProcessConPTYCtrlD proves the exact one-byte veofByte (0x04) write
// this file's "VEOF/EOF design decision" documents (terminal_windows.go) end
// the child's own read call — via conPTYTerminal.Write's interception
// closing the retained input pipe write end — even with NO explicit
// Stdin.Close() call, mirroring TestProcessPTYCtrlD's own structure exactly
// (process_pty_unix_test.go). Unlike that Unix test, this does not (and
// cannot) prove the pseudo console stays open for FURTHER writes afterward:
// closing the input pipe is, on this platform, an irreversible action for
// this Process's whole input channel — see this file's own top-of-file doc
// comment and conPTYTerminal.Write's doc comment for why that one-shot-ness
// is an accepted, platform-inherent difference from Unix's repeatable VEOF,
// not exercised by production code, which only ever sends this byte once,
// via Stdin().Close().
func TestProcessConPTYCtrlD(t *testing.T) {
	proc := startConPTYProcess(t, `findstr "^"`)
	if _, err := proc.Stdin().Write([]byte("before-eof\r\n")); err != nil {
		t.Fatalf("Stdin.Write: %v", err)
	}
	conPTYReadUntilContains(t, proc.Stdout(), "before-eof", 5*time.Second)
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
		t.Fatalf("ExitCode = %d, want 0 (findstr should exit cleanly on EOF, not die of an unexpected teardown)", result.ExitCode)
	}
}

// TestProcessConPTYInterrupt proves Process.Signal(ProcessSignalInterrupt)
// actually reaches a ConPTY-attached child, via conPTYSignaler
// (terminal_windows.go): writing conPTYInterruptByte (0x03) into the pseudo
// console's own input stream, which the console host translates into a real
// CTRL_C_EVENT delivered to the attached process — NOT via *processTree's
// own sendInterrupt (GenerateConsoleCtrlEvent), which cannot reach a
// ConPTY-attached child at all (see conPTYSignaler's own doc comment for
// exactly why: PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE attaches the child to the
// pseudo console instead of the caller's own console, and
// GenerateConsoleCtrlEvent only reaches a process group sharing the
// CALLER's console). Unlike Unix, where Process.Signal(Interrupt) delivers
// SIGINT via a process-group kill entirely independent of the terminal
// (lifetime_unix.go) — TestProcessPTYInterruptForegroundGroup
// (process_pty_unix_test.go) exercises a SEPARATE, terminal-byte-based path
// that never goes through Process.Signal at all — this Process.Signal call
// itself is what routes through the pseudo console's input stream on
// Windows, because no terminal-independent primitive can reach a
// ConPTY-attached child (see conPTYInterruptByte's own doc comment).
// portableSleepCommand's underlying ping.exe has no custom console-control-
// event handler, so only a genuinely delivered CTRL_C_EVENT (the console's
// own default unhandled-event action is termination) explains a prompt exit
// here.
func TestProcessConPTYInterrupt(t *testing.T) {
	proc := startConPTYProcess(t, portableSleepCommand(30))
	if err := proc.Signal(context.Background(), ProcessSignalInterrupt); err != nil {
		t.Fatalf("Signal(Interrupt): %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := proc.Wait(ctx); err != nil {
		t.Fatalf("Wait after in-band interrupt did not return in time (Ctrl-C was not really delivered through the pseudo console's input stream): %v", err)
	}
}

// TestProcessConPTYOutputEOFNormalization proves Process.Stdout's Read
// reports io.EOF, never a raw platform error, once the child has fully
// exited. This is the Windows analogue of TestProcessPTYEIONormalization
// (process_pty_unix_test.go) — but unlike Linux's EIO-on-an-abandoned-PTY-
// master, which terminalMaster.Read must explicitly normalize, Go's own os
// package already normalizes ERROR_BROKEN_PIPE to io.EOF for any pipe-kind
// *os.File (see TestConPTYPipeReadNormalizesBrokenPipeToEOF, below, for the
// direct unit-level proof of that claim), so conPTYTerminal.Read needs no
// equivalent explicit normalization of its own; this test proves the same
// OBSERVABLE CONTRACT holds end to end regardless.
func TestProcessConPTYOutputEOFNormalization(t *testing.T) {
	proc := startConPTYProcess(t, "echo done")
	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	_, err := conPTYReadUntilEOF(t, proc.Stdout(), 5*time.Second)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("final Stdout Read error = %v, want io.EOF (not a raw platform error)", err)
	}
}

// TestProcessConPTYUnavailable proves the "typed unavailable behavior"
// acceptance criterion: a host that lacks the CreatePseudoConsole export
// (probed by conPTYProbe, terminal_windows.go, before any allocation) fails
// Start with the typed ErrProcessConPTYUnavailable sentinel — never a panic (see
// conPTYCreatePseudoConsoleProc's own doc comment for why probing first,
// rather than calling golang.org/x/sys/windows.CreatePseudoConsole directly,
// matters) — and no Process is ever returned, and no child is ever spawned
// (proved by a marker file that never appears), mirroring
// TestProcessPTYAllocationFailure's (process_pty_unix_test.go) own structure
// exactly. conPTYProbe's indirection (mirroring openPTY's identical
// indirection on Unix) lets this run deterministically on any Windows host,
// including one that DOES have ConPTY.
func TestProcessConPTYUnavailable(t *testing.T) {
	injected := fmt.Errorf("%w: injected unavailable ConPTY", ErrProcessConPTYUnavailable)
	original := conPTYProbe
	conPTYProbe = func() error { return injected }
	t.Cleanup(func() { conPTYProbe = original })

	workspace := t.TempDir()
	marker := filepath.Join(workspace, "marker")
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
	executor, err := set.For("conpty-unavailable")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: portableWriteCommand(marker, "spawned"),
		ExecutionID: "conpty-unavailable", TTY: true,
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if !errors.Is(err, ErrProcessConPTYUnavailable) {
		t.Fatalf("Start error = %v, want ErrProcessConPTYUnavailable", err)
	}
	if proc != nil {
		t.Fatal("Start returned a non-nil Process alongside an unavailable-ConPTY failure")
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("marker exists even though ConPTY was unavailable: stat err = %v", statErr)
	}
}

// TestProcessConPTYNoPipeFallback proves a successful ConPTY spawn never
// silently mixes in pipe-shaped streams — mirroring TestProcessPTYNoPipeFallback
// (process_pty_unix_test.go) exactly: StreamMode reports PTY; Stdout carries
// stdout AND stderr combined into ONE interleaved stream (a real second pipe
// would keep err-marker off Stdout entirely); Stderr is the synthetic,
// already-closed, empty reader; and Resize still reaches the genuine pseudo
// console on a still-running process (proving Stdin/Stdout/resize all still
// ride the same underlying ConPTY).
func TestProcessConPTYNoPipeFallback(t *testing.T) {
	proc := startConPTYProcess(t, "set /p x= & echo out-marker & echo err-marker 1>&2")
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
	if _, err := proc.Stdin().Write([]byte("\r\n")); err != nil {
		t.Fatalf("Stdin.Write: %v", err)
	}
	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	got, err := conPTYReadUntilEOF(t, proc.Stdout(), 5*time.Second)
	if err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("Stdout drain error = %v, want io.EOF", err)
	}
	if !strings.Contains(got, "out-marker") || !strings.Contains(got, "err-marker") {
		t.Fatalf("combined output = %q, want it to contain both out-marker and err-marker (a silent second pipe would leave err-marker off Stdout entirely)", got)
	}
}

// TestProcessConPTYCloseAfterNaturalExit proves Close() returns nil on the
// most common, well-behaved sequence — run to completion, Wait, then Close.
// Unlike Unix's identically named test (process_pty_unix_test.go), Windows
// needs no EIO-style normalization here at all: conPTYTerminal.Close closes
// only OUR OWN retained pipe/console handles, which never fail due to the
// far end's state — closing your own handle is unconditionally safe
// regardless of whether the child that used to read from it is still
// running, exiting, or long gone. This test exists to prove that holds in
// practice, not merely by inspection of the Close implementation.
func TestProcessConPTYCloseAfterNaturalExit(t *testing.T) {
	proc := startConPTYProcess(t, portableSuccessCommand())
	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if err := proc.Close(context.Background()); err != nil {
		t.Fatalf("Close after natural exit = %v, want nil", err)
	}
}

// TestProcessConPTYResizeCloseRace exercises Process.Resize concurrently
// with Process.Close under -race, mirroring TestProcessPTYResizeCloseRace
// (process_pty_unix_test.go) exactly. conPTYTerminal.resize (terminal_
// windows.go) guards the pseudo-console handle with its own mutex — the
// SAME pattern internal/windows/job_windows.go's Job type already uses for
// its own handle, chosen deliberately over *os.File's SyscallConn/Control
// (which console, unlike input/output, is never wrapped in) — specifically
// so a resize racing Close can never land on an already-closed or
// already-reused handle. This test cannot, from this package, observe that
// protection directly; it proves this fix's stated minimum bar instead:
// concurrent Resize/Close neither deadlocks nor panics nor is flagged by the
// race detector, and the process still reaches a confirmed terminal state
// promptly afterward.
func TestProcessConPTYResizeCloseRace(t *testing.T) {
	proc := startConPTYProcess(t, portableSleepCommand(5))

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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if _, err := proc.Wait(ctx); err != nil {
		t.Fatalf("Wait after concurrent Resize/Close did not return in time: %v", err)
	}
}

// TestConPTYPipeReadNormalizesBrokenPipeToEOF is a direct unit-level proof
// of the claim TestProcessConPTYOutputEOFNormalization's own doc comment
// makes: Go's os package auto-detects a pipe handle (via GetFileType inside
// os.NewFile) and normalizes ERROR_BROKEN_PIPE to io.EOF on Read once the
// peer end is gone, with NO code in this package doing that translation
// itself — unlike terminalMaster.Read's explicit syscall.EIO normalization
// on Unix (terminal_unix.go). It never allocates a pseudo console or spawns
// a process at all: a plain CreatePipe pair, with the write end closed,
// already reproduces the exact condition this claim is about.
func TestConPTYPipeReadNormalizesBrokenPipeToEOF(t *testing.T) {
	var readHandle, writeHandle windows.Handle
	if err := windows.CreatePipe(&readHandle, &writeHandle, nil, 0); err != nil {
		t.Fatalf("CreatePipe: %v", err)
	}
	reader := os.NewFile(uintptr(readHandle), "conpty-test-broken-pipe-read")
	t.Cleanup(func() { _ = reader.Close() })
	if err := windows.CloseHandle(writeHandle); err != nil {
		t.Fatalf("CloseHandle(write end): %v", err)
	}

	buf := make([]byte, 8)
	if _, err := reader.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("Read once the write end is gone = %v, want io.EOF", err)
	}
}

// TestConPTYTerminalWriteVEOFByteClosesInputIdempotently is a direct
// unit-level proof of conPTYTerminal.Write's own contract (terminal_
// windows.go, "The VEOF/EOF design decision"): an ordinary write is passed
// through unchanged and really reaches the peer; an exact one-byte veofByte
// write closes the retained input pipe write end instead of forwarding the
// byte as data, observably (the peer's own read reports io.EOF afterward);
// and repeating that exact write — or following it with a real Close() —
// is safe, never a double-close panic/error. It never allocates a pseudo
// console at all (console stays its zero value): this proves Write/Close's
// own pipe-handling logic directly, mirroring
// TestTerminalMasterReadNormalizesEIOToEOF's (process_pty_unix_test.go) own
// "exercise the mechanism itself, not only transitively" precedent.
func TestConPTYTerminalWriteVEOFByteClosesInputIdempotently(t *testing.T) {
	var inRead, inWrite, outRead, outWrite windows.Handle
	if err := windows.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		t.Fatalf("CreatePipe(input): %v", err)
	}
	if err := windows.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		_ = windows.CloseHandle(inRead)
		_ = windows.CloseHandle(inWrite)
		t.Fatalf("CreatePipe(output): %v", err)
	}
	inReader := os.NewFile(uintptr(inRead), "conpty-test-input-read")
	t.Cleanup(func() { _ = inReader.Close() })
	outWriter := os.NewFile(uintptr(outWrite), "conpty-test-output-write")
	t.Cleanup(func() { _ = outWriter.Close() })

	terminal := &conPTYTerminal{
		input:  os.NewFile(uintptr(inWrite), "conpty-test-input-write"),
		output: os.NewFile(uintptr(outRead), "conpty-test-output-read"),
	}
	t.Cleanup(func() { _ = terminal.Close() })

	if n, err := terminal.Write([]byte("hi")); err != nil || n != 2 {
		t.Fatalf("ordinary write = (%d, %v), want (2, nil)", n, err)
	}
	ordinary := make([]byte, 2)
	if _, err := io.ReadFull(inReader, ordinary); err != nil || string(ordinary) != "hi" {
		t.Fatalf("peer read of ordinary write = (%q, %v), want (\"hi\", nil)", ordinary, err)
	}

	n, err := terminal.Write([]byte{veofByte})
	if err != nil || n != 1 {
		t.Fatalf("first VEOF write = (%d, %v), want (1, nil)", n, err)
	}
	n, err = terminal.Write([]byte{veofByte})
	if err != nil || n != 1 {
		t.Fatalf("second VEOF write = (%d, %v), want (1, nil) — must be idempotent", n, err)
	}

	buf := make([]byte, 8)
	if _, err := inReader.Read(buf); !errors.Is(err, io.EOF) {
		t.Fatalf("peer read after VEOF = %v, want io.EOF (the write end should really be closed)", err)
	}
	if err := terminal.Close(); err != nil {
		t.Fatalf("Close after an earlier VEOF write = %v, want nil (input is already closed; Close must not double-close it)", err)
	}
}

// TestProcessTreeConPTYJobBeforeResume is this task's own containment proof,
// mirroring TestProcessTreeWindowsJobBeforeResume
// (process_tree_windows_test.go) exactly — including reusing that file's own
// jobMembershipPayloadCommand/"job-membership" TestProcessTreeHelper payload
// verbatim — but routed through processTree.openTerminal + start's ConPTY
// dispatch (process_tree_windows.go) instead of the plain cmd.Start() path,
// so it proves the IDENTICAL guarantee for THIS task's new code: the
// child's own observation of its Job membership, recorded at its own first
// instruction, is itself the proof that assignment happened before resume —
// not a same-process assertion on tree.assigned alone, which only proves
// this process believes it called Assign, not that the child could never
// have run first. A background drain of the pseudo console's output
// mirrors pumpPTYOutput's own necessity (process.go) — this payload writes
// almost nothing to stdout, but nothing else drains it in this white-box
// test, and an undrained pipe could otherwise block the child's own exit
// exactly like Task 21's confirmed PTY hang.
func TestProcessTreeConPTYJobBeforeResume(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "conpty-job-membership-marker")
	cmd := jobMembershipPayloadCommand(marker)

	tree, err := newProcessTree(cmd, processTreeOptions{Sandboxed: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tree.close()

	terminal, closeSlave, err := tree.openTerminal(cmd)
	if err != nil {
		t.Fatalf("openTerminal: %v", err)
	}
	defer func() { _ = terminal.Close() }()
	go func() { _, _ = io.Copy(io.Discard, terminal) }()

	if err := tree.start(cmd); err != nil {
		t.Fatalf("start: %v", err)
	}
	if err := closeSlave(); err != nil {
		t.Fatalf("closeSlave: %v", err)
	}
	if !tree.assigned {
		t.Fatal("start returned successfully without ever recording Job assignment")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("payload exited with an error: %v", err)
	}

	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read payload marker: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "true" {
		t.Fatalf("payload observed Job membership %q at its own first instruction (via ConPTY-backed startConPTY); want %q — assignment must precede resume", got, "true")
	}
}

// TestProcessTreeConPTYFailsClosedWithoutJob is a defensive, unit-level
// proof of startConPTY's own precondition check (process_tree_windows.go):
// a tree with no Job to assign to (tree.job == nil; *winjob.Job's own
// Handle() already reports 0 for a nil receiver) fails before ever calling
// CreateProcess — no process is created, suspended or otherwise, proved by
// cmd.Process staying nil (startConPTY only ever sets it, via
// os.FindProcess, after a real CreateProcess call has already succeeded).
// This never occurs in production (newProcessTree, above, always creates a
// real Job before any cmd is ever built): it exists to prove the
// precondition check's own logic directly, mirroring the same "unreachable
// in production, still worth a fail-closed proof" spirit
// TestProcessPTYAllocationFailure (process_pty_unix_test.go) already
// applies to a real openPTY failure. The command name itself is never
// looked up or launched — this path returns before ever reaching that —
// so an arbitrary, resolvable name is enough.
func TestProcessTreeConPTYFailsClosedWithoutJob(t *testing.T) {
	cmd := exec.Command("cmd.exe")

	tree := &processTree{cmd: cmd}
	terminal, closeSlave, err := tree.openTerminal(cmd)
	if err != nil {
		t.Fatalf("openTerminal: %v", err)
	}
	defer func() { _ = terminal.Close() }()
	defer func() { _ = closeSlave() }()

	if err := tree.start(cmd); err == nil {
		t.Fatal("expected start to fail closed with no Job to assign to")
	}
	if cmd.Process != nil {
		t.Fatal("start set cmd.Process despite having no Job to assign the new process to — a process was created before the precondition check")
	}
}
