//go:build windows

package exec

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// This file is Task 22B's real Windows ConPTY implementation, backing the
// same platform-neutral processTerminal/processTerminalTarget vocabulary
// (terminal.go) terminal_unix.go backs with github.com/creack/pty on
// darwin/linux. ttySupported is true here: PrepareProcess (process.go) now
// admits ProcessOptions.TTY == true on Windows and spawns a real pseudo
// console instead of failing closed with ErrProcessTTYUnsupported.
// terminal_other.go's build tag was narrowed to exclude windows specifically
// so it and this file never both try to define the same symbols for
// GOOS=windows.
//
// Unlike terminal_unix.go, this file does NOT define openProcessTerminal as
// the real terminal-opening seam: a ConPTY-backed launch cannot be built the
// same way — Go's os/exec has no extensibility point for attaching the
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE attribute CreateProcess needs (see
// process_tree_windows.go's own doc comment on processTree.openTerminal for
// the full explanation), so the real suspended-create has to happen inside
// processTree.start itself, composing with the SAME Job the tree already
// owns — never a second, unconfined path. openProcessTerminal below exists
// only to satisfy openConfinedTerminal's (process.go) static fallback
// reference on this platform; it is never reached in production, because
// *processTree (process_tree_windows.go) always implements
// processTreeTerminalOpener, and openConfinedTerminal prefers that whenever
// it is available.
//
// ## The VEOF/EOF design decision
//
// terminalStdin.Close() (terminal.go, shared) is fixed: it writes exactly one
// byte, veofByte (0x04, ASCII EOT/Ctrl-D), to the terminal, then normalizes
// syscall.EIO to nil. On Unix this works because a PTY's line discipline, in
// canonical mode, recognizes 0x04 as its configured VEOF character and
// delivers EOF to the child's own read call — a KERNEL-level mechanism this
// codebase's Go code never has to implement itself; terminalMaster.Write
// (terminal_unix.go) just forwards the byte.
//
// A Windows console has no configurable VEOF, and 0x04 is ordinary input to
// it. Its end-of-input convention is Ctrl-Z (0x1A) as the FIRST character of
// a cooked (ENABLE_LINE_INPUT) line, submitted with Enter: the console host
// completes the line, and a ReadFile on console input — the read every
// console program that treats stdin as a stream makes, findstr, sort, more,
// the C runtime's _read — reports ZERO bytes for a line that begins with
// Ctrl-Z (the console's ReadConsole message carries ProcessControlZ for a
// ReadFile-originated read). That is what "type Ctrl-Z, then Enter" ends
// input with at an interactive Windows console, and it is what this file
// sends: conPTYTerminal.Write translates the EXACT one-byte veofByte write
// into conPTYEOFSequence ("\x1a\r") on the pseudo console's input pipe.
//
// It deliberately does NOT close the input pipe. An earlier version did,
// reasoning that a closed input pipe is ConPTY's "no more input" signal like
// a closed pipe is for a pipe-backed child. It is not: the console host
// treats a broken input pipe as its terminal having gone away and shuts the
// session down — it sends CTRL_CLOSE_EVENT to every attached client, whose
// default handler exits with STATUS_CONTROL_C_EXIT (0xC000013A). That was the
// second Windows CI run exactly: every test that ended input through VEOF
// (Interactive, Input, EOF, CtrlD) saw 0xC000013A, while the two that never
// sent VEOF (CombinedOutput, Resize) exited 0 through the very same
// pseudo-console teardown path.
//
// The translation keeps Unix's VEOF semantics where they matter. VEOF at the
// start of a line is EOF for the next read; VEOF after a partial line does
// not end input on Unix either (it only flushes the partial line), and here
// the Ctrl-Z simply becomes part of that line. One Windows-specific case is
// handled: a console line ends with Enter, CR, and a Unix-style LF (alone or
// after CR) is a Ctrl-J key to the console host, which may stay in its line
// buffer as content and so occupy the start of the next line. When the last
// byte this terminal forwarded was LF, VEOF is therefore preceded by one CR
// (conPTYEOFAfterLFSequence): that submits whatever the LF left behind as a
// line of its own (at worst one extra empty line) so that the Ctrl-Z is
// first on a fresh line and EOF is delivered either way. Because nothing is closed,
// VEOF is repeatable and later writes still reach the child, exactly as on
// Unix. A raw-mode client (no ENABLE_LINE_INPUT) sees the two bytes as
// ordinary key input, which is what a real Windows terminal would deliver
// it. Only an exact single-byte 0x04 write is translated — the exact, and
// only, wire shape terminalStdin.Close() produces; a longer buffer that
// contains 0x04 passes through unchanged. A caller that writes
// Stdin().Write([]byte{0x04}) directly gets the identical EOF delivery, the
// same inherent behavior Unix's VEOF byte has ("press Ctrl-D to end input").
const conPTYCreatePseudoConsoleAPI = "CreatePseudoConsole"

// ttySupported is true on Windows: openConfinedTerminal (process.go) reaches
// processTree.openTerminal (process_tree_windows.go) for a real ConPTY-backed
// spawn instead of ever falling back to openProcessTerminal, below.
const ttySupported = true

// prepareTerminalSysProcAttr is a deliberate no-op on Windows. Unix's own
// version (terminal_unix.go) sets Setsid/Setctty to establish a new session
// and controlling terminal before the PTY slave is attached to cmd's
// stdio — syscall.SysProcAttr has no such fields on Windows at all, because a
// ConPTY-backed child never attaches via cmd.Stdin/Stdout/Stderr in the first
// place: it attaches through the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
// attribute processTree.start's ConPTY branch (process_tree_windows.go)
// builds directly. newProcessTree (process_tree_windows.go) already
// initializes cmd.SysProcAttr and sets CREATE_SUSPENDED |
// CREATE_NEW_PROCESS_GROUP unconditionally, for both the pipe-backed and
// ConPTY-backed cases alike, so there is nothing left for this function to do
// for a TTY-specific request.
func prepareTerminalSysProcAttr(*exec.Cmd) {}

// openProcessTerminal exists only to satisfy openConfinedTerminal's
// (process.go) static fallback reference on this platform; it is never
// reached in production, because *processTree
// (process_tree_windows.go) always implements processTreeTerminalOpener,
// and openConfinedTerminal always prefers that when available. See this
// file's own top-of-file doc comment for the full explanation of why the
// real ConPTY-opening logic lives on *processTree instead of here.
func openProcessTerminal(*exec.Cmd) (processTerminal, func() error, error) {
	return nil, nil, errors.New("sandbox: ConPTY terminal must be opened through its process tree")
}

// defaultConPTYSize is the initial pseudo-console geometry CreatePseudoConsole
// requires up front (it cannot be zero). ProcessOptions carries no initial
// width/height, exactly like the Unix PTY path (openProcessTerminal,
// terminal_unix.go, also allocates with no initial size request) — a caller
// that cares about real dimensions is expected to call Process.Resize
// immediately after Start, exactly as it already must on Unix.
var defaultConPTYSize = windows.Coord{X: 80, Y: 24}

// conPTYCreatePseudoConsoleProc is a SEPARATE, independently-constructed
// LazyProc for the exact same kernel32.dll export
// golang.org/x/sys/windows.CreatePseudoConsole itself resolves internally
// (via its own unexported procCreatePseudoConsole LazyProc). It exists only
// so probeConPTYAvailable can call Find — which returns an error — instead of
// Call/Addr, which PANIC if the named export cannot be located (LazyProc's
// own documented behavior). Calling x/sys/windows's real wrapper directly on
// a pre-1809 Windows host that lacks this export would crash this process
// instead of failing closed; probing this independent LazyProc first avoids
// that without depending on any unexported state in x/sys/windows.
var conPTYCreatePseudoConsoleProc = windows.NewLazySystemDLL("kernel32.dll").NewProc(conPTYCreatePseudoConsoleAPI)

// probeConPTYAvailable is conPTYProbe's production implementation.
func probeConPTYAvailable() error {
	if err := conPTYCreatePseudoConsoleProc.Find(); err != nil {
		return fmt.Errorf("%w: %v", ErrProcessConPTYUnavailable, err)
	}
	return nil
}

// conPTYProbe is indirected so process_conpty_windows_test.go can force the
// unavailable path deterministically, without needing an actual pre-1809
// Windows host — mirrors openPTY's identical indirection (terminal_unix.go).
var conPTYProbe = probeConPTYAvailable

// errConPTYClosed is returned by conPTYTerminal.resize once the pseudo
// console has already been closed (Process.Close's terminalCloser, or a
// concurrent teardown), mirroring terminalMaster.resize's own behavior on a
// closed master: a resize racing Close reports a real error rather than
// silently succeeding — Process.Resize itself already returns a harmless nil
// for a CONFIRMED terminal process (see its own confirmedTerminal check,
// process.go), so this is only ever observed for a genuine close/resize
// race, exactly like TestProcessPTYResizeCloseRace exercises on Unix.
var errConPTYClosed = errors.New("sandbox: ConPTY already closed")

// conPTYTerminal is this platform's real processTerminal implementation,
// backing a ConPTY-attached Process exactly like terminalMaster
// (terminal_unix.go) backs a real Unix PTY: a combined-terminal endpoint the
// output-draining pump (pumpPTYOutput, process.go) reads and terminalStdin
// (terminal.go) writes, plus resize. Unlike a Unix PTY's single master
// descriptor, ConPTY's I/O is two independent pipes — input, output — plus a
// separate pseudo-console handle for resize/teardown; this type owns all
// three for the Process's whole lifetime.
//
// console is guarded by mu so Close and resize can never race each other
// into a use-after-close: BOTH methods hold mu for the full duration of
// their own real syscall (ClosePseudoConsole/ResizePseudoConsole), not just
// while reading or zeroing the field — mirroring
// internal/windows/job_windows.go's Job.Assign/Job.Terminate literally,
// which hold job.mu via a defer spanning their own real syscalls. (Job.Close
// itself instead zeroes job.handle under the lock and calls CloseHandle
// after releasing it — safe there only because Job.Assign/Job.Terminate are
// what actually hold the lock through their syscalls; this type does not
// have that asymmetry available, since resize is the only "live operation on
// a handle that might already be closing" method here, so both it and Close
// hold the lock through their own syscalls, matching Assign/Terminate's
// shape rather than Close's.) console, like a Job handle, is a bare
// windows.Handle never wrapped in an *os.File and therefore never gets
// *os.File's own internal/poll concurrent-close protection for free.
// input/output ARE
// *os.File-wrapped (via os.NewFile over a real pipe handle, which Go's
// os package auto-detects as FILE_TYPE_PIPE and therefore already normalizes
// ERROR_BROKEN_PIPE to io.EOF on Read — see this type's Read doc — so they
// need no equivalent explicit locking: *os.File already makes concurrent
// Read/Write/Close safe against each other on its own).
type conPTYTerminal struct {
	mu      sync.Mutex
	console windows.Handle

	input  *os.File // ConsoleInputWrite: retained; terminalStdin's write target.
	output *os.File // ConsoleOutputRead: retained; pumpPTYOutput's read source.

	// inputMu guards lastInput, the last byte the input pipe accepted, which
	// Write consults to translate VEOF (see Write).
	inputMu   sync.Mutex
	lastInput byte

	closeOnce sync.Once
	closeErr  error
}

// Read drains the pseudo console's output pipe. Go's os package already
// normalizes ERROR_BROKEN_PIPE to io.EOF for a pipe-kind *os.File
// (internal/poll, kindPipe — detected automatically by os.NewFile via
// GetFileType), which is the Windows analogue of terminalMaster.Read's
// explicit syscall.EIO-to-io.EOF translation on Unix (Linux specifically):
// this type needs no equivalent explicit normalization of its own.
func (t *conPTYTerminal) Read(p []byte) (int, error) { return t.output.Read(p) }

// conPTYEOFSequence is what a veofByte write becomes on a pseudo console:
// Ctrl-Z then Enter (CR, which the console host's VT input turns into an
// Enter key event). conPTYEOFAfterLFSequence is the same preceded by one
// Enter, used when the last forwarded byte was LF. See this file's "VEOF/EOF
// design decision".
const (
	conPTYEOFSequence        = "\x1a\r"
	conPTYEOFAfterLFSequence = "\r\x1a\r"
)

// Write writes to the pseudo console's input pipe, with one exception: an
// exact one-byte write of veofByte (0x04) is translated into the console's
// own end-of-input convention, conPTYEOFSequence, and reports the caller's
// one byte written. The input pipe is never closed here — closing it hangs
// the whole pseudo console up (see this file's "VEOF/EOF design decision");
// only Close does that, after the child is gone or to tear it down.
//
// inputMu serializes writes so lastInput is exactly the last byte the pipe
// accepted; a concurrent Signal(Interrupt) ^C and a Stdin write would be
// serialized by the pipe (and *os.File) anyway.
func (t *conPTYTerminal) Write(p []byte) (int, error) {
	t.inputMu.Lock()
	defer t.inputMu.Unlock()
	if len(p) == 1 && p[0] == veofByte {
		sequence := conPTYEOFSequence
		if t.lastInput == '\n' {
			sequence = conPTYEOFAfterLFSequence
		}
		if n, err := t.input.Write([]byte(sequence)); err != nil {
			if n > 0 {
				t.lastInput = sequence[n-1]
			}
			return 0, err
		}
		t.lastInput = sequence[len(sequence)-1]
		return 1, nil
	}
	n, err := t.input.Write(p)
	if n > 0 {
		t.lastInput = p[n-1]
	}
	return n, err
}

// Close performs the genuine hangup Process.Close's terminalCloser seam
// requires (process.go): ClosePseudoConsole terminates any client process
// still attached to the pseudo console — Microsoft's own documented ConPTY
// teardown behavior — exactly mirroring Unix's real master Close delivering
// SIGHUP to the terminal's whole foreground process group. It then releases
// this type's own two retained pipe ends. Idempotent via closeOnce, exactly
// like terminalMaster.Close.
//
// t.mu is held for the ENTIRE ClosePseudoConsole call, not just the read/
// zero of t.console beforehand — mirroring internal/windows/job_windows.go's
// Job.Assign/Job.Terminate literally, which hold job.mu via a defer spanning
// their own real syscalls, not merely the read of job.handle. Releasing the
// lock before calling the real API (an earlier version of both this method
// and resize, below, did exactly that) is a genuine handle-lifetime race the
// Go race detector cannot see at all: a concurrent resize could still be
// mid-syscall against the SAME handle value this method has already decided
// to close, or could start its own syscall against a handle number the OS
// has, by then, already reused for something else entirely. Holding the lock
// through the syscall here (matched by resize also holding it through ITS
// OWN syscall) makes the two calls fully mutually exclusive for real,
// instead of merely mutually exclusive for the field read.
func (t *conPTYTerminal) Close() error {
	t.closeOnce.Do(func() {
		t.mu.Lock()
		if t.console != 0 {
			windows.ClosePseudoConsole(t.console)
			t.console = 0
		}
		t.mu.Unlock()
		t.closeErr = errors.Join(t.input.Close(), t.output.Close())
	})
	return t.closeErr
}

// hangupAfterExit implements terminalExitHangup (process.go): it closes the
// pseudo console once the spawn's whole Job has been proven empty, leaving
// the input and output pipe ends to Close.
//
// This is what lets Stdout reach EOF after the child exits. On Unix the
// master reports EOF/EIO when the last slave reference closes, which happens
// by itself when the child (the only slave holder once the parent dropped
// its copy at Start) exits. A pseudo console has no such moment: the console
// host (conhost.exe, created by CreatePseudoConsole in THIS process) holds
// the output pipe's write end for as long as the pseudo console exists, so
// the pump would block forever on a child that has long exited until
// something closes it. ClosePseudoConsole makes the host flush its final
// frame and exit, which closes that write end; the pump drains what remains
// and observes EOF (ERROR_BROKEN_PIPE, normalised to io.EOF).
//
// It runs from spawn cleanup, strictly after supervise's terminateAndWait
// confirmed no process remains in the Job, so it can never be the thing that
// kills a client: every process that could still be attached is already gone.
//
// t.console is zeroed under t.mu and the handle closed after releasing it.
// That is safe for exactly the reason Close/resize hold the lock through
// their syscalls — every user reads the field under the lock and uses it only
// while still holding it — and it matters here: on Windows releases before
// Windows 11 24H2, ClosePseudoConsole blocks until the host has written its
// final frame, which needs the output pipe drained. If nobody reads Stdout,
// that only ends when Process.Close closes the output read end, and Close
// takes t.mu first; holding the lock here would deadlock the two.
func (t *conPTYTerminal) hangupAfterExit() {
	t.mu.Lock()
	console := t.console
	t.console = 0
	t.mu.Unlock()
	if console != 0 {
		windows.ClosePseudoConsole(console)
	}
}

// resize changes the pseudo console's buffer/window size via
// ResizePseudoConsole. rows/cols follow processTerminalTarget's documented
// Rows-then-Cols order (terminal.go); ConPTY's own windows.Coord is
// (X=columns, Y=rows), so the two are swapped here.
//
// t.mu is held for the ENTIRE ResizePseudoConsole call via defer, not merely
// while reading t.console — mirroring internal/windows/job_windows.go's
// Job.Assign/Job.Terminate literally (see Close's own doc comment, above,
// for why releasing the lock before the actual syscall — this method's own
// earlier shape — is a real handle-lifetime race despite being invisible to
// the Go race detector, and why holding it through the syscall here, not
// *os.File's SyscallConn/Control the way terminal_unix.go's
// terminalMaster.resize does, is the right pattern: console is a bare
// windows.Handle, never wrapped in an *os.File, so it has none of that
// type's own concurrent-close protection for free).
func (t *conPTYTerminal) resize(rows, cols uint16) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.console == 0 {
		return errConPTYClosed
	}
	return windows.ResizePseudoConsole(t.console, windows.Coord{X: int16(cols), Y: int16(rows)})
}

// conPTYInterruptByte is the ASCII ETX / Ctrl-C control character. Writing
// it to a console's input stream — with that console's default
// ENABLE_PROCESSED_INPUT mode, which CreatePseudoConsole's fresh console
// buffer carries exactly like any newly created console does — makes the
// console HOST itself (conhost.exe/OpenConsole.exe, whichever process
// actually backs the pseudo console) translate it into a real CTRL_C_EVENT
// delivered to whatever is attached, exactly as if a real keyboard had sent
// it: this is ConPTY's own intended, documented interrupt-delivery
// mechanism (it is how real terminal emulators, e.g. Windows Terminal,
// deliver Ctrl+C to a ConPTY-hosted process). Never a control-character
// interception this package's own Go code performs itself, unlike
// veofByte's Write-layer special-casing above: this byte is forwarded to
// the pseudo console completely unchanged; the console HOST is what
// reinterprets it.
//
// This is NOT the same relationship Unix's own TestProcessPTYInterruptForegroundGroup
// (process_pty_unix_test.go) has to Process.Signal: on Unix, writing 0x03 to
// the terminal and calling Process.Signal(ProcessSignalInterrupt) are two
// INDEPENDENT paths to the same eventual SIGINT — the kernel's line
// discipline reacts to the byte on its own, entirely outside
// Process.Signal, which instead delivers SIGINT directly via a process-group
// kill (lifetime_unix.go's tree.sendInterrupt, signalGroup) and never
// touches the terminal at all. On Windows there is no such independent,
// terminal-free interrupt primitive available for a ConPTY-attached child
// (see conPTYSignaler's own doc comment for exactly why
// GenerateConsoleCtrlEvent cannot reach one) — conPTYSignaler deliberately
// ROUTES Process.Signal(ProcessSignalInterrupt) itself through this byte,
// because it is the ONLY working mechanism this platform offers for this
// process topology, not because it mirrors how Unix's Process.Signal
// happens to be wired.
const conPTYInterruptByte byte = 0x03

// conPTYSignaler adapts a ConPTY-backed Process's Signal seam (process.go,
// processSignalTarget) to the mechanism each request actually needs:
// sendInterrupt writes conPTYInterruptByte into the pseudo console's own
// input stream (see that constant's doc comment, including why this
// deliberately does NOT mirror how Unix's own Process.Signal is wired)
// rather than reusing *processTree's own sendInterrupt, which delivers
// CTRL_BREAK_EVENT via GenerateConsoleCtrlEvent — an API that only reaches a
// process group sharing the CALLING process's own console.
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE (processTree.startConPTY) deliberately
// attaches a ConPTY-backed child to the pseudo console INSTEAD of the
// caller's console, so that mechanism cannot reach it at all — the
// identical reasoning errElevatedRunnerInterruptUnsupported's own doc
// comment (internal/windows/elevated_runner_launcher_windows.go) already
// documents for the elevated/broker path, which has this exact same
// non-console-sharing property (there, with no ConPTY input stream
// available either, it fails closed instead; here, the input stream gives
// this path a real working primitive the broker path does not have).
//
// sendTerminate/sendKill still delegate to tree unchanged:
// TerminateJobObject/TerminateProcess do not depend on console sharing at
// all, so *processTree's own implementation (process_tree_windows.go) is
// already correct for a ConPTY-backed Process exactly as it is for a
// pipe-backed one — attachSignaler (process_tree_windows.go) wires this
// type in place of tree directly only for a ConPTY-backed Process,
// specifically to fix sendInterrupt; every other method it needs still
// comes from the SAME tree.
type conPTYSignaler struct {
	terminal *conPTYTerminal
	tree     processSignalTarget
}

func (s conPTYSignaler) sendInterrupt() error {
	_, err := s.terminal.Write([]byte{conPTYInterruptByte})
	return err
}

func (s conPTYSignaler) sendTerminate() error { return s.tree.sendTerminate() }

func (s conPTYSignaler) sendKill() error { return s.tree.sendKill() }

// conPTYApplicationPath resolves cmd's executable path for the raw
// CreateProcess call processTree.startConPTY (process_tree_windows.go)
// performs in place of cmd.Start(). cmd.Path is already what every other
// Windows spawn path in this package (the plain cmd.Start()-driven one) uses
// as-is; this only adds the same absolute-join-against-Dir adjustment
// exec.Cmd.Start's own internal syscall.StartProcess performs via
// joinExeDirAndFName immediately before its own CreateProcess call, so a
// relative cmd.Path resolves the same way it would have through that path.
// It is a deliberately simpler approximation of that stdlib-internal
// function (no UNC/drive-letter special-casing) rather than a byte-for-byte
// port: every argv0 this package's own compiled backends produce today is
// already absolute (canonicalWorkingDirectory, grant.go, already canonicalizes
// cmd.Dir itself), so this function's relative-path branch is defensive, not
// exercised in production.
func conPTYApplicationPath(cmd *exec.Cmd) (string, error) {
	if cmd.Path == "" {
		return "", errors.New("sandbox: ConPTY launch has no resolved executable path")
	}
	if filepath.IsAbs(cmd.Path) {
		return cmd.Path, nil
	}
	if cmd.Dir == "" {
		return filepath.Abs(cmd.Path)
	}
	return filepath.Abs(filepath.Join(cmd.Dir, cmd.Path))
}

// conPTYCommandLine builds the single escaped command-line string
// CreateProcess itself requires (unlike POSIX execve's argv array) from
// args (cmd.Args — arg0 followed by the rest), mirroring
// syscall.makeCmdLine's own algorithm exactly: escape each argument with
// windows.EscapeArg (the exported form of the identical escaping
// syscall.appendEscapeArg performs internally) and join with a single space.
func conPTYCommandLine(args []string) (string, error) {
	if len(args) == 0 {
		return "", errors.New("sandbox: ConPTY launch has an empty argument list")
	}
	escaped := make([]string, len(args))
	for i, arg := range args {
		escaped[i] = windows.EscapeArg(arg)
	}
	return strings.Join(escaped, " "), nil
}

// conPTYLaunchEnvBlock builds the CreateProcess environment block for a
// ConPTY launch of cmd. The plain cmd.Start() Windows path never hands cmd.Env
// to the OS verbatim: os/exec first applies dedupEnv (case-insensitive on
// Windows, the LAST spelling of a name winning) and addCriticalEnv (appending
// SYSTEMROOT from the parent when no spelling of it is present), because
// Winsock, CryptoAPI/CNG and many system DLLs fail to initialise in a process
// with no SystemRoot. The ConPTY path calls CreateProcess itself, so it must
// apply the same two steps or a scrubbed ConPTY child starts without
// SystemRoot. It does so through exec.Cmd.Environ, which is exactly that
// pipeline (cmd.environ: dedupEnv then addCriticalEnv; its cmd.Dir-based PWD
// rewrite is POSIX-only and only applies when Env is nil), on a throwaway Cmd
// carrying only the environment.
//
// Two deliberate departures from calling cmd.Environ() directly:
//
//   - A nil cmd.Env is treated as EMPTY, never as "inherit": Environ would
//     substitute the full parent environment for a nil Env, and every ConPTY
//     launch this package builds sets Env from assembleEnv, so a nil here is a
//     bug that must fail closed (an empty block plus SYSTEMROOT), not a
//     secret leak.
//   - An entry containing NUL is an error, as it always was here: Environ
//     silently drops such an entry (it ignores dedupEnv's error), and a
//     silently altered environment is not something a launch should paper
//     over.
func conPTYLaunchEnvBlock(cmd *exec.Cmd) ([]uint16, error) {
	env := cmd.Env
	if env == nil {
		env = []string{}
	}
	for _, entry := range env {
		if strings.IndexByte(entry, 0) >= 0 {
			return nil, errors.New("sandbox: invalid ConPTY launch environment entry: contains NUL")
		}
	}
	return conPTYEnvBlock((&exec.Cmd{Env: env}).Environ())
}

// conPTYEnvBlock builds the double-NUL-terminated UTF-16 environment block
// CreateProcess requires when CREATE_UNICODE_ENVIRONMENT is set, mirroring
// syscall.createEnvBlock's own layout exactly (each entry UTF-16, NUL
// terminated; one further trailing NUL closes the block). env must already be
// the launch environment as os/exec would compute it — conPTYLaunchEnvBlock
// produces that, deduplicated case-insensitively and carrying SYSTEMROOT — so
// this function only encodes. Unlike syscall.createEnvBlock it does not sort
// the entries: sorting is the documented convention for a system-provided
// block, not a CreateProcess requirement, and with duplicates already removed
// the order cannot change which value a name resolves to.
func conPTYEnvBlock(env []string) ([]uint16, error) {
	if len(env) == 0 {
		return []uint16{0, 0}, nil
	}
	block := make([]uint16, 0, len(env)*8)
	for _, entry := range env {
		encoded, err := windows.UTF16FromString(entry)
		if err != nil {
			return nil, fmt.Errorf("sandbox: invalid ConPTY launch environment entry: %w", err)
		}
		block = append(block, encoded...) // UTF16FromString already NUL-terminates.
	}
	block = append(block, 0) // Second NUL completes the block's required double-NUL terminator.
	return block, nil
}

// conPTYAttributeHandle reads pending's stored pseudo-console handle back out
// as a real windows.Handle, mirroring ConPTYAttribute's own documented
// reason for storing it as a platform-neutral uintptr (conpty_launch_plan.go)
// instead of a windows.Handle directly.
func conPTYAttributeHandle(attribute ConPTYAttribute) windows.Handle {
	return windows.Handle(attribute.PseudoConsoleHandle)
}

// closeConPTYHandles is a small defensive helper for openTerminal's
// (process_tree_windows.go) own multi-step cleanup-on-partial-failure paths:
// it closes every non-zero handle given and joins any resulting errors,
// mirroring the errors.Join(...) pattern startConfined/startConfinedTTY
// (process.go) already use for their own multi-descriptor cleanup.
func closeConPTYHandles(handles ...windows.Handle) error {
	var err error
	for _, h := range handles {
		if h != 0 {
			err = errors.Join(err, windows.CloseHandle(h))
		}
	}
	return err
}
