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
// terminalStdin.Close() (terminal.go, shared, unmodified by this task) is
// fixed: it writes exactly one byte, veofByte (0x04, ASCII EOT/Ctrl-D), to
// the terminal, then normalizes syscall.EIO to nil. On Unix this works
// because a PTY's line discipline, in canonical mode, recognizes 0x04 as its
// configured VEOF character and delivers EOF to the child's own read call —
// a KERNEL-level mechanism this codebase's Go code never has to implement
// itself; terminalMaster.Write (terminal_unix.go) just forwards the byte.
//
// Windows has no equivalent. A ConPTY-attached child's console input has no
// POSIX-style line discipline with a configurable EOF character at all: a
// literal 0x04 byte written into the pseudo console's input pipe is just
// ordinary input data to whatever reads it (unlike Ctrl-Z, which only some
// programs treat as EOF, and only as a C-runtime TEXT-MODE-FILE convention —
// not a universal, kernel-guaranteed signal any child can rely on the way
// Unix's VEOF is). The one mechanism ConPTY documents as the actual, correct,
// universal "no more input will ever arrive" signal — and the one that,
// exactly like Unix's VEOF, does NOT tear down the pseudo console or the
// child itself — is closing the parent's own retained write end of the
// pseudo console's input pipe.
//
// Given that, and given terminal.go's shared terminalStdin.Close() cannot be
// changed for this task (it is Unix-reviewed, unmodified, and shared), this
// file's conPTYTerminal.Write special-cases the EXACT one-byte payload
// terminalStdin.Close() sends: instead of writing 0x04 as data, it closes the
// retained input pipe write end, once, idempotently, and reports success.
// Any other write — including a longer buffer that happens to CONTAIN a 0x04
// byte somewhere inside it, which on Unix would ALSO be interpreted by the
// kernel line discipline as VEOF, transparently, regardless of caller intent
// — is passed straight through unchanged; only an exact single-byte 0x04
// write is intercepted, because that is the exact, and only, wire shape
// terminalStdin.Close() itself ever produces. A caller that calls
// Stdin().Write([]byte{0x04}) directly (bypassing Close) triggers the
// identical EOF delivery — this is not a Windows-specific ambiguity Close()
// introduces: it is the same inherent behavior Unix's own VEOF byte already
// has (that is precisely what "press Ctrl-D to end input" means to a Unix
// user), just performed by this package's own Go code instead of
// transparently by the kernel. See conPTYTerminal.Write's own doc comment.
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

	closeInputOnce sync.Once
	closeOnce      sync.Once
	closeErr       error
}

// Read drains the pseudo console's output pipe. Go's os package already
// normalizes ERROR_BROKEN_PIPE to io.EOF for a pipe-kind *os.File
// (internal/poll, kindPipe — detected automatically by os.NewFile via
// GetFileType), which is the Windows analogue of terminalMaster.Read's
// explicit syscall.EIO-to-io.EOF translation on Unix (Linux specifically):
// this type needs no equivalent explicit normalization of its own.
func (t *conPTYTerminal) Read(p []byte) (int, error) { return t.output.Read(p) }

// Write writes to the pseudo console's input pipe, with one exception: an
// exact one-byte write of veofByte (0x04) is translated into Windows' own
// EOF-delivery primitive — closing this terminal's retained input pipe write
// end — instead of being forwarded as literal data. See this file's own
// top-of-file doc comment ("The VEOF/EOF design decision") for the full
// reasoning. closeInputOnce makes repeated VEOF writes (or a VEOF write
// followed by Close) safe: closing an *os.File twice would otherwise return
// os.ErrClosed on the second attempt.
func (t *conPTYTerminal) Write(p []byte) (int, error) {
	if len(p) == 1 && p[0] == veofByte {
		t.closeInputOnce.Do(func() { _ = t.input.Close() })
		return 1, nil
	}
	return t.input.Write(p)
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
		t.closeInputOnce.Do(func() { _ = t.input.Close() })
		t.closeErr = t.output.Close()
	})
	return t.closeErr
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

// conPTYEnvBlock builds the double-NUL-terminated UTF-16 environment block
// CreateProcess requires when CREATE_UNICODE_ENVIRONMENT is set, mirroring
// syscall.createEnvBlock's own layout exactly (each entry UTF-16, NUL
// terminated; one further trailing NUL closes the block). Unlike that
// unexported stdlib helper, this does not sort entries: sorting is
// documented Windows convention for a system-provided environment block, not
// a CreateProcess requirement, and env here is already the exact same
// cmd.Env value the plain cmd.Start()-driven Windows path already passes
// through unsorted via syscall.StartProcess's own internal env handling —
// see that path's own createEnvBlock call, which DOES sort, meaning this is a
// deliberate, narrow behavioral difference from that path, noted here for a
// future reader: it has no observed effect on any target this package
// launches today, since duplicate-key environments are not something this
// package's own compiled backends produce.
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
