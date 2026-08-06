//go:build darwin || linux

package exec

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
)

// This file is Task 21's real Unix PTY implementation, extending Task 12b's
// pipe-backed confined-spawn machinery (startConfined, process.go) rather
// than duplicating it: prepareTerminalSysProcAttr/openProcessTerminal are the
// two seams startConfined's TTY branch (startConfinedTTY, process.go) calls,
// at the same two points the pipe branch calls its own SysProcAttr/pipe-
// wiring equivalents.
//
// It uses github.com/creack/pty's Open, never Start: Start would call
// cmd.Start itself, bypassing this package's own configure/processTree/
// lease.start ownership linearization — the enforcement ownership point
// every spawn in this package, pipe-backed or PTY-backed, already goes
// through.

// ttySupported reports that this platform's process package can spawn a real
// PTY-backed Process. terminal_other.go (every non-Unix platform, including
// Windows until a later phase wires ConPTY) sets this false, leaving
// PrepareProcess's original TTY fail-closed behavior exactly as it was
// before this file existed.
const ttySupported = true

// prepareTerminalSysProcAttr marks cmd for a TTY-backed spawn's session and
// controlling-terminal setup. Setsid creates a new session, making the child
// (soon to hold the PTY slave as fd 0/1/2 once openProcessTerminal attaches
// it, below) both session leader and process-group leader of a fresh group
// whose id equals its own pid — the exact pgid-equals-pid outcome
// newProcessTree's Setpgid+Pgid:0 branch (process_tree_unix.go) exists to
// produce for the pipe-backed case. POSIX forbids ALSO setpgid'ing a session
// leader (a session leader's own setpgid call fails EPERM unconditionally,
// confirmed empirically on this codebase's darwin target: `fork/exec:
// operation not permitted`), so newProcessTree must see Setsid already set
// here and skip its own Setpgid — this function's caller (startConfined,
// process.go) runs it strictly before e.processTree for exactly that reason.
// Setctty + Ctty: 0 makes fd 0 (the PTY slave, once attached below) this new
// session's controlling terminal; per syscall.SysProcAttr's own doc, Setctty
// is only meaningful once Setsid is also set, and Ctty is an index into the
// CHILD's files — 0 is correct here because openProcessTerminal attaches the
// identical slave file to cmd.Stdin (child fd 0), cmd.Stdout (fd 1), and
// cmd.Stderr (fd 2) alike.
//
// This never opens a PTY device: only openProcessTerminal does that, and
// only after e.processTree has already succeeded — see startConfinedTTY's
// own doc comment (process.go) for why that ordering is load-bearing on
// Darwin.
func prepareTerminalSysProcAttr(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid = true
	cmd.SysProcAttr.Setctty = true
	cmd.SysProcAttr.Ctty = 0
}

// openPTY is pty.Open, indirected so process_pty_unix_test.go can force an
// allocation failure deterministically without needing to actually exhaust a
// real host's PTY devices.
var openPTY = pty.Open

// openProcessTerminal allocates one PTY and attaches its slave half to cmd's
// Stdin, Stdout, AND Stderr alike (matching ordinary interactive-terminal
// shape, and matching Ctty: 0's assumption above that fd 0 is the slave). It
// is called by startConfinedTTY (process.go) only after e.processTree has
// already succeeded, so a platform/backend combination that cannot supervise
// the spawn (Darwin's Seatbelt fail-closed contract, process_tree_darwin.go)
// rejects before this function — and therefore before any PTY device or
// child process — is ever reached.
//
// The returned closeSlave drops only the PARENT's own reference to the
// slave; startConfinedTTY calls it right after cmd.Start succeeds (mirroring
// startConfined's identical outW/errW/inR closure for the pipe-backed path
// exactly — the child now holds its own inherited copy, so the parent's copy
// must go so the retained master can ever observe the child's exit as
// EOF/EIO). The returned processTerminal is the retained master, owned by
// the eventual Process for its whole lifetime and closed only via
// Process.Close.
func openProcessTerminal(cmd *exec.Cmd) (processTerminal, func() error, error) {
	master, slave, err := openPTY()
	if err != nil {
		return nil, nil, err
	}
	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	return newTerminalMaster(master), slave.Close, nil
}

// terminalMaster wraps a PTY master file descriptor as the single retained
// processTerminal a PTY-backed Process's output-draining pump reads
// (pumpPTYOutput, process.go), terminalStdin writes (terminal.go), and
// Process.Resize/Process.Close resize and hang up through — a PTY
// multiplexes both directions and window-size control over its one master
// descriptor, unlike the pipe-backed path's three independent os.Pipe pairs.
// Process.Stdout() itself no longer reads this directly: it returns the
// pump's own pipe read end instead, so the master is drained continuously
// regardless of whether/when a caller ever reads Stdout (see newPTYProcess's
// doc comment for why that is load-bearing on Darwin).
//
// Read normalizes syscall.EIO to io.EOF: once every slave-side reference is
// gone (the child exited, and this package's own parent-side copy was
// already dropped right after Start — see openProcessTerminal's doc above),
// a Linux master read returns EIO rather than a clean 0-byte read (Darwin
// already returns a clean EOF for the identical condition). This keeps
// terminalMaster's own Read contract platform-uniform (io.EOF, never a raw
// platform errno) as a guarantee of this type itself — NOT because it is
// load-bearing for today's one production caller: pumpPTYOutput's loop
// (process.go) already returns, and closes its pipe, on ANY read error,
// normalized or not, so Process.Stdout's own readers would see a plain
// io.EOF from the pump either way. TestTerminalMasterReadNormalizesEIOToEOF
// (process_pty_unix_test.go) exercises this directly against Read itself,
// not only transitively through Stdout().
//
// Close is idempotent via closeOnce: Process.Close's own terminalCloser.Close()
// call is the only path that ever reaches it in production (Stdin().Close()
// writes the in-band VEOF byte instead, via terminalStdin, and never calls
// this; Stdout().Close() closes only the pump's pipe read end) — idempotency
// is kept regardless, since a test or a future caller could still reach this
// value more than once.
type terminalMaster struct {
	f *os.File

	closeOnce sync.Once
	closeErr  error
}

func newTerminalMaster(f *os.File) *terminalMaster { return &terminalMaster{f: f} }

func (m *terminalMaster) Read(p []byte) (int, error) {
	n, err := m.f.Read(p)
	if err != nil && errors.Is(err, syscall.EIO) {
		err = io.EOF
	}
	return n, err
}

func (m *terminalMaster) Write(p []byte) (int, error) { return m.f.Write(p) }

func (m *terminalMaster) Close() error {
	m.closeOnce.Do(func() { m.closeErr = m.f.Close() })
	return m.closeErr
}

// resize changes the PTY's window size via TIOCSWINSZ on the master. X/Y
// (pixel dimensions) are deliberately left zero: nothing in this package's
// contract (ProcessOptions, Process.Resize) carries pixel geometry, and a
// zero X/Y is the same "unknown" value most terminal emulators already send.
//
// This deliberately does NOT call github.com/creack/pty's own Setsize:
// Setsize issues its ioctl against m.f.Fd() directly, and Fd() itself warns
// that "if the file descriptor is used incorrectly, subsequent behavior is
// undefined" — it forfeits the safe-concurrent-close protection
// (internal/poll's reference-counted FD) that already makes Read, Write,
// and Close on m.f safe against each other, so a resize (e.g. forwarding a
// SIGWINCH) racing Process.Close's master teardown would be a raw ioctl on
// a file descriptor that could already be closed, or worse, already reused
// by an unrelated concurrent open elsewhere in this process. Going through
// (*os.File).SyscallConn().Control instead reuses that exact protection: per
// syscall.RawConn's own doc, the fd Control's callback receives "is
// guaranteed to remain valid while f executes", and Control itself returns
// an error instead of ever invoking the callback once m.f is closed.
// TestProcessPTYResizeCloseRace (process_pty_unix_test.go) exercises Resize
// concurrently with Close under -race as this fix's minimum bar.
func (m *terminalMaster) resize(rows, cols uint16) error {
	conn, err := m.f.SyscallConn()
	if err != nil {
		return err
	}
	ws := &pty.Winsize{Rows: rows, Cols: cols}
	var ctlErr error
	if err := conn.Control(func(fd uintptr) {
		ctlErr = ioctlSetWinsize(fd, ws)
	}); err != nil {
		return err
	}
	return ctlErr
}

// ioctlSetWinsize issues the raw TIOCSWINSZ ioctl against fd directly. It
// exists only so terminalMaster.resize (above) can drive the ioctl from
// inside a syscall.RawConn.Control callback — which hands this function a
// bare fd, not an *os.File — instead of going through
// github.com/creack/pty's own Setsize (see resize's doc comment for why).
// ws's field layout (Rows, Cols, X, Y uint16) is pty.Winsize's own exported
// type, so it is ABI-identical to this ioctl's expected struct winsize by
// construction; mirrors github.com/creack/pty's own ioctlInner exactly (same
// syscall, same "non-zero errno is the error" convention), which is
// otherwise unexported and unreachable from this package.
func ioctlSetWinsize(fd uintptr, ws *pty.Winsize) error {
	//nolint:gosec // Expected unsafe pointer for a TIOCSWINSZ ioctl syscall.
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, syscall.TIOCSWINSZ, uintptr(unsafe.Pointer(ws)))
	if errno != 0 {
		return errno
	}
	return nil
}
