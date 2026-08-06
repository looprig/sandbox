package exec

import (
	"errors"
	"io"
	"syscall"
)

// This file declares the platform-neutral PTY vocabulary Process/PrepareProcess
// (process.go) share across platforms: the stream-topology type a caller uses
// to tell a combined-terminal Process apart from a pipe-backed one, the resize
// seam Process.Resize drives (mirroring processSignalTarget's Signal seam
// exactly), and the synthetic empty Stderr a PTY-backed Process reports.
// terminal_unix.go backs all of this with a real github.com/creack/pty
// implementation on darwin and linux; terminal_other.go leaves every other
// platform's ErrProcessTTYUnsupported fail-closed behavior exactly as it was
// before this file existed — see both files' own doc comments.

// ProcessStreamMode describes a running Process's stream topology, mirroring
// Harness's tool.ProcessStreamMode vocabulary structurally (see process.go's
// own doc comment on why this package defines its own stdlib-only types
// rather than importing Harness's).
type ProcessStreamMode uint8

const (
	// ProcessStreamModePipes exposes distinct non-nil Stdout and Stderr pipe
	// readers. Every Process this package constructed before PTY support
	// existed, and every pipe-backed Process constructed since, is this mode.
	ProcessStreamModePipes ProcessStreamMode = iota + 1
	// ProcessStreamModePTY exposes combined terminal bytes through Stdout;
	// Stderr stays non-nil but is already closed and permanently empty (see
	// closedEmptyReadCloser). A PTY-backed Process never silently falls back
	// to separate pipes for either stream.
	ProcessStreamModePTY
)

// Valid reports whether m is a recognized process stream mode.
func (m ProcessStreamMode) Valid() bool {
	return m >= ProcessStreamModePipes && m <= ProcessStreamModePTY
}

// processTerminalTarget is the narrow seam Process.Resize drives to actually
// change a PTY's window size — exactly like processSignalTarget (process.go)
// is the seam Process.Signal drives to deliver a real OS signal. Only a
// PTY-backed Process (newPTYProcess, process.go) ever sets Process.resizer to
// a non-nil value; a pipe-backed Process leaves it nil and Resize fails
// closed with ErrProcessResizeUnsupported.
type processTerminalTarget interface {
	// resize changes the terminal's window size. rows/cols follow
	// github.com/creack/pty's Winsize field order (Rows then Cols), matching
	// `stty size`'s own "rows columns" output order.
	resize(rows, cols uint16) error
}

// processTerminal is one platform's real interactive-terminal implementation
// backing a PTY-backed Process: a single combined, EOF-normalized read+write
// endpoint — a PTY multiplexes both directions over its one master
// descriptor, unlike the pipe-backed path's three independent
// stdout/stderr/stdin pipes — plus resize. Only two things ever touch it
// directly: the output-draining pump (pumpPTYOutput, process.go), which is
// Process.Stdout's real reader so the master is always drained regardless of
// whether/when a caller reads Stdout, and terminalStdin (below), which is
// Process.Stdin's real writer. Process itself retains it a third way, as
// terminalCloser, so Process.Close can still hang it up for real.
// terminal_unix.go backs this with github.com/creack/pty on darwin and
// linux; terminal_other.go never constructs one at all — see its own doc
// comment for why that is safe.
type processTerminal interface {
	io.ReadWriteCloser
	processTerminalTarget
}

// closedEmptyReadCloser is the synthetic, permanently-empty, already-closed
// reader a PTY-backed Process reports from Stderr(): ProcessStreamModePTY
// combines stdout/stderr into Stdout's one stream, so there is no second
// stream to expose, but Stderr must stay non-nil — never silently
// reinterpreted by a caller as "this Process has no stderr at all" — and its
// Close must be a harmless no-op, so Process.Close's unconditional
// p.stderr.Close() call never reports a spurious error for a PTY-backed
// Process.
type closedEmptyReadCloser struct{}

func (closedEmptyReadCloser) Read([]byte) (int, error) { return 0, io.EOF }
func (closedEmptyReadCloser) Close() error             { return nil }

// veofByte is the ASCII EOT control character (Ctrl-D) — a Unix PTY line
// discipline's default VEOF value in canonical mode. Writing it to a
// terminal's master delivers EOF to the child's own read call without
// tearing down the terminal itself; see terminalStdin, below.
const veofByte byte = 0x04

// terminalStdin adapts a processTerminal (the one master endpoint a PTY-
// backed Process's Stdin and Stdout both ride) to the io.WriteCloser
// newProcessStdin (process.go) wraps, overriding what Close does: on a PTY,
// "the caller is done writing" must be delivered IN-BAND — the VEOF control
// byte written to the master — never by actually closing the master. A real
// master close is a genuine hangup (SIGHUP delivered to the terminal's whole
// foreground process group, plus losing whatever output is still buffered
// there) and stays exclusively Process.Close's job, via terminalCloser
// (process.go) — Stdin().Close() must never reach it. newProcessStdin's own
// mutex/closed guard already makes the eventual Close idempotent, so this
// type only needs to implement the one-shot VEOF write, not its own guard.
type terminalStdin struct {
	terminal processTerminal
}

func newTerminalStdin(terminal processTerminal) *terminalStdin {
	return &terminalStdin{terminal: terminal}
}

func (s *terminalStdin) Write(p []byte) (int, error) { return s.terminal.Write(p) }

// Close writes the VEOF byte and normalizes syscall.EIO to nil — extending
// the identical EIO-normalization precedent terminalMaster.Read already
// applies on the read side (terminal_unix.go). On the well-behaved,
// by-far-most-common sequence (the child already ran to completion and this
// package's own parent-side slave reference was already dropped — see
// openProcessTerminal's doc, terminal_unix.go), the master's slave side is
// already gone by the time a caller gets around to Close()ing Stdin, and a
// write in that state fails with EIO: there is nothing left to signal EOF
// to, so that failure is not a real error from this call's point of view,
// and must not surface as Process.Close's returned error the way the
// pipe-backed path never errors on closing your own pipe end regardless of
// the peer's state. Every other write failure (a real device error, say)
// still propagates.
func (s *terminalStdin) Close() error {
	_, err := s.terminal.Write([]byte{veofByte})
	if errors.Is(err, syscall.EIO) {
		return nil
	}
	return err
}
