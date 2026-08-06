package exec

import "errors"

// Process/PreparedProcess sentinels. Each is the single value raised anywhere
// this pipe-backed API rejects a call, so errors.Is answers the same
// regardless of which method refused. They join the executor-level and
// grant-level sentinels already declared in executor_set.go and grant.go;
// keeping them in their own file mirrors how this microtask's public types
// live in their own process.go rather than growing executor.go.
var (
	// ErrProcessClosed reports that a PreparedProcess or Process was already
	// closed and no further preparation, start, or stream operation may
	// proceed through it.
	ErrProcessClosed = errors.New("sandbox: process closed")

	// ErrProcessAlreadyStarted reports that a PreparedProcess's single-use
	// Start was already consumed by an earlier call.
	ErrProcessAlreadyStarted = errors.New("sandbox: process already started")

	// ErrProcessTTYUnsupported reports a prepare request for a TTY-backed
	// process on a platform/build with no real PTY primitive wired at all
	// (ttySupported is false — see terminal_other.go). Unix (terminal_unix.go)
	// and Windows (terminal_windows.go, ConPTY) both admit
	// ProcessOptions.TTY == true and spawn a real terminal instead of
	// returning this error. This never silently downgrades a TTY request to
	// pipes on any platform.
	ErrProcessTTYUnsupported = errors.New("sandbox: process TTY mode is not yet supported")

	// ErrConPTYUnavailable reports that this Windows host does not export the
	// CreatePseudoConsole API a ConPTY-backed TTY request needs (Windows 10
	// 1809+ / Windows Server 2019+ only). Unlike ErrProcessTTYUnsupported —
	// decided once, at compile time, from the ttySupported constant, before
	// any reservation is made (PrepareProcess) — this is a runtime capability
	// check specific to the actual host: Windows generically supports ConPTY
	// (ttySupported is true there), but a specific old host may not, so this
	// surfaces later, from Start, once terminal_windows.go's openTerminal
	// actually probes for the API. See probeConPTYAvailable
	// (terminal_windows.go) for the probe itself.
	ErrConPTYUnavailable = errors.New("sandbox: ConPTY (pseudo console) is not available on this host")

	// ErrProcessStdinClosed reports a write attempted after the process's
	// stdin was closed (explicitly or by a prior EOF).
	ErrProcessStdinClosed = errors.New("sandbox: process stdin closed")

	// ErrProcessSignalUnsupported reports that a not-yet-terminal Process has
	// no real signal-delivery implementation wired in yet (see
	// processSignalTarget in process.go): Signal fails closed with this
	// error rather than silently succeeding. A later microtask (the Unix
	// lifetime shim, the Windows Job signal mapping) wires production
	// Process values to a real implementation; a Process already confirmed
	// terminal never reaches this error regardless.
	ErrProcessSignalUnsupported = errors.New("sandbox: process signal delivery is not yet supported")

	// ErrProcessResizeUnsupported reports that a not-yet-terminal Process has
	// no terminal-resize implementation wired (see processTerminalTarget,
	// terminal.go): a pipe-mode Process, or a TTY request this platform
	// cannot yet honor at all (PrepareProcess already fails those closed
	// with ErrProcessTTYUnsupported before a Process ever exists, so this
	// sentinel is unreachable through that path). Mirrors
	// ErrProcessSignalUnsupported's fail-closed contract exactly.
	ErrProcessResizeUnsupported = errors.New("sandbox: process resize is not yet supported")
)
