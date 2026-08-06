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

	// ErrProcessTTYUnsupported reports a TTY-backed process request that
	// cannot be honored, for either of two independent reasons: (1) a
	// prepare-time, platform-wide reason — a platform/build with no real PTY
	// primitive wired at all (ttySupported is false — see terminal_other.go);
	// Unix (terminal_unix.go) and Windows (terminal_windows.go, ConPTY) both
	// admit ProcessOptions.TTY == true at PrepareProcess and spawn a real
	// terminal instead of returning this error — or (2) a Start-time,
	// backend-specific reason — PrepareProcess's ttySupported check cannot
	// know which of Start's two dispatch branches (startConfined vs
	// startBackendOwned, process.go) a given preparation will resolve to, so
	// a backend that compiles a Launch-carrying spec but has no terminal
	// wiring of its own (today: the Windows elevated/broker backend) rejects
	// a TTY request here instead, at Start (startBackendOwned's own
	// top-of-function guard) — never silently downgrading to a plain
	// pipe-backed Process. This never silently downgrades a TTY request to
	// pipes on any platform or backend.
	ErrProcessTTYUnsupported = errors.New("sandbox: process TTY mode is not yet supported")

	// ErrProcessConPTYUnavailable reports that this Windows host does not
	// export the CreatePseudoConsole API a ConPTY-backed TTY request needs
	// (Windows 10 1809+ / Windows Server 2019+ only). Unlike
	// ErrProcessTTYUnsupported — decided once, at compile time, from the
	// ttySupported constant, before any reservation is made (PrepareProcess)
	// — this is a runtime capability check specific to the actual host:
	// Windows generically supports ConPTY (ttySupported is true there), but
	// a specific old host may not, so this surfaces later, from Start, once
	// terminal_windows.go's openTerminal actually probes for the API. See
	// probeConPTYAvailable (terminal_windows.go) for the probe itself.
	// Named ErrProcessConPTYUnavailable, not ErrConPTYUnavailable, to match
	// this file's own ErrProcess* naming convention: it is raised through
	// the same Process/PreparedProcess surface as every other sentinel here.
	ErrProcessConPTYUnavailable = errors.New("sandbox: ConPTY (pseudo console) is not available on this host")

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
