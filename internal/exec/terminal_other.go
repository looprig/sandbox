//go:build !darwin && !linux

package exec

import "os/exec"

// This file is every non-Unix platform's (Windows and anything else, until a
// later phase wires ConPTY — Windows is explicitly out of Task 21's scope)
// counterpart to terminal_unix.go: it exists only so process.go, which has no
// build tag and must compile identically everywhere, has something to call.
// Neither function below is ever reachable in production: PrepareProcess
// checks ttySupported before startConfined's TTY branch is ever entered, so a
// TTY request on this platform is already rejected with
// ErrProcessTTYUnsupported long before either of these would run.

// ttySupported is false on every platform this file builds for. See
// terminal_unix.go's identical constant for the platforms where it is true.
const ttySupported = false

// prepareTerminalSysProcAttr is unreachable in production on this platform
// (see the file doc above); it exists only to satisfy process.go's call site.
func prepareTerminalSysProcAttr(*exec.Cmd) {}

// openProcessTerminal mirrors prepareTerminalSysProcAttr's unreachability:
// it defensively fails closed with the same sentinel a TTY request on this
// platform is already rejected with, rather than ever allocating anything.
func openProcessTerminal(*exec.Cmd) (processTerminal, func() error, error) {
	return nil, nil, ErrProcessTTYUnsupported
}
