//go:build windows

package exec

import (
	"os/exec"

	winlaunch "github.com/looprig/sandbox/internal/windows"
)

// platformConfigureChildHandleList publishes an explicit
// PROC_THREAD_ATTRIBUTE_HANDLE_LIST for a generic executor spawn. The child
// shares only os/exec's child-side standard stream handles. In particular,
// path canonicalization handles, Jobs, tokens, journal/state objects, broker
// channels, and proxy objects are never added.
//
// The configurator replaces every *os.File standard stream with a
// least-access DUPLICATE the parent owns until the returned cleanup runs.
// Those duplicates are open write ends of the run's output pipes, so the
// cleanup must run as soon as Start returns (see releaseChildHandleList,
// handlelist.go), never at spawn release: release waits for the output
// drain, and the drain cannot observe EOF while this process still holds a
// write end.
func platformConfigureChildHandleList(cmd *exec.Cmd) (func(), error) {
	return winlaunch.ConfigureExplicitHandleList(cmd, nil)
}
