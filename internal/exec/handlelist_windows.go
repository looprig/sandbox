//go:build windows

package exec

import (
	"os/exec"

	winlaunch "github.com/looprig/sandbox/internal/windows"
)

func configureChildHandleList(cmd *exec.Cmd) (func(), error) {
	// Generic executor spawns share only os/exec's child-side standard stream
	// handles. In particular, path canonicalization handles, Jobs, tokens,
	// journal/state objects, broker channels, and proxy objects are never added.
	return winlaunch.ConfigureExplicitHandleList(cmd, nil)
}
