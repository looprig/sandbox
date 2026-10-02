//go:build !windows

package exec

import "os/exec"

// applyShellCommandLine is a no-op off Windows: execve(2) receives argv as
// an array, so there is no command-line encoding for a shell to disagree
// with.
func applyShellCommandLine(*exec.Cmd) {}
