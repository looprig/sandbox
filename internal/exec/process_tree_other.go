//go:build !darwin && !linux && !windows

package exec

import (
	"github.com/looprig/sandbox/internal/enforce"
)

import "os/exec"

// Unsupported platforms have no process-tree primitive with the required
// start/kill/wait guarantees. Reject before Start rather than claiming that
// killing only the immediate child revokes the run.
type processTree struct{}

func newProcessTree(*exec.Cmd) (*processTree, error) { return nil, enforce.ErrUnavailable }
func (*processTree) start(*exec.Cmd) error           { return enforce.ErrUnavailable }
func (*processTree) terminateAndWait() error         { return nil }
func (*processTree) close()                          {}
