//go:build !darwin

package exec

import (
	"os/exec"

	"github.com/looprig/sandbox/internal/enforce"
)

// attachSynchronousDescendantProof is darwin-only (process_tree_darwin.go):
// there the synchronous Seatbelt path borrows the best-effort descendant
// tracker so a setsid'd escapee is killed at teardown (review M10). Linux and
// Windows keep their existing synchronous teardown unchanged — Linux's
// kernel-exact proofs are a Supervised-spawn requirement, and a Windows Job
// already contains every descendant the restricted tier can create — so this
// is a no-op everywhere else.
func attachSynchronousDescendantProof(processTreeBoundary, *exec.Cmd, enforce.Backend) {}
