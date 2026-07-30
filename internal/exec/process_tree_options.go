package exec

import (
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
)

// processTreeOptions is an immutable copy of one execution snapshot's process
// containment inputs.
type processTreeOptions struct {
	Sandboxed bool
	Limits    policy.Limits
	// Supervised marks a spawn whose lifetime is asynchronously tracked by
	// this module's pipe-backed Process API (PreparedProcess.Start), as
	// opposed to the synchronous RunCommand/RunArgv path, which blocks for
	// the whole run and is unaffected by this field (SPEC Task 12b). Only a
	// Supervised spawn requires the mandatory Rung-1 PID-namespace or
	// delegated-cgroup exact containment proof on Linux; the synchronous
	// path keeps its existing process-group signal-and-poll behavior.
	Supervised bool
	// Backend is the compiled enforce.Backend this spawn's snapshot was
	// produced from. It is read only when Supervised is true, by a
	// platform-specific process-tree constructor that needs to know more
	// than Wrap's opaque configure/cleanup closures expose (e.g. the Linux
	// backend's selected Rung and its already-probed delegated cgroup v2
	// pids ancestor) to select an exact containment proof.
	Backend enforce.Backend
}
