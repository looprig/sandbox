package exec

import "github.com/looprig/sandbox/internal/policy"

// processTreeOptions is an immutable copy of one execution snapshot's process
// containment inputs.
type processTreeOptions struct {
	Sandboxed bool
	Limits    policy.Limits
}
