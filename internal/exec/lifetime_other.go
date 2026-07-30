//go:build !darwin && !linux

package exec

// attachSignaler is the non-Unix stub counterpart to lifetime_unix.go: no
// real signal-delivery implementation is wired for Windows/other platforms by
// this microtask (Windows Job signal mapping is Task 12D's scope), so this is
// a no-op and every Process built through PreparedProcess.startConfined on
// these platforms keeps its pre-12B signaler == nil, matching Signal's
// existing fail-closed default (ErrProcessSignalUnsupported) exactly. This
// file exists only so process.go's unconditional attachSignaler call compiles
// on every platform.
func attachSignaler(proc *Process, tree processTreeBoundary) {}
