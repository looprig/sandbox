//go:build !darwin && !linux && !windows

package exec

// attachSignaler is the stub counterpart to lifetime_unix.go and
// process_tree_windows.go's own attachSignaler: no real signal-delivery
// implementation exists for a platform with no process-tree primitive at all
// (process_tree_other.go's processTree is a fail-closed
// enforce.ErrUnavailable stub), so this is a no-op and every Process built
// through PreparedProcess.startConfined on such a platform keeps its
// pre-12B signaler == nil, matching Signal's existing fail-closed default
// (ErrProcessSignalUnsupported) exactly. Windows is excluded from this
// build constraint as of Task 12D — process_tree_windows.go now defines the
// real Windows attachSignaler, so this file exists only so process.go's
// unconditional attachSignaler call still compiles on any remaining
// platform with neither a Unix nor a Windows process tree.
func attachSignaler(proc *Process, tree processTreeBoundary) {}
