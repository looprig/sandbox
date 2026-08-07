//go:build darwin || linux

package exec

// This file wires *processTree (process_tree_unix.go) to Process's
// processSignalTarget seam (process.go), closing the gap Task 12A left open:
// every Process constructed by the confined spawn path (PreparedProcess.
// startConfined) left Signal nil/unwired, so it failed closed with
// ErrProcessSignalUnsupported for a not-yet-terminal process. sendInterrupt/
// sendTerminate/sendKill deliver SIGINT/SIGTERM/SIGKILL to the SAME Unix
// process group tree.terminate (process_tree_unix.go) and cmd.Cancel already
// address — signalGroup is the one group-signal primitive every caller
// shares, rather than a second, independently-aimed mechanism.
//
// This is genuinely Unix-wide (darwin || linux), not Linux-specific: it makes
// Process.Signal real on Darwin too, exactly like on Linux. The Linux-only
// part of this microtask — Rung-1 PID-namespace / delegated-cgroup exact
// process-tree CONTAINMENT (the proof terminateAndWait relies on for a
// Supervised spawn) — lives separately in process_tree_linux.go /
// process_tree_darwin.go, since that half genuinely differs by platform:
// Linux selects and retains a real kernel-enforced mechanism
// (process_tree_linux.go), reporting LifetimeContainmentEnforced. Darwin has
// no such kernel primitive available to an unentitled process (NOTE_TRACK is
// ENOTSUP; Endpoint Security needs an Apple-granted entitlement), so its
// attachSupervisedProof (process_tree_darwin.go) instead attaches a
// best-effort prover — process-group SIGKILL-and-poll plus process-table-
// closure descendant tracking — to every real Seatbelt-confined Supervised
// spawn and reports LifetimeContainmentBestEffort, a deliberate, accepted
// downgrade (2026-08-06) rather than the earlier fail-closed rejection this
// package used to return via enforce.ErrLifetimeContainmentUnavailable. See
// docs/lifetime-containment.md.

import "syscall"

// sendInterrupt requests cooperative interruption by delivering SIGINT to
// this run's process group.
func (tree *processTree) sendInterrupt() error { return tree.signalGroup(syscall.SIGINT) }

// sendTerminate requests cooperative termination by delivering SIGTERM to
// this run's process group.
func (tree *processTree) sendTerminate() error { return tree.signalGroup(syscall.SIGTERM) }

// sendKill force-terminates immediately by delivering SIGKILL to this run's
// process group — the identical signal/target tree.terminate() (cmd.Cancel,
// terminateAndWait's own defensive kill) already uses.
func (tree *processTree) sendKill() error { return tree.signalGroup(syscall.SIGKILL) }

// attachSignaler wires a freshly constructed Process's Signal seam to tree
// when tree actually implements processSignalTarget (every *processTree does,
// via the three methods above). It is called once, right after the Process
// is constructed, by every confined Unix spawn path (PreparedProcess.
// startConfined); a Process built any other way (the unconfined spawnProcess
// free function, which builds no processTree; a future Windows/backend-owned
// path) is unaffected and keeps signaler nil, matching its pre-12B fail-closed
// default.
func attachSignaler(proc *Process, tree processTreeBoundary) {
	if proc == nil {
		return
	}
	if signaler, ok := tree.(processSignalTarget); ok {
		proc.signaler = signaler
	}
}
