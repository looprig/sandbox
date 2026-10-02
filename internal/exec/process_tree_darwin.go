//go:build darwin

package exec

import (
	"os/exec"
	"reflect"
	"syscall"

	"github.com/looprig/sandbox/internal/darwin"
	"github.com/looprig/sandbox/internal/enforce"
)

// darwinBackendType identifies the real, production Seatbelt-backed
// enforce.Backend darwin.NewBackend() returns (internal/darwin's
// seatbeltBackend is unexported, so a reflect.TypeOf comparison is the same
// idiom internal/platform's own darwin backend-selection test already uses
// across this package boundary — see platform_darwin_test.go).
var darwinBackendType = reflect.TypeOf(darwin.NewBackend())

// darwinBestEffortProof is the Darwin Supervised zeroProver: process-group
// SIGKILL-and-poll plus proc-table-closure descendant kills
// (descendantTracker, process_descendants_darwin.go). BEST-EFFORT by design:
// macOS has no kernel-enforced tree-teardown primitive available to an
// unentitled process (NOTE_TRACK is ENOTSUP; Endpoint Security needs an
// Apple-granted entitlement), and the project accepted the downgrade
// (2026-08-06) because Seatbelt access confinement is inherited by every
// descendant — a lifetime escapee is an orphaned but still-sandboxed
// process, not an access-control hole. The downgrade is reported per spawn:
// lifetimeContainment() answers LifetimeContainmentBestEffort, surfaced as
// Process.LifetimeContainment. See docs/lifetime-containment.md.
type darwinBestEffortProof struct {
	cmd     *exec.Cmd
	tracker *descendantTracker
}

func (p *darwinBestEffortProof) lifetimeContainment() LifetimeContainment {
	return LifetimeContainmentBestEffort
}

func (p *darwinBestEffortProof) armPID(pid int) error {
	if p == nil || p.tracker == nil {
		return nil
	}
	return p.tracker.arm(pid)
}

func (p *darwinBestEffortProof) terminateAndWait() (error, error) {
	if p == nil || p.cmd == nil || p.cmd.Process == nil {
		return nil, nil
	}
	pgid := p.cmd.Process.Pid
	if pgid <= 0 {
		return nil, nil
	}
	if p.tracker != nil {
		p.tracker.killAndAwaitZero(pgid)
		return nil, nil
	}
	// Tracker unavailable (construction failed in attachSupervisedProof):
	// plain group sweep.
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
	signalAndPollProcessGroupZero(pgid, func(sig syscall.Signal) error {
		err := syscall.Kill(-pgid, sig)
		if err == syscall.ESRCH {
			return nil
		}
		return err
	})
	return nil, nil
}

func (p *darwinBestEffortProof) close() {
	if p != nil && p.tracker != nil {
		p.tracker.close()
	}
}

// attachSynchronousDescendantProof gives a synchronous (RunCommand/RunArgv/
// RunCommandWithGrants) Seatbelt spawn the same best-effort prover a
// Supervised spawn gets. newProcessTree attaches a proof only to Supervised
// spawns because on Linux that proof is a kernel mechanism the synchronous
// path does not require; on darwin the prover is just the descendant tracker,
// and without it run's teardown is a bare process-group sweep that cannot
// see a descendant which left the group with setsid(2). Such an escapee then
// survives the run and, if it inherited stdout/stderr, holds the output pipe
// open after the group is gone (review M10). With the tracker armed, a
// sample that observed the escapee while its ppid/pgid link still existed
// makes it a member, and killAndAwaitZero kills it at teardown.
//
// It is still best-effort — a descendant that detaches between two samples
// and loses its link is missed — which is why run additionally bounds its
// output drain (waitOutputDrain). Scoping matches attachSupervisedProof: only
// a tree this package built (*processTree) for the real Seatbelt backend,
// never one that already carries a proof, never an Unconfined (null) or
// pinned test backend. A tracker that fails to construct leaves the tree
// exactly as it was, with its plain group sweep.
func attachSynchronousDescendantProof(tree processTreeBoundary, cmd *exec.Cmd, backend enforce.Backend) {
	unixTree, ok := tree.(*processTree)
	if !ok || unixTree == nil || unixTree.cmd != cmd || unixTree.proof != nil {
		return
	}
	if backend == nil || reflect.TypeOf(backend) != darwinBackendType {
		return
	}
	tracker, err := newDescendantTracker()
	if err != nil {
		return
	}
	unixTree.proof = &darwinBestEffortProof{cmd: cmd, tracker: tracker}
}

// attachSupervisedProof attaches Darwin's best-effort prover to every real
// Seatbelt-backed Supervised spawn. Scoping mirrors Linux: an Unconfined
// executor or a pinned test backend makes no Darwin containment claim, so it
// attaches nothing (and the spawn reports LifetimeContainmentUnspecified).
func attachSupervisedProof(cmd *exec.Cmd, options processTreeOptions) (zeroProver, error) {
	if options.Backend == nil || reflect.TypeOf(options.Backend) != darwinBackendType {
		return nil, nil
	}
	tracker, err := newDescendantTracker()
	if err != nil {
		// Tracker construction failing (fd exhaustion) degrades to the plain
		// group sweep rather than blocking the spawn: the tracker only ever
		// narrows the best-effort gap; it is not the containment itself.
		tracker = nil
	}
	return &darwinBestEffortProof{cmd: cmd, tracker: tracker}, nil
}
