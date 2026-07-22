package exec

import (
	"errors"
	"os/exec"
	"sync"
	"time"
)

const quarantineRetryInterval = 100 * time.Millisecond

// zeroProver owns the platform process boundary. A nil proof error is the only
// evidence that every process inside that boundary is gone. Termination errors
// are kept separate because a redundant/failed termination can coexist with a
// successful absence proof.
type zeroProver interface {
	terminateAndWait() (terminateErr, proofErr error)
	close()
}

type processTreeBoundary interface {
	zeroProver
	start(*exec.Cmd) error
}

type processTreeFactory func(*exec.Cmd, processTreeOptions) (processTreeBoundary, error)

// quarantineSink is the narrow ownership-transfer seam used by the executor.
// Tests inject a deterministic sink; production uses an asynchronous reaper.
type quarantineSink interface {
	quarantine(*quarantinedSpawn)
}

// quarantinedSpawn is the complete ownership capsule for one uncertain
// Windows spawn. Keeping cmd reachable is intentional: exec.Cmd and its pipes,
// the Job, per-spawn cleanup, transient spec/proxy releases, and the execution
// lease must all outlive a failed zero proof.
type quarantinedSpawn struct {
	prover  zeroProver
	cmd     *exec.Cmd
	lease   *executionLease
	observe func()

	releaseOnce    sync.Once
	transferOnce   sync.Once
	spawnCleanup   []func() error
	afterExecution []func() error
}

func newQuarantinedSpawn(prover zeroProver, cmd *exec.Cmd, lease *executionLease) *quarantinedSpawn {
	return &quarantinedSpawn{prover: prover, cmd: cmd, lease: lease}
}

func (spawn *quarantinedSpawn) transferTo(sink quarantineSink) {
	if spawn == nil || sink == nil {
		return
	}
	spawn.transferOnce.Do(func() { sink.quarantine(spawn) })
}

// reapOnce attempts termination and then an exact zero proof. Resources remain
// untouched on proof failure, even when termination also failed. Once proof is
// obtained, release is idempotent and the termination error remains visible.
func (spawn *quarantinedSpawn) reapOnce() (done bool, err error) {
	if spawn == nil || spawn.prover == nil {
		return true, nil
	}
	terminateErr, proofErr := spawn.prover.terminateAndWait()
	if proofErr != nil {
		return false, errors.Join(terminateErr, proofErr)
	}
	return true, spawn.release(false, true, terminateErr)
}

func (spawn *quarantinedSpawn) release(observe, recordDelayed bool, terminalErr error) error {
	if spawn == nil {
		return nil
	}
	releaseErr := terminalErr
	spawn.releaseOnce.Do(func() {
		if spawn.prover != nil {
			spawn.prover.close()
		}
		for _, release := range spawn.spawnCleanup {
			if release != nil {
				releaseErr = errors.Join(releaseErr, release())
			}
		}
		if spawn.lease != nil {
			spawn.lease.finishExecution()
		}
		if observe && spawn.observe != nil {
			spawn.observe()
		}
		for _, release := range spawn.afterExecution {
			if release != nil {
				releaseErr = errors.Join(releaseErr, release())
			}
		}
		if spawn.lease != nil && recordDelayed {
			spawn.lease.lifecycle.recordCleanupError(releaseErr)
		}
		if spawn.lease != nil {
			spawn.lease.finishCleanup()
		}
		spawn.cmd = nil
	})
	return releaseErr
}

type asyncQuarantineReaper struct {
	retryInterval time.Duration
}

func newAsyncQuarantineReaper() *asyncQuarantineReaper {
	return &asyncQuarantineReaper{retryInterval: quarantineRetryInterval}
}

func (reaper *asyncQuarantineReaper) quarantine(spawn *quarantinedSpawn) {
	if reaper == nil || spawn == nil {
		return
	}
	go func() {
		for {
			if done, _ := spawn.reapOnce(); done {
				return
			}
			time.Sleep(reaper.retryInterval)
		}
	}()
}
