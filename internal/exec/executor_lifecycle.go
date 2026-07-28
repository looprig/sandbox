package exec

import (
	"context"
	"errors"
	"os/exec"
	"sync"
)

// executorLifecycle is shared by every Executor owned by one ExecutorSet. Its
// mutex is the spawn/close linearization point: Start either completes before
// close begins, or observes closing and fails without spawning.
type executorLifecycle struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	active     sync.WaitGroup
	cleanup    sync.WaitGroup
	closed     bool
	errMu      sync.Mutex
	cleanupErr error
}

func newExecutorLifecycle() *executorLifecycle {
	ctx, cancel := context.WithCancel(context.Background())
	return &executorLifecycle{ctx: ctx, cancel: cancel}
}

type executionLease struct {
	lifecycle     *executorLifecycle
	caller        context.Context
	ctx           context.Context
	cancel        context.CancelFunc
	stopClose     func() bool
	executionOnce sync.Once
	cleanupOnce   sync.Once
}

func (e *Executor) beginExecution(caller context.Context) (*executionLease, error) {
	if e == nil || e.lifecycle == nil {
		return nil, ErrExecutorClosed
	}
	if caller == nil {
		caller = context.Background()
	}
	lifecycle := e.lifecycle
	lifecycle.mu.Lock()
	if lifecycle.closed {
		lifecycle.mu.Unlock()
		return nil, ErrExecutorClosed
	}
	lifecycle.active.Add(1)
	lifecycle.cleanup.Add(1)
	lifecycle.mu.Unlock()

	ctx, cancel := context.WithCancel(caller)
	lease := &executionLease{
		lifecycle: lifecycle,
		caller:    caller,
		ctx:       ctx,
		cancel:    cancel,
	}
	lease.stopClose = context.AfterFunc(lifecycle.ctx, cancel)
	return lease, nil
}

func (lease *executionLease) start(cmd *exec.Cmd, tree processTreeBoundary) error {
	if lease == nil || lease.lifecycle == nil {
		return ErrExecutorClosed
	}
	lifecycle := lease.lifecycle
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.closed {
		return ErrExecutorClosed
	}
	if err := lease.ctx.Err(); err != nil {
		return err
	}
	return tree.start(cmd)
}

// authorizeBackendStart is the launch linearization point for a backend-owned
// process boundary. The backend receives lease.ctx and must observe cancellation
// before creating authority or a process.
func (lease *executionLease) authorizeBackendStart() error {
	if lease == nil || lease.lifecycle == nil {
		return ErrExecutorClosed
	}
	lifecycle := lease.lifecycle
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.closed {
		return ErrExecutorClosed
	}
	return lease.ctx.Err()
}

func (lease *executionLease) finishExecution() {
	if lease == nil {
		return
	}
	lease.executionOnce.Do(func() {
		if lease.stopClose != nil {
			lease.stopClose()
		}
		lease.cancel()
		lease.lifecycle.active.Done()
	})
}

func (lease *executionLease) finishCleanup() {
	if lease == nil || lease.lifecycle == nil {
		return
	}
	lease.cleanupOnce.Do(func() { lease.lifecycle.cleanup.Done() })
}

// finish releases both barriers for paths that never transfer spawn ownership.
func (lease *executionLease) finish() {
	lease.finishExecution()
	lease.finishCleanup()
}

func (lifecycle *executorLifecycle) beginClose() {
	if lifecycle == nil {
		return
	}
	lifecycle.mu.Lock()
	if !lifecycle.closed {
		lifecycle.closed = true
		lifecycle.cancel()
	}
	lifecycle.mu.Unlock()
}

func (lifecycle *executorLifecycle) wait() {
	if lifecycle != nil {
		lifecycle.active.Wait()
	}
}

func (lifecycle *executorLifecycle) waitCleanup() {
	if lifecycle != nil {
		lifecycle.cleanup.Wait()
	}
}

func (lifecycle *executorLifecycle) recordCleanupError(err error) {
	if lifecycle == nil || err == nil {
		return
	}
	lifecycle.errMu.Lock()
	lifecycle.cleanupErr = errors.Join(lifecycle.cleanupErr, err)
	lifecycle.errMu.Unlock()
}

func (lifecycle *executorLifecycle) delayedCleanupError() error {
	if lifecycle == nil {
		return nil
	}
	lifecycle.errMu.Lock()
	defer lifecycle.errMu.Unlock()
	return lifecycle.cleanupErr
}
