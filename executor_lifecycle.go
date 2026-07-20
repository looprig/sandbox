package sandbox

import (
	"context"
	"os/exec"
	"sync"
)

// executorLifecycle is shared by every Executor owned by one ExecutorSet. Its
// mutex is the spawn/close linearization point: Start either completes before
// close begins, or observes closing and fails without spawning.
type executorLifecycle struct {
	mu     sync.Mutex
	ctx    context.Context
	cancel context.CancelFunc
	active sync.WaitGroup
	closed bool
}

func newExecutorLifecycle() *executorLifecycle {
	ctx, cancel := context.WithCancel(context.Background())
	return &executorLifecycle{ctx: ctx, cancel: cancel}
}

type executionLease struct {
	lifecycle *executorLifecycle
	caller    context.Context
	ctx       context.Context
	cancel    context.CancelFunc
	stopClose func() bool
	once      sync.Once
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

func (lease *executionLease) start(cmd *exec.Cmd) error {
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
	return cmd.Start()
}

func (lease *executionLease) finish() {
	if lease == nil {
		return
	}
	lease.once.Do(func() {
		if lease.stopClose != nil {
			lease.stopClose()
		}
		lease.cancel()
		lease.lifecycle.active.Done()
	})
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
