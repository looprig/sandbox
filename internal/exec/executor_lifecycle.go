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
//
// prepared additionally tracks every live PreparedProcess that has reserved a
// lease (via beginExecution, inside PrepareProcess) but has not yet been
// consumed by Start or released by Close. A started Process eventually
// releases its lease because lifecycle.ctx cancellation reaches a real OS
// process or backend authority (cmd.Cancel / the backend's own Launch
// context); an UNSTARTED preparation has no such authority for a cancelled
// context to reach, so beginClose must actively close every one of them
// itself rather than merely waiting — otherwise an abandoned (never
// Started, never Closed) PreparedProcess would keep lifecycle.wait blocked
// forever.
type executorLifecycle struct {
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	active     sync.WaitGroup
	cleanup    sync.WaitGroup
	closed     bool
	prepared   map[*PreparedProcess]struct{}
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

// beginClose marks the lifecycle closed, cancels lifecycle.ctx (which reaches
// every live lease via the AfterFunc hook beginExecution installs), and
// atomically snapshots-and-clears the set of prepared-but-not-yet-started
// handles, returning them so the caller can release each one. Using the same
// mutex registerPrepared contends on makes the handoff race-free: a
// PrepareProcess call either registers before this snapshot (so it is
// returned here) or observes lifecycle.closed afterward (so registerPrepared
// itself refuses and the caller releases its own handle) — a handle can never
// fall in the gap between the two.
func (lifecycle *executorLifecycle) beginClose() []*PreparedProcess {
	if lifecycle == nil {
		return nil
	}
	lifecycle.mu.Lock()
	var abandoned []*PreparedProcess
	if !lifecycle.closed {
		lifecycle.closed = true
		lifecycle.cancel()
		for p := range lifecycle.prepared {
			abandoned = append(abandoned, p)
		}
		lifecycle.prepared = nil
	}
	lifecycle.mu.Unlock()
	return abandoned
}

// registerPrepared records a live PreparedProcess so beginClose can find and
// release it if its caller abandons it without ever calling Start or Close.
// It reports false (and registers nothing) once the lifecycle has begun
// closing; the caller must then release the handle itself instead of
// returning it.
func (lifecycle *executorLifecycle) registerPrepared(p *PreparedProcess) bool {
	if lifecycle == nil || p == nil {
		return false
	}
	lifecycle.mu.Lock()
	defer lifecycle.mu.Unlock()
	if lifecycle.closed {
		return false
	}
	if lifecycle.prepared == nil {
		lifecycle.prepared = make(map[*PreparedProcess]struct{})
	}
	lifecycle.prepared[p] = struct{}{}
	return true
}

// unregisterPrepared removes a PreparedProcess from the abandoned-handle
// registry once its caller has consumed it (Start) or released it (Close)
// normally. It is always safe to call, including after beginClose has
// already cleared the registry (delete on a nil map is a no-op).
func (lifecycle *executorLifecycle) unregisterPrepared(p *PreparedProcess) {
	if lifecycle == nil || p == nil {
		return
	}
	lifecycle.mu.Lock()
	delete(lifecycle.prepared, p)
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
