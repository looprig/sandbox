package exec

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/policy"
)

type fakeRetainedHandle struct{ closes int }

func (handle *fakeRetainedHandle) Close() error {
	handle.closes++
	return nil
}

type signalingRetainedHandle struct {
	closes atomic.Int32
	done   chan struct{}
	once   sync.Once
}

func (handle *signalingRetainedHandle) Close() error {
	handle.closes.Add(1)
	handle.once.Do(func() { close(handle.done) })
	return nil
}

func TestRetainedGrantPathTimerClosesIdleExpiry(t *testing.T) {
	executor := &Executor{
		clock:               time.Now,
		retainedGrantPaths:  make(retainedGrantPaths),
		grantExpiryRealtime: true,
	}
	handle := &signalingRetainedHandle{done: make(chan struct{})}
	executor.grantMu.Lock()
	err := executor.retainedGrantPaths.add([32]byte{7}, retainedGrantPath{
		binding: policy.PathBinding{CanonicalPath: "/target", ExistingPath: "/target", Identity: "identity"},
		target:  "/target", expiryUnixMilli: time.Now().Add(25 * time.Millisecond).UnixMilli(), handle: handle,
	})
	if err == nil {
		executor.rescheduleRetainedGrantExpiryLocked()
	}
	executor.grantMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-handle.done:
	case <-time.After(time.Second):
		t.Fatal("idle expired handle was not closed by timer")
	}
	if got := handle.closes.Load(); got != 1 {
		t.Fatalf("close count = %d, want 1", got)
	}
}

func TestRetainedGrantPathTimerRacesCloseWithoutDoubleClose(t *testing.T) {
	for range 25 {
		executor := &Executor{clock: time.Now, retainedGrantPaths: make(retainedGrantPaths), grantExpiryRealtime: true}
		handle := &signalingRetainedHandle{done: make(chan struct{})}
		executor.grantMu.Lock()
		if err := executor.retainedGrantPaths.add([32]byte{8}, retainedGrantPath{
			binding: policy.PathBinding{CanonicalPath: "/target", ExistingPath: "/target", Identity: "identity"},
			target:  "/target", expiryUnixMilli: time.Now().Add(time.Millisecond).UnixMilli(), handle: handle,
		}); err != nil {
			executor.grantMu.Unlock()
			t.Fatal(err)
		}
		executor.rescheduleRetainedGrantExpiryLocked()
		executor.grantMu.Unlock()
		executor.revokeResources()
		select {
		case <-handle.done:
		case <-time.After(time.Second):
			t.Fatal("close race leaked retained handle")
		}
		if got := handle.closes.Load(); got != 1 {
			t.Fatalf("close race count = %d, want 1", got)
		}
	}
}

func TestRetainedGrantPathsPruneTakeAndCloseLifecycle(t *testing.T) {
	paths := make(retainedGrantPaths)
	binding := policy.PathBinding{CanonicalPath: "/target", ExistingPath: "/target", Identity: "identity"}
	firstID := [32]byte{1}
	first := &fakeRetainedHandle{}
	if err := paths.add(firstID, retainedGrantPath{binding: binding, target: "/target", exact: true, expiryUnixMilli: 10, handle: first}); err != nil {
		t.Fatal(err)
	}
	paths.prune(10)
	if first.closes != 0 {
		t.Fatal("entry was closed at its inclusive expiry")
	}
	paths.prune(11)
	if first.closes != 1 || len(paths) != 0 {
		t.Fatalf("expired entry lifecycle: closes=%d len=%d", first.closes, len(paths))
	}

	secondID := [32]byte{2}
	second := &fakeRetainedHandle{}
	if err := paths.add(secondID, retainedGrantPath{binding: binding, target: "/target", exact: true, expiryUnixMilli: 20, handle: second}); err != nil {
		t.Fatal(err)
	}
	got, err := paths.borrow(secondID, &binding, "/target", true, 20)
	if err != nil || got != second {
		t.Fatalf("take = (%T, %v), want retained handle", got, err)
	}
	if _, err := paths.borrow(secondID, &binding, "/target", true, 20); err != nil {
		t.Fatalf("second borrow error = %v", err)
	}
	handles, err := paths.commit([][32]byte{secondID})
	if err != nil || len(handles) != 1 || handles[0] != second {
		t.Fatalf("commit = (%v, %v), want retained handle", handles, err)
	}
	if _, err := paths.borrow(secondID, &binding, "/target", true, 20); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("borrow after commit error = %v, want ErrGrantReplay", err)
	}
	if err := handles[0].Close(); err != nil || second.closes != 1 {
		t.Fatalf("transferred close = %v, closes=%d", err, second.closes)
	}

	third := &fakeRetainedHandle{}
	if err := paths.add([32]byte{3}, retainedGrantPath{binding: binding, target: "/target", expiryUnixMilli: 30, handle: third}); err != nil {
		t.Fatal(err)
	}
	paths.closeAll()
	if third.closes != 1 || len(paths) != 0 {
		t.Fatalf("closeAll lifecycle: closes=%d len=%d", third.closes, len(paths))
	}
}

func TestRetainedGrantPathsRejectAuthenticatedBindingMismatch(t *testing.T) {
	paths := make(retainedGrantPaths)
	id := [32]byte{4}
	handle := &fakeRetainedHandle{}
	binding := policy.PathBinding{CanonicalPath: "/target", ExistingPath: "/target", Identity: "identity"}
	if err := paths.add(id, retainedGrantPath{binding: binding, target: "/target", exact: true, expiryUnixMilli: 10, handle: handle}); err != nil {
		t.Fatal(err)
	}
	tampered := binding
	tampered.Identity = "other"
	if _, err := paths.borrow(id, &tampered, "/target", true, 10); !errors.Is(err, ErrGrantTargetChanged) {
		t.Fatalf("binding mismatch error = %v, want ErrGrantTargetChanged", err)
	}
	if handle.closes != 0 || len(paths) != 1 {
		t.Fatalf("mismatched borrow mutated registry: closes=%d len=%d", handle.closes, len(paths))
	}
}
