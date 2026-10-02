package exec

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"testing"
	"time"
)

// noDeadlineReadEnd is a drainReadEnd whose descriptor takes no deadline —
// the shape every os.Pipe read end has on Windows, where SetReadDeadline
// answers os.ErrNoDeadline because anonymous pipes are not pollable there.
type noDeadlineReadEnd struct{ *drainReadEnd }

func (noDeadlineReadEnd) SetReadDeadline(time.Time) error { return os.ErrNoDeadline }

// TestWaitOutputDrainFallbackCloseIsIdempotentForTheProcess pins the second
// half of the first Windows CI failure ("close |0: file already closed"):
// when waitOutputDrain cannot expire a deadline it closes the read end, and
// the pipe-backed Process that owns the same read end closes it again during
// spawn cleanup. That second Close must not surface as a teardown error,
// because the truncation is already reported, once, as
// ErrOutputDrainIncomplete.
func TestWaitOutputDrainFallbackCloseIsIdempotentForTheProcess(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// w stays open for the whole test: it is the detached holder that keeps
	// the drain from ever observing EOF on its own.
	t.Cleanup(func() { _ = w.Close() })
	readEnd := newDrainReadEnd(r)

	var drainWG sync.WaitGroup
	drainWG.Add(1)
	go func() {
		defer drainWG.Done()
		_, _ = io.Copy(io.Discard, readEnd)
	}()

	done := make(chan bool, 1)
	go func() { done <- waitOutputDrain(&drainWG, 50*time.Millisecond, noDeadlineReadEnd{readEnd}) }()
	select {
	case incomplete := <-done:
		if !incomplete {
			t.Fatal("waitOutputDrain reported a complete drain while a writer still held the pipe")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("waitOutputDrain's close fallback did not release a drain blocked on a deadline-less read end")
	}

	process := newPipeProcess(nil, readEnd, closedEmptyReadCloser{}, nil, 0)
	if err := process.Close(context.Background()); err != nil {
		t.Fatalf("Process.Close after the drain fallback closed the read end = %v, want nil (the close must be idempotent)", err)
	}
	if err := readEnd.Close(); err != nil {
		t.Fatalf("third Close = %v, want the first close's nil result", err)
	}
}

// TestDrainReadEndCloseReturnsFirstResult proves the wrapper reaches the OS
// exactly once: the raw *os.File reports os.ErrClosed on a second close, the
// wrapper never does.
func TestDrainReadEndCloseReturnsFirstResult(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	readEnd := newDrainReadEnd(r)
	for i := 0; i < 3; i++ {
		if err := readEnd.Close(); err != nil {
			t.Fatalf("Close #%d = %v, want nil", i+1, err)
		}
	}
	if err := r.Close(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("raw close after the wrapper closed = %v, want os.ErrClosed (the wrapper must have closed the real file)", err)
	}
}
