package windows

import (
	"context"
	"errors"
	"testing"
	"time"
)

type scriptedCompletionSource struct {
	events []jobCompletionEvent
	calls  int
}

func (source *scriptedCompletionSource) next(time.Duration) jobCompletionEvent {
	source.calls++
	if len(source.events) == 0 {
		return jobCompletionEvent{err: errJobCompletionPollTimeout}
	}
	event := source.events[0]
	source.events = source.events[1:]
	return event
}

func TestWaitJobCompletionActiveZero(t *testing.T) {
	source := &scriptedCompletionSource{events: []jobCompletionEvent{
		{message: jobObjectMessageNewProcess, key: 7},
		{message: jobObjectMessageActiveProcessZero, key: 7},
	}}
	if err := waitForJobActiveProcessZero(context.Background(), 7, source.next, jobCompletionWaitOptions{}); err != nil {
		t.Fatal(err)
	}
	if source.calls != 2 {
		t.Fatalf("completion reads = %d, want 2", source.calls)
	}
}

func TestWaitJobCompletionIgnoresUnrelatedMessages(t *testing.T) {
	source := &scriptedCompletionSource{events: []jobCompletionEvent{
		{message: jobObjectMessageActiveProcessZero, key: 99},
		{message: jobObjectMessageExitProcess, key: 7},
		{message: jobObjectMessageActiveProcessZero, key: 7},
	}}
	if err := waitForJobActiveProcessZero(context.Background(), 7, source.next, jobCompletionWaitOptions{}); err != nil {
		t.Fatal(err)
	}
	if source.calls != 3 {
		t.Fatalf("completion reads = %d, want 3", source.calls)
	}
}

func TestWaitJobCompletionPersistentErrorsAreBounded(t *testing.T) {
	readErr := errors.New("injected completion failure")
	source := &scriptedCompletionSource{events: []jobCompletionEvent{
		{err: readErr},
		{err: readErr},
		{err: readErr},
		{message: jobObjectMessageActiveProcessZero, key: 7},
	}}
	err := waitForJobActiveProcessZero(context.Background(), 7, source.next, jobCompletionWaitOptions{maxErrors: 3})
	if !errors.Is(err, ErrJobCompletionWait) || !errors.Is(err, readErr) {
		t.Fatalf("wait error = %v, want completion sentinel and injected cause", err)
	}
	if source.calls != 3 {
		t.Fatalf("completion reads = %d, want bounded 3", source.calls)
	}
}

func TestWaitJobCompletionCloseRaceIsTerminal(t *testing.T) {
	source := &scriptedCompletionSource{events: []jobCompletionEvent{{err: errJobCompletionPortClosed}}}
	err := waitForJobActiveProcessZero(context.Background(), 7, source.next, jobCompletionWaitOptions{maxErrors: 9})
	if !errors.Is(err, ErrJobCompletionWait) || !errors.Is(err, errJobCompletionPortClosed) {
		t.Fatalf("wait error = %v, want terminal close-race error", err)
	}
	if source.calls != 1 {
		t.Fatalf("completion reads = %d, want 1", source.calls)
	}
}

func TestWaitJobCompletionContextIsBounded(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	source := &scriptedCompletionSource{}
	next := func(timeout time.Duration) jobCompletionEvent {
		event := source.next(timeout)
		if source.calls == 2 {
			cancel()
		}
		return event
	}
	err := waitForJobActiveProcessZero(ctx, 7, next, jobCompletionWaitOptions{pollInterval: time.Millisecond})
	if !errors.Is(err, ErrJobCompletionWait) || !errors.Is(err, context.Canceled) {
		t.Fatalf("wait error = %v, want bounded context cancellation", err)
	}
	if source.calls != 2 {
		t.Fatalf("completion reads = %d, want 2", source.calls)
	}
}
