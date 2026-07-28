package windows

import (
	"context"
	"errors"
	"fmt"
	"time"
)

const (
	jobObjectMessageActiveProcessZero uint32 = 4
	jobObjectMessageNewProcess        uint32 = 6
	jobObjectMessageExitProcess       uint32 = 7
)

var (
	// ErrJobCompletionWait marks a failure to prove that a terminated Job has
	// reached zero active processes. Callers must escalate containment rather
	// than treating this as successful cleanup.
	ErrJobCompletionWait = errors.New("sandbox: Windows Job completion wait failed")

	errJobCompletionPollTimeout = errors.New("windows job completion poll timeout")
	errJobCompletionPortClosed  = errors.New("windows job completion port closed")
)

type jobCompletionEvent struct {
	message uint32
	key     uintptr
	err     error
}

type jobCompletionWaitOptions struct {
	pollInterval time.Duration
	maxErrors    int
}

type jobCompletionNext func(time.Duration) jobCompletionEvent

func waitForJobActiveProcessZero(ctx context.Context, key uintptr, next jobCompletionNext, options jobCompletionWaitOptions) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if next == nil {
		return fmt.Errorf("%w: nil completion source", ErrJobCompletionWait)
	}
	if options.pollInterval <= 0 {
		options.pollInterval = 50 * time.Millisecond
	}
	if options.maxErrors <= 0 {
		options.maxErrors = 3
	}

	errorsSeen := 0
	for {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("%w: %w", ErrJobCompletionWait, err)
		}
		event := next(options.pollInterval)
		if event.err != nil {
			if errors.Is(event.err, errJobCompletionPollTimeout) {
				continue
			}
			if errors.Is(event.err, errJobCompletionPortClosed) {
				return fmt.Errorf("%w: %w", ErrJobCompletionWait, event.err)
			}
			errorsSeen++
			if errorsSeen >= options.maxErrors {
				return fmt.Errorf("%w after %d completion errors: %w", ErrJobCompletionWait, errorsSeen, event.err)
			}
			continue
		}
		if event.key == key && event.message == jobObjectMessageActiveProcessZero {
			return nil
		}
	}
}
