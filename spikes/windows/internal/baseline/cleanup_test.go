package baseline

import (
	"errors"
	"testing"
	"time"
)

func TestCleanupStateIsBounded(t *testing.T) {
	boom := errors.New("terminate failed")
	tests := []struct {
		name      string
		done      chan error
		terminate error
		close     error
		kill      error
		complete  bool
	}{
		{"termination failure", closedResult(nil), boom, nil, nil, true},
		{"no completion", make(chan error), nil, nil, nil, false},
		{"delayed completion", delayedResult(nil), nil, nil, nil, true},
		{"setup failure", closedResult(errors.New("wait failed")), nil, nil, nil, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result := CleanupWithWatchdog(test.done, time.After(20*time.Millisecond), func() error { return test.terminate }, func() error { return test.close }, func() error { return test.kill })
			if result.Completed != test.complete {
				t.Fatalf("completed=%v want %v", result.Completed, test.complete)
			}
			if test.terminate != nil && result.TerminateError == nil {
				t.Fatal("termination error lost")
			}
		})
	}
}

func closedResult(err error) chan error { ch := make(chan error, 1); ch <- err; return ch }
func delayedResult(err error) chan error {
	ch := make(chan error, 1)
	go func() { time.Sleep(time.Millisecond); ch <- err }()
	return ch
}
