package exec

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
)

func TestBoundedOutputWriterCapsAndSignalsOnce(t *testing.T) {
	var output bytes.Buffer
	var mu sync.Mutex
	var overflow atomic.Bool
	var cancellations atomic.Int32
	writer := &boundedOutputWriter{
		mu:         &mu,
		dst:        &output,
		limit:      5,
		overflow:   &overflow,
		onOverflow: func() { cancellations.Add(1) },
	}

	if n, err := writer.Write([]byte("hello world")); err != nil || n != len("hello world") {
		t.Fatalf("Write = (%d, %v), want all input accepted", n, err)
	}
	if got := output.String(); got != "hello" {
		t.Fatalf("captured output = %q, want %q", got, "hello")
	}
	if !overflow.Load() || cancellations.Load() != 1 {
		t.Fatalf("overflow=%v cancellations=%d, want true/1", overflow.Load(), cancellations.Load())
	}
	_, _ = writer.Write([]byte("again"))
	if cancellations.Load() != 1 {
		t.Fatalf("cancellations=%d after repeated overflow, want 1", cancellations.Load())
	}
}
