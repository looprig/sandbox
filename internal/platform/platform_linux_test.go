//go:build linux

package platform

import (
	"errors"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/linux"
)

// TestSelectLinuxBackend covers the rung × Init-called matrix that Backend
// uses: a re-exec rung (1/2) needs Init() and yields the linux.Backend, else
// linux.ErrInitNotCalled; rung none yields the null backend regardless of Init.
func TestSelectLinuxBackend(t *testing.T) {
	tests := []struct {
		name       string
		Rung       linux.Rung
		initCalled bool
		wantErr    error
		wantType   string // "linux" | "null"
	}{
		{"rung2 with Init -> linux backend", linux.RungTwo, true, nil, "linux"},
		{"rung1 with Init -> linux backend", linux.RungOne, true, nil, "linux"},
		{"rung2 without Init -> linux.ErrInitNotCalled", linux.RungTwo, false, linux.ErrInitNotCalled, ""},
		{"rung1 without Init -> linux.ErrInitNotCalled", linux.RungOne, false, linux.ErrInitNotCalled, ""},
		{"linux.Rung none with Init -> unavailable", linux.RungNone, true, enforce.ErrUnavailable, ""},
		{"linux.Rung none without Init -> unavailable", linux.RungNone, false, enforce.ErrUnavailable, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, err := linux.SelectBackend(tt.Rung, tt.initCalled)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("linux.SelectBackend err = %v, want %v", err, tt.wantErr)
			}
			if tt.wantErr != nil {
				if b != nil {
					t.Errorf("backend = %v, want nil on error", b)
				}
				return
			}
			switch tt.wantType {
			case "linux":
				if _, ok := b.(*linux.Backend); !ok {
					t.Errorf("backend = %T, want *linux.Backend", b)
				}
			}
		})
	}
}
