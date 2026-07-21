//go:build !darwin && !linux

package sandbox

import (
	"errors"
	"github.com/looprig/sandbox/internal/enforce"
	"testing"
)

func TestUnsupportedPlatformHasNoSandboxBackend(t *testing.T) {
	backend, err := platformBackend()
	if enforce.Backend != nil || !errors.Is(err, enforce.ErrUnavailable) {
		t.Fatalf("platformBackend = %T, %v; want nil, enforce.ErrUnavailable", backend, err)
	}
}
