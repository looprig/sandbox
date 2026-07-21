//go:build !darwin && !linux

package platform

import (
	"errors"
	"github.com/looprig/sandbox/internal/enforce"
	"testing"
)

func TestUnsupportedPlatformHasNoSandboxBackend(t *testing.T) {
	backend, err := Backend()
	if enforce.Backend != nil || !errors.Is(err, enforce.ErrUnavailable) {
		t.Fatalf("Backend = %T, %v; want nil, enforce.ErrUnavailable", backend, err)
	}
}
