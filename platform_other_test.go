//go:build !darwin && !linux

package sandbox

import (
	"errors"
	"testing"
)

func TestUnsupportedPlatformHasNoSandboxBackend(t *testing.T) {
	backend, err := platformBackend()
	if backend != nil || !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("platformBackend = %T, %v; want nil, ErrSandboxUnavailable", backend, err)
	}
}
