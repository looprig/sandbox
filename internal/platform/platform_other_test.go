//go:build !darwin && !linux && !windows

package platform

import (
	"errors"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/windows"
)

func TestUnsupportedPlatformHasNoSandboxBackend(t *testing.T) {
	backend, err := Backend(Options{})
	if backend != nil || !errors.Is(err, enforce.ErrUnavailable) {
		t.Fatalf("Backend = %T, %v; want nil, enforce.ErrUnavailable", backend, err)
	}
}

func TestPlatformRejectsWindowsOptionsOnUnsupportedNonWindows(t *testing.T) {
	backend, err := Backend(Options{Windows: windows.Config{Mode: windows.Elevated}})
	if backend != nil || err == nil {
		t.Fatalf("Backend(non-zero Windows options) = %T, %v; want nil, error", backend, err)
	}
}
