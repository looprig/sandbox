//go:build darwin

package platform

import (
	"reflect"
	"testing"

	"github.com/looprig/sandbox/internal/darwin"
	"github.com/looprig/sandbox/internal/windows"
)

func TestPlatformZeroWindowsOptionsLeaveDarwinSelectionUnchanged(t *testing.T) {
	backend, err := Backend(Options{})
	if err != nil {
		t.Fatalf("Backend(Options{}): %v", err)
	}
	if reflect.TypeOf(backend) != reflect.TypeOf(darwin.NewBackend()) {
		t.Fatalf("Backend(Options{}) = %T; want %T", backend, darwin.NewBackend())
	}
}

func TestPlatformRejectsWindowsOptionsOnDarwin(t *testing.T) {
	backend, err := Backend(Options{Windows: windows.Config{StateRoot: `/windows-only`}})
	if backend != nil || err == nil {
		t.Fatalf("Backend(non-zero Windows options) = %T, %v; want nil, error", backend, err)
	}
}
