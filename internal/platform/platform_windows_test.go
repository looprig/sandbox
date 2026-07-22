//go:build windows

package platform

import (
	"errors"
	"reflect"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/windows"
)

func TestPlatformForwardsEveryWindowsMode(t *testing.T) {
	tests := []struct {
		name        string
		config      windows.Config
		scratchRoot string
	}{
		{name: "auto", config: windows.Config{Mode: windows.Auto}, scratchRoot: `C:\scratch\auto`},
		{name: "restricted token", config: windows.Config{Mode: windows.RestrictedToken}, scratchRoot: `C:\scratch\restricted`},
		{name: "elevated", config: windows.Config{Mode: windows.Elevated, StateRoot: `C:\ProgramData\Looprig`}, scratchRoot: `C:\scratch\elevated`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var got windows.Config
			var gotScratchRoot string
			calls := 0
			original := windowsPlatformBackend
			windowsPlatformBackend = func(config windows.Config, scratchRoot string) (enforce.Backend, error) {
				calls++
				got = config
				gotScratchRoot = scratchRoot
				return enforce.NewNull(), nil
			}
			t.Cleanup(func() { windowsPlatformBackend = original })

			backend, err := Backend(Options{Windows: test.config, ScratchRoot: test.scratchRoot})
			if err != nil {
				t.Fatalf("Backend: %v", err)
			}
			if reflect.TypeOf(backend) != reflect.TypeOf(enforce.NewNull()) {
				t.Fatalf("Backend = %T; want %T", backend, enforce.NewNull())
			}
			if calls != 1 {
				t.Fatalf("selector calls = %d; want 1", calls)
			}
			if !reflect.DeepEqual(got, test.config) {
				t.Fatalf("forwarded config = %#v; want %#v", got, test.config)
			}
			if gotScratchRoot != test.scratchRoot {
				t.Fatalf("forwarded scratch root = %q; want %q", gotScratchRoot, test.scratchRoot)
			}
		})
	}
}

func TestPlatformReturnsWindowsSelectorErrorUnchanged(t *testing.T) {
	want := errors.New("selector failed")
	original := windowsPlatformBackend
	windowsPlatformBackend = func(windows.Config, string) (enforce.Backend, error) {
		return nil, want
	}
	t.Cleanup(func() { windowsPlatformBackend = original })

	backend, err := Backend(Options{Windows: windows.Config{Mode: windows.RestrictedToken}})
	if backend != nil {
		t.Fatalf("Backend = %T; want nil", backend)
	}
	if !errors.Is(err, want) {
		t.Fatalf("Backend error = %v; want %v", err, want)
	}
}
