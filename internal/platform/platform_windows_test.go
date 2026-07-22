//go:build windows

package platform

import (
	"reflect"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/windows"
)

func TestPlatformForwardsWindowsOptions(t *testing.T) {
	want := windows.Config{Mode: windows.Elevated, StateRoot: `C:\ProgramData\Looprig`}
	var got windows.Config
	original := windowsPlatformBackend
	windowsPlatformBackend = func(config windows.Config) (enforce.Backend, error) {
		got = config
		return enforce.NewNull(), nil
	}
	t.Cleanup(func() { windowsPlatformBackend = original })

	backend, err := Backend(Options{Windows: want})
	if err != nil {
		t.Fatalf("Backend: %v", err)
	}
	if reflect.TypeOf(backend) != reflect.TypeOf(enforce.NewNull()) {
		t.Fatalf("Backend = %T; want %T", backend, enforce.NewNull())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("forwarded config = %#v; want %#v", got, want)
	}
}
