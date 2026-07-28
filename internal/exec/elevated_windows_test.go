//go:build windows

package exec

import (
	"errors"
	"testing"

	"github.com/looprig/sandbox/internal/platform"
	"github.com/looprig/sandbox/internal/policy"
	winbackend "github.com/looprig/sandbox/internal/windows"
)

func TestExplicitWindowsElevatedSelectionNeverFallsBackToInteractiveToken(t *testing.T) {
	backend, err := platform.Backend(platform.Options{
		Windows: winbackend.Config{Mode: winbackend.Elevated, StateRoot: `C:\ProgramData\Looprig\Sandbox`},
	})
	if err != nil {
		t.Fatalf("select elevated backend: %v", err)
	}
	spec, _, level, bits, err := backend.Compile(policy.Effective{})
	if !errors.Is(err, winbackend.ErrSetupRequired) {
		t.Fatalf("compile error = %v, want ErrSetupRequired while live composition is unavailable", err)
	}
	if spec.Wrap != nil || level != LevelNone || bits != 0 {
		t.Fatalf("elevated selection returned partial enforcement: %#v/%d/%#x", spec, level, bits)
	}
}
