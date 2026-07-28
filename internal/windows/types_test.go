//go:build !windows

package windows

import (
	"context"
	"errors"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
)

func TestWindowsTypesAndProblemCodes(t *testing.T) {
	var _ SandboxMode = Auto
	status := SetupStatus{Problems: []SetupProblem{{
		Code:     SetupProblemPortInUse,
		Resource: "looprig-host",
		Path:     `C:\ProgramData\Looprig`,
		Port:     43191,
		PID:      42,
		Detail:   "port is held by another process",
	}}}
	if err := status.Problems[0].validate(); err != nil {
		t.Fatalf("valid problem: %v", err)
	}
	status.Problems[0].Detail = " credential\x00"
	if err := status.Problems[0].validate(); err == nil {
		t.Fatal("unsafe problem detail validated")
	}

	wantCodes := []WindowsSetupProblemCode{
		SetupProblemUnknown,
		SetupProblemManifestMissing,
		SetupProblemOwnerMismatch,
		SetupProblemHostBinaryStale,
		SetupProblemServiceUnavailable,
		SetupProblemAccountMissing,
		SetupProblemCredentialUnavailable,
		SetupProblemFirewallOverridden,
		SetupProblemFirewallRuleChanged,
		SetupProblemPortInUse,
		SetupProblemRuntimeBaselineGap,
		SetupProblemLeaseRecoveryPending,
		SetupProblemProtocolMismatch,
	}
	for index, code := range wantCodes {
		if code != WindowsSetupProblemCode(index) {
			t.Fatalf("problem code %d = %d", index, code)
		}
	}
}

func TestWindowsUnavailableErrors(t *testing.T) {
	for name, err := range map[string]error{
		"setup required": ErrSetupRequired,
		"setup stale":    ErrSetupStale,
	} {
		if !errors.Is(err, enforce.ErrUnavailable) {
			t.Errorf("%s does not unwrap to enforce.ErrUnavailable", name)
		}
	}
	if errors.Is(ErrElevationRequired, enforce.ErrUnavailable) {
		t.Fatal("ErrElevationRequired unexpectedly unwraps to enforce.ErrUnavailable")
	}

	config := SetupConfig{}
	if _, err := Inspect(context.Background(), config); !errors.Is(err, enforce.ErrUnavailable) {
		t.Fatalf("Inspect error = %v, want enforce.ErrUnavailable", err)
	}
	if err := Setup(context.Background(), config); !errors.Is(err, enforce.ErrUnavailable) {
		t.Fatalf("Setup error = %v, want enforce.ErrUnavailable", err)
	}
	if err := Remove(context.Background(), config); !errors.Is(err, enforce.ErrUnavailable) {
		t.Fatalf("Remove error = %v, want enforce.ErrUnavailable", err)
	}
}
