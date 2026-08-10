//go:build !windows

package exec

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRunArgvLimitedTerminatesOverflowingProcess(t *testing.T) {
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot:  workspace,
		WorkspaceRead:  Allow,
		WorkspaceWrite: Allow,
		HostRead:       Allow,
		HostWrite:      Allow,
		Network:        Allow,
		Command:        Allow,
		Isolation:      Unconfined,
		AckUnconfined:  true,
	})
	executor, err := newTestExecutor(profile)
	if err != nil {
		t.Fatal(err)
	}
	out, code, err := executor.RunArgvLimited(context.Background(), workspace, portableEchoArgv(t, strings.Repeat("x", 64<<10)), 16)
	if !errors.Is(err, ErrOutputLimit) {
		t.Fatalf("RunArgvLimited error = %v, want ErrOutputLimit (output=%q code=%d)", err, out, code)
	}
	if len(out) > 16 {
		t.Fatalf("captured output length = %d, want <= 16", len(out))
	}
}
