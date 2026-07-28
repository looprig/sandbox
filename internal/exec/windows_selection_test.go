//go:build windows

package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/windows"
)

func TestWindowsRestrictedSelectionRunsThroughExecutorLifecycle(t *testing.T) {
	if os.Getenv("SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST") != "1" {
		t.Skip("restricted ACL integration is restricted to a disposable Windows worker")
	}
	requireWindowsDisposableStandardSourceToken(t)
	workspace := t.TempDir()
	scratch := t.TempDir()
	marker := filepath.Join(scratch, "caller-owned.marker")
	journal := filepath.Join(scratch, "restricted-journal-v1")
	if err := os.WriteFile(marker, []byte("owned by caller"), 0o600); err != nil {
		t.Fatalf("write caller-owned marker: %v", err)
	}
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Allow, Network: Allow, Command: Allow,
	})
	set, err := NewExecutorSet(prof,
		WithScratchRoot(scratch),
		WithMaxExecutors(1),
		WithWindowsSandboxMode(windows.RestrictedToken),
	)
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	owned := set.ownedRoot
	executor, err := set.For("restricted")
	if err != nil {
		_ = set.Close()
		t.Fatalf("For: %v", err)
	}
	if got := executor.Level(); got != LevelNone {
		t.Errorf("Level = %d; want LevelNone", got)
	}
	if got := executor.GuaranteeBits(); got != GuaranteeEnvScrub {
		t.Errorf("guarantee bits = %#x; want only EnvScrub (%#x)", got, GuaranteeEnvScrub)
	}

	for attempt := 0; attempt < 2; attempt++ {
		if _, code, runErr := executor.RunCommand(context.Background(), workspace, "exit 0"); runErr != nil || code != 0 {
			_ = set.Close()
			t.Fatalf("restricted execution %d = code %d, error %v", attempt+1, code, runErr)
		}
	}
	if err := set.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := set.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := os.Stat(owned); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("set-owned root still exists or stat failed: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("caller scratch was removed with restricted journal state: %v", err)
	}
	if info, err := os.Stat(journal); err != nil || !info.IsDir() {
		t.Fatalf("stable restricted journal did not survive set close: info=%v error=%v", info, err)
	}
}

func TestWindowsCompiledSpecUsesFreshSpawnCleanupAndOwnerRelease(t *testing.T) {
	var cleanups atomic.Int32
	var releases atomic.Int32
	backend := &captureBackend{
		bits: GuaranteeEnvScrub,
		cleanup: func() {
			cleanups.Add(1)
		},
		release: func() error {
			releases.Add(1)
			return nil
		},
	}
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: t.TempDir(), WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Allow, Network: Allow, Command: Allow,
	})
	set, err := NewExecutorSet(prof,
		WithScratchRoot(t.TempDir()),
		WithMaxExecutors(1),
		WithWindowsSandboxMode(windows.RestrictedToken),
		withExecutorSetConfig(withBackend(backend)),
	)
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	executor, err := set.For("restricted-lifecycle")
	if err != nil {
		_ = set.Close()
		t.Fatalf("For: %v", err)
	}
	for attempt := 0; attempt < 2; attempt++ {
		if _, code, runErr := executor.RunCommand(context.Background(), prof.Settings().WorkspaceRoot, "exit 0"); runErr != nil || code != 0 {
			_ = set.Close()
			t.Fatalf("execution %d = code %d, error %v", attempt+1, code, runErr)
		}
	}
	if got := cleanups.Load(); got != 2 {
		t.Errorf("per-spawn cleanup count = %d; want 2", got)
	}
	if got := releases.Load(); got != 0 {
		t.Errorf("owner release count before close = %d; want 0", got)
	}
	if err := set.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := set.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := releases.Load(); got != 1 {
		t.Errorf("owner release count after two closes = %d; want 1", got)
	}
}

func TestWindowsAutoRejectsRestrictedFallbackWhenGuaranteesAreMissing(t *testing.T) {
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: t.TempDir(), WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Allow, Command: Allow,
	})
	set, err := NewExecutorSet(prof,
		WithScratchRoot(t.TempDir()),
		WithMaxExecutors(1),
		WithWindowsSandboxMode(windows.Auto),
	)
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })

	if _, err := set.For("auto"); !errors.Is(err, windows.ErrSetupRequired) {
		t.Fatalf("For error = %v; want ErrSetupRequired", err)
	} else if !errors.Is(err, enforce.ErrUnavailable) {
		t.Fatalf("For error = %v; want ErrUnavailable sentinel relationship", err)
	} else if !strings.Contains(err.Error(), "WriteBoundary") {
		t.Fatalf("For error = %v; want the missing WriteBoundary named", err)
	}
}

func TestWindowsElevatedSelectionNeverFallsBack(t *testing.T) {
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: t.TempDir(), WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Allow, Network: Allow, Command: Allow,
	})
	set, err := NewExecutorSet(prof,
		WithScratchRoot(t.TempDir()),
		WithMaxExecutors(1),
		WithWindowsSandboxMode(windows.Elevated),
	)
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })

	if _, err := set.For("elevated"); !errors.Is(err, windows.ErrSetupRequired) {
		t.Fatalf("For error = %v; want ErrSetupRequired rather than restricted fallback", err)
	}
}
