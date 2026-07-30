//go:build integration

package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
)

// TestIntegrationProcessPreparedGrantLifetime exercises the full two-phase
// async process lifecycle — grant issuance, PrepareProcess's redemption
// transaction, Start's confined spawn, live streaming, Wait, and
// ExecutorSet.Close's terminal cleanup — against a REAL supported backend
// (no test-injected backend/processTree/quarantine seam), exactly like this
// package's other //go:build integration and platform acceptance tests. Its
// tagged execution is deferred to Task 13's owning phase gate on a worker
// with real grant backends, matching this plan's general policy.
//
// This doc comment originally claimed the test also runs for real on this
// host's own Seatbelt backend on darwin (gated by requireSandboxExec exactly
// like TestAcceptanceMatrixDarwin). That was true when this test was
// written (Task 11), before Task 12C made every Darwin async Start() fail
// closed with enforce.ErrLifetimeContainmentUnavailable (Darwin has no real
// process-tree containment primitive yet, so this phase deliberately does
// not claim Darwin async execution). Real end-to-end exercise of this test
// is therefore Linux-only now; on darwin it skips as soon as Start reports
// exactly that expected fail-closed error, rather than treating it as a
// failure.
func TestIntegrationProcessPreparedGrantLifetime(t *testing.T) {
	requireSandboxExec(t)

	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1))
	if err != nil {
		skipIfNoRealBackend(t, "NewExecutorSet", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("integration-prepared-grant")
	if err != nil {
		t.Fatalf("ExecutorSet.For: %v", err)
	}

	inside := filepath.Join(workspace, "granted.txt")
	outside := filepath.Join(t.TempDir(), "ungranted.txt")
	started := filepath.Join(workspace, "started")
	completed := filepath.Join(workspace, "completed")
	command := portableWriteSleepWriteCommand(started, completed, 1) + separatorFor() +
		portableWriteCommand(inside, "granted") + separatorFor() +
		portableWriteCommand(outside, "leaked")

	now := time.Now()
	commandToken, err := executor.IssueGrant(context.Background(), "integration-prepared-grant", command, workspace,
		"command.execute", "", GrantClassCommandStart, command, now.Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatalf("IssueGrant (command.start): %v", err)
	}
	// A tree grant on the whole workspace, not just one file: the workspace
	// itself must already be writable for started/completed's own writes to
	// succeed, exactly like a real caller granting write access to a working
	// tree rather than one single output file.
	writeToken, err := executor.IssueGrant(context.Background(), "integration-prepared-grant", command, workspace,
		"filesystem.write", "tree:"+workspace, GrantClassFilesystemTreeWrite, workspace, now.Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatalf("IssueGrant (filesystem.write): %v", err)
	}

	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: command, ExecutionID: "integration-prepared-grant",
		Grants: []string{commandToken, writeToken},
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	if _, statErr := os.Stat(started); !os.IsNotExist(statErr) {
		t.Fatalf("PrepareProcess appears to have spawned: marker stat err = %v", statErr)
	}
	access := prepared.EffectiveAccess()
	if access.Kind != ProcessAccessScopedWrite {
		t.Fatalf("EffectiveAccess.Kind = %v, want ProcessAccessScopedWrite", access.Kind)
	}

	proc, err := prepared.Start(context.Background())
	if err != nil {
		if runtime.GOOS == "darwin" && errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Skipf("Start: %v (expected: darwin has no async lifetime-containment primitive yet, per Task 12C)", err)
		}
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })

	// The command's final step deliberately writes outside the granted tree,
	// so a nonzero-but-ran exit is expected here (the shell's last command
	// fails its confined write) — err must still be nil, exactly like the
	// synchronous RunCommand exit-code convention (a ran-but-nonzero process
	// is a result, not an error).
	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if _, statErr := os.Stat(completed); statErr != nil {
		t.Fatalf("completed marker: %v, want the confined process to have run to completion", statErr)
	}
	if data, statErr := os.ReadFile(inside); statErr != nil || string(data) != "granted" {
		t.Fatalf("write inside the granted tree: data=%q err=%v, want a successful confined write", data, statErr)
	}
	if _, statErr := os.Stat(outside); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("write outside the granted tree succeeded — FAIL-OPEN: stat err = %v", statErr)
	}

	// The token was already burned during PrepareProcess: it cannot be
	// replayed even now that the process has fully terminated.
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "integration-prepared-grant", workspace, command,
		[]string{commandToken, writeToken}); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("replaying the prepared grant after termination = %v, want ErrGrantReplay", err)
	}
}

func separatorFor() string {
	if runtime.GOOS == "windows" {
		return " & "
	}
	return "; "
}
