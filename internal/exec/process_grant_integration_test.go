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
// This test runs for real on this host's own Seatbelt backend on darwin too
// (gated by requireSandboxExec exactly like TestAcceptanceMatrixDarwin).
// Between Task 12C and the 2026-08-06 best-effort containment decision, every
// Darwin async Start() failed closed with
// enforce.ErrLifetimeContainmentUnavailable (Darwin had no process-tree
// containment primitive at all), so this test was Linux-only in the
// meantime; process_tree_darwin.go's attachSupervisedProof now attaches a
// best-effort prover instead of rejecting, so the grant lifecycle below runs
// end-to-end under real Seatbelt confinement on darwin exactly like it always
// has on Linux.
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
	if errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
		// A supervised spawn has no best-effort fallback: without a delegated
		// cgroup v2 pids ancestor there is no cgroup.kill containment proof,
		// so Start fails closed by design (SPEC Task 12b). Hosted CI runners
		// do not delegate that controller. Accept only this exact sentinel --
		// any other Start error is still a failure -- and stop before the
		// lifecycle assertions, which need a live process to mean anything.
		t.Skipf("lifetime containment unavailable on this host: %v", err)
	}
	if err != nil {
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

// skipIfNoRealBackend skips (rather than fails) when err reflects this host
// having no usable OS confinement backend at all (enforce.ErrUnavailable —
// e.g. a Linux kernel with no Landlock support, which every OTHER Linux
// confined-spawn test in this package already gates on via
// requireLandlockV4/requireSeccomp) — a genuine environment gap, not a
// containment defect the calling test's own proof is responsible for. Any
// other error still fails the test. This file carries only the
// `//go:build integration` constraint (no darwin || linux restriction, unlike
// process_parent_death_integration_unix_test.go, this helper's original
// home): every `-tags integration` build on every platform this module
// targets, including GOOS=windows, must be able to resolve this symbol —
// process_grant_integration_test.go's own TestIntegrationProcessPreparedGrantLifetime
// is one of several platform-neutral callers.
func skipIfNoRealBackend(t *testing.T, op string, err error) {
	t.Helper()
	if errors.Is(err, enforce.ErrUnavailable) {
		t.Skipf("%s: no OS confinement backend available on this host (%v); the containment this test proves cannot be exercised without one", op, err)
	}
	t.Fatalf("%s: %v", op, err)
}

func separatorFor() string {
	if runtime.GOOS == "windows" {
		return " & "
	}
	return "; "
}
