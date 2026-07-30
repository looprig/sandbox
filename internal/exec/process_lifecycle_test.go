package exec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This file covers Task 11's Step 1 test list for the ExecutorSet/lifecycle
// side of the two-phase async process: explicit session cancellation kills a
// live process, ExecutorSet.Close prevents new starts, terminates live
// processes, and waits for terminal cleanup before returning, start/close
// linearization leaks nothing, a consumer that never calls Wait still gets
// cleanup, and an uncertain terminal proof transfers the whole capsule to the
// existing quarantinedSpawn/retry path exactly like the synchronous path
// already does (see TestExecutorRunQuarantineBlocksSetCloseAndAggregatesDelayedErrors
// in process_quarantine_test.go, which this file's quarantine test mirrors
// through PrepareProcess/Start instead of executor.run).

// TestExecutorSetCloseCancelsLiveAsyncProcess proves explicit executor-set
// (session) close kills a live async process exactly like it already does
// for the synchronous RunCommand path (see
// TestExecutorSetCloseCancelsAndWaitsForActiveCommand): Close cancels
// lifecycle.ctx, which reaches the spawned cmd's context and SIGKILLs its
// process group, and Close does not return until that termination's zero
// proof is confirmed and every reservation released.
func TestExecutorSetCloseCancelsLiveAsyncProcess(t *testing.T) {
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(&captureBackend{
			bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		})))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := set.For("live-async")
	if err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(workspace, "started")
	completed := filepath.Join(workspace, "completed")
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: portableWriteSleepWriteCommand(started, completed, 30),
		ExecutionID: "live-async",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitForPath(t, started)

	closeDone := make(chan error, 1)
	go func() { closeDone <- set.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ExecutorSet.Close did not return after cancelling a live async process")
	}
	if _, err := os.Stat(completed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("killed process reached its completion marker: stat err = %v", err)
	}
	result, waitErr := proc.Wait(context.Background())
	t.Logf("post-close Wait = (%+v, %v)", result, waitErr)
}

// TestExecutorSetCloseClosesAbandonedPreparedHandle proves that a
// PreparedProcess the caller never Starts and never Closes is released by
// ExecutorSet.Close anyway — the whole point of executorLifecycle's prepared
// registry — rather than leaving Close blocked forever on a lease nothing
// will ever finish.
func TestExecutorSetCloseClosesAbandonedPreparedHandle(t *testing.T) {
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	var released atomic.Bool
	backend := &captureBackend{
		bits:    GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		release: func() error { released.Store(true); return nil },
	}
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(backend)))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := set.For("abandoned-prepared")
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(workspace, "marker")
	if _, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: portableWriteCommand(marker, "spawned"),
		ExecutionID: "abandoned-prepared",
	}); err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	// Deliberately never Start nor Close the returned *PreparedProcess.

	closeDone := make(chan error, 1)
	go func() { closeDone <- set.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ExecutorSet.Close blocked forever on an abandoned unstarted PreparedProcess")
	}
	if !released.Load() {
		t.Fatal("abandoned PreparedProcess's compiled spec was never released by Close")
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("abandoned preparation appears to have spawned: stat err = %v", err)
	}
}

// TestPreparedProcessNeverWaitedStillGetsCleanedUp proves the background
// supervisor Start hands ownership to reaps and releases resources on its
// own, entirely independent of whether the caller ever calls Process.Wait —
// no ExecutorSet.Close involved here at all.
func TestPreparedProcessNeverWaitedStillGetsCleanedUp(t *testing.T) {
	workspace := t.TempDir()
	var released atomic.Bool
	backend := &captureBackend{
		bits:    GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		release: func() error { released.Store(true); return nil },
	}
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	executor, err := newTestExecutor(profile, withBackend(backend))
	if err != nil {
		t.Fatal(err)
	}
	completed := filepath.Join(workspace, "completed")
	command := portableWriteCommand(completed, "completed")
	// A grant is required so this preparation compiles its own fresh spec
	// (resolveGrantedProcessResources) rather than reusing the executor's
	// shared base spec, whose Release belongs to Executor.releaseCompiledSpec
	// and is never called per spawn (see resolvePlainProcessResources).
	token := mustCommandStartGrant(t, executor, "never-waited", command, workspace)
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: command,
		ExecutionID: "never-waited", Grants: []string{token},
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	if _, err := prepared.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v", err)
	}
	// Deliberately never call proc.Wait or proc.Close.

	waitForPath(t, completed)
	deadline := time.Now().Add(3 * time.Second)
	for !released.Load() {
		if time.Now().After(deadline) {
			t.Fatal("compiled spec was never released for a Process nobody ever waited on")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestPreparedProcessStartCloseLinearizationHasNoLeak races Start and Close
// on the same PreparedProcess many times: exactly one path (Start succeeding
// and later reaping the process, or Close winning and releasing the
// reservation) must own the release, releasing the compiled spec exactly
// once every time, with no leaked lease (each iteration's ExecutorSet.Close
// -- called at the very end -- must still return promptly).
func TestPreparedProcessStartCloseLinearizationHasNoLeak(t *testing.T) {
	const iterations = 25
	for i := 0; i < iterations; i++ {
		workspace := t.TempDir()
		var releases atomic.Int32
		backend := &captureBackend{
			bits:    GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
			release: func() error { releases.Add(1); return nil },
		}
		profile := mustProfile(t, ProfileConfig{
			WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
			HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
		})
		set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
			withExecutorSetConfig(withBackend(backend)))
		if err != nil {
			t.Fatal(err)
		}
		executor, err := set.For("race")
		if err != nil {
			t.Fatal(err)
		}
		prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
			Directory: workspace, Command: portableSuccessCommand(), ExecutionID: "race",
		})
		if err != nil {
			t.Fatalf("PrepareProcess: %v", err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		var proc *Process
		var startErr, closeErr error
		go func() { defer wg.Done(); proc, startErr = prepared.Start(context.Background()) }()
		go func() { defer wg.Done(); closeErr = prepared.Close() }()
		wg.Wait()

		if startErr == nil && proc != nil {
			if _, err := proc.Wait(context.Background()); err != nil {
				t.Fatalf("iteration %d: Wait: %v", i, err)
			}
		}
		if closeErr != nil {
			t.Fatalf("iteration %d: Close: %v", i, closeErr)
		}

		closeSetDone := make(chan error, 1)
		go func() { closeSetDone <- set.Close() }()
		select {
		case err := <-closeSetDone:
			if err != nil {
				t.Fatalf("iteration %d: ExecutorSet.Close: %v", i, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("iteration %d: ExecutorSet.Close leaked (never returned)", i)
		}
		if got := releases.Load(); got != 1 {
			t.Fatalf("iteration %d: compiled spec released %d times, want exactly 1", i, got)
		}
	}
}

// TestPreparedProcessUncertainProofTransfersCapsuleToQuarantine mirrors
// TestExecutorRunQuarantineBlocksSetCloseAndAggregatesDelayedErrors
// (process_quarantine_test.go) through PrepareProcess/Start's async
// supervisor instead of executor.run: an initially-failed zero proof must
// retain every resource (cmd, spawn cleanup, and the grant/spec release
// closures) until a later proof succeeds, must not let ExecutorSet.Close
// return early, and must aggregate the delayed release error into Close's
// result exactly once.
func TestPreparedProcessUncertainProofTransfersCapsuleToQuarantine(t *testing.T) {
	proofErr := errors.New("initial zero proof failed")
	terminateErr := errors.New("later terminate failed")
	specErr := errors.New("compiled spec release failed")
	tree := &integrationProcessTree{
		results: [][2]error{{nil, proofErr}, {terminateErr, nil}},
		record:  func(string) {},
	}
	sink := &captureQuarantine{}
	workspace := t.TempDir()
	backend := &captureBackend{
		bits:    GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		release: func() error { return specErr },
	}
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(backend),
			executorConfig{quarantine: sink, processTree: func(*exec.Cmd, processTreeOptions) (processTreeBoundary, error) {
				return tree, nil
			}}))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := set.For("quarantine-async")
	if err != nil {
		t.Fatal(err)
	}
	command := portableSuccessCommand()
	// A grant is required so this preparation compiles its own fresh spec
	// (resolveGrantedProcessResources), whose Release joins the SAME
	// per-spawn quarantinedSpawn.afterExecution list the compiled backend
	// resource, retained path handles, and proxy credential would — proving
	// the whole capsule, not just process-tree authority, transfers to
	// quarantine on an uncertain proof.
	token := mustCommandStartGrant(t, executor, "quarantine-async", command, workspace)
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: command, ExecutionID: "quarantine-async", Grants: []string{token},
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	_ = proc
	// The fake processTree's start is a no-op that never truly execs
	// anything (mirroring TestExecutorRunQuarantineBlocksSetCloseAndAggregatesDelayedErrors's
	// own "not-started" fixture exactly), so this deliberately does not
	// assert on proc.Wait's own result here — only on the quarantine
	// transfer and eventual release the background supervisor drives.

	// The supervisor goroutine performs the (failing) zero proof
	// asynchronously; give it a moment to reach the quarantine transfer.
	deadline := time.Now().Add(2 * time.Second)
	for sink.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("uncertain proof never transferred to quarantine")
		}
		time.Sleep(5 * time.Millisecond)
	}

	closeResult := make(chan error, 1)
	go func() { closeResult <- set.Close() }()
	select {
	case err := <-closeResult:
		t.Fatalf("ExecutorSet.Close returned before the later zero proof: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	if done, err := sink.Load().reapOnce(); !done || !errors.Is(err, terminateErr) || !errors.Is(err, specErr) {
		t.Fatalf("later reap = (%v, %v), want both delayed errors", done, err)
	}
	closeErr := <-closeResult
	if !errors.Is(closeErr, terminateErr) || !errors.Is(closeErr, specErr) {
		t.Fatalf("ExecutorSet.Close error = %v, want delayed terminate and spec release errors", closeErr)
	}
}
