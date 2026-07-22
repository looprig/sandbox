package exec

import (
	"context"
	"errors"
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/internal/windows"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type blockingConfigureBackend struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	bits    uint64
}

func (b *blockingConfigureBackend) Compile(policy.Effective) (enforce.Spec, CompileReport, uint8, uint64, error) {
	spec := enforce.Spec{Wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd) error, func()) {
		return argv, func(*exec.Cmd) error {
			b.once.Do(func() { close(b.entered) })
			<-b.release
			return nil
		}, nil
	}}
	return spec, CompileReport{}, LevelNone, b.bits, nil
}

func TestExecutorSetValidationOwnershipAndCleanup(t *testing.T) {
	workspace := t.TempDir()
	scratch := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	backend := &captureBackend{bits: GuaranteeWriteBoundary | GuaranteeReadBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}

	if _, err := NewExecutorSet(profile, WithMaxExecutors(1)); err == nil {
		t.Fatal("NewExecutorSet without scratch root succeeded")
	}
	if _, err := NewExecutorSet(profile, WithScratchRoot(scratch)); err == nil {
		t.Fatal("NewExecutorSet without positive limit succeeded")
	}

	set, err := NewExecutorSet(profile,
		WithScratchRoot(scratch), WithMaxExecutors(2),
		withExecutorSetConfig(withBackend(backend)),
	)
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	owned := set.ownedRoot
	assertOwnerOnlyDir(t, owned)

	alpha, err := set.For("alpha")
	if err != nil {
		t.Fatal(err)
	}
	again, err := set.For("alpha")
	if err != nil || again != alpha {
		t.Fatalf("memoized For = (%p,%v), want (%p,nil)", again, err, alpha)
	}
	beta, err := set.For("beta")
	if err != nil {
		t.Fatal(err)
	}
	if beta == alpha || beta.home == alpha.home || beta.tmp == alpha.tmp {
		t.Fatal("distinct keys shared executor, HOME, or TMPDIR")
	}
	assertOwnerOnlyDir(t, alpha.home)
	assertOwnerOnlyDir(t, beta.home)
	assertOwnerOnlyDir(t, alpha.tmp)
	assertOwnerOnlyDir(t, beta.tmp)
	if access := policy.ResolveFS(alpha.policy.FS, alpha.home); access&(policy.ReadAccess|policy.WriteAccess) != policy.ReadAccess|policy.WriteAccess {
		t.Fatalf("isolated HOME access = %d, want read and write", access)
	}
	if access := policy.ResolveFS(alpha.policy.FS, alpha.tmp); access&(policy.ReadAccess|policy.WriteAccess) != policy.ReadAccess|policy.WriteAccess {
		t.Fatalf("isolated TMPDIR access = %d, want read and write", access)
	}
	if !containsEnv(alpha.env, "TMPDIR="+alpha.tmp) {
		t.Fatalf("executor environment does not use owned TMPDIR %q", alpha.tmp)
	}
	if !pathWithin(alpha.home, owned) || !pathWithin(beta.home, owned) || !pathWithin(alpha.tmp, owned) || !pathWithin(beta.tmp, owned) {
		t.Fatalf("executor HOME/TMPDIR paths are not all beneath %q", owned)
	}
	if _, err := set.For("gamma"); !errors.Is(err, ErrExecutorLimit) {
		t.Fatalf("third executor error = %v, want ErrExecutorLimit", err)
	}

	if err := set.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := set.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := os.Stat(owned); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned root still exists or unexpected error: %v", err)
	}
	if _, err := os.Stat(scratch); err != nil {
		t.Fatalf("caller scratch root was removed: %v", err)
	}
	if _, err := set.For("after-close"); !errors.Is(err, ErrExecutorSetClosed) {
		t.Fatalf("For after close error = %v, want ErrExecutorSetClosed", err)
	}
}

func TestWindowsExecutorOptionsRejectedOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows contract")
	}
	profile := mustProfile(t, ProfileConfig{WorkspaceRoot: t.TempDir()})
	for name, option := range map[string]ExecutorSetOption{
		"restricted mode": WithWindowsSandboxMode(windows.RestrictedToken),
		"elevated mode":   WithWindowsSandboxMode(windows.Elevated),
		"state root":      WithWindowsSandboxStateRoot(`C:\ProgramData\Looprig`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1), option); err == nil {
				t.Fatal("NewExecutorSet with non-default Windows option succeeded")
			}
		})
	}

	set, err := NewExecutorSet(profile,
		WithScratchRoot(t.TempDir()),
		WithMaxExecutors(1),
		WithWindowsSandboxMode(windows.Auto),
		WithWindowsSandboxStateRoot(""),
	)
	if err != nil {
		t.Fatalf("NewExecutorSet with default Windows options: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
}

func TestExecutorSetCloseReleasesCompiledSpecOnce(t *testing.T) {
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	var releases atomic.Int32
	backend := &captureBackend{
		bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		release: func() error {
			releases.Add(1)
			return nil
		},
	}
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(backend)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.For("executor"); err != nil {
		t.Fatal(err)
	}
	if got := releases.Load(); got != 0 {
		t.Fatalf("release count before close = %d, want 0", got)
	}
	if err := set.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := set.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := releases.Load(); got != 1 {
		t.Fatalf("release count after two closes = %d, want 1", got)
	}
}

func TestExecutorSetConcurrentMemoization(t *testing.T) {
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: t.TempDir(), WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })

	const workers = 32
	got := make(chan *Executor, workers)
	errCh := make(chan error, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			executor, err := set.For("same")
			got <- executor
			errCh <- err
		}()
	}
	wg.Wait()
	close(got)
	close(errCh)
	for err := range errCh {
		if err != nil {
			t.Fatalf("For: %v", err)
		}
	}
	var first *Executor
	for executor := range got {
		if first == nil {
			first = executor
		} else if executor != first {
			t.Fatalf("concurrent For returned %p and %p", first, executor)
		}
	}
}

func TestExecutorSetPartialConstructionCleanup(t *testing.T) {
	profile := mustProfile(t, ProfileConfig{WorkspaceRoot: t.TempDir()})
	backend := &captureBackend{compileErr: errors.New("compile failed")}
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(backend)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	if _, err := set.For("broken"); err == nil {
		t.Fatal("For with failing backend succeeded")
	}
	entries, err := os.ReadDir(set.ownedRoot)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("partial construction left %d entries in owned root", len(entries))
	}

	var releases atomic.Int32
	releasable := &captureBackend{
		bits: GuaranteeEnvScrub,
		release: func() error {
			releases.Add(1)
			return nil
		},
	}
	setWithCompiledSpec, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(releasable)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = setWithCompiledSpec.Close() })
	if _, err := setWithCompiledSpec.For("missing-guarantees"); !errors.Is(err, enforce.ErrUnavailable) {
		t.Fatalf("For with missing backend guarantees error = %v, want enforce.ErrUnavailable", err)
	}
	if got := releases.Load(); got != 1 {
		t.Fatalf("release count after compiled-spec construction failure = %d, want 1", got)
	}
}

func TestExecutorSetCloseBlocksCommandsBeforeStart(t *testing.T) {
	for _, commandAccess := range []Access{Allow, Gated} {
		commandAccess := commandAccess
		name := map[Access]string{Allow: "allowed", Gated: "granted"}[commandAccess]
		t.Run(name, func(t *testing.T) {
			workspace := t.TempDir()
			backend := &blockingConfigureBackend{
				entered: make(chan struct{}),
				release: make(chan struct{}),
				bits:    GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
			}
			profile := mustProfile(t, ProfileConfig{
				WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
				HostRead: Allow, HostWrite: Deny, Network: Deny, Command: commandAccess,
			})
			set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
				withExecutorSetConfig(withBackend(backend)))
			if err != nil {
				t.Fatal(err)
			}
			executor, err := set.For("executor")
			if err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(workspace, "started")
			command := "printf started > " + marker
			runDone := make(chan error, 1)
			go func() {
				if commandAccess == Allow {
					_, _, err = executor.RunCommand(context.Background(), workspace, command)
				} else {
					now := time.Now()
					token := issueTestGrant(t, executor, now, "pre-start", command, workspace,
						"command.execute", "", "command.start.v1", command)
					_, _, err = executor.RunCommandWithGrants(context.Background(), "pre-start", workspace, command, []string{token})
				}
				runDone <- err
			}()
			<-backend.entered

			closeDone := make(chan error, 1)
			go func() { closeDone <- set.Close() }()
			select {
			case err := <-closeDone:
				close(backend.release)
				<-runDone
				t.Fatalf("Close returned before the admitted pre-start command terminated: %v", err)
			case <-time.After(100 * time.Millisecond):
			}
			close(backend.release)
			if err := <-closeDone; err != nil {
				t.Fatalf("Close: %v", err)
			}
			if err := <-runDone; !errors.Is(err, ErrExecutorClosed) && !errors.Is(err, context.Canceled) {
				t.Fatalf("pre-start run error = %v, want executor closed or context canceled", err)
			}
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("command started after Close began: marker stat = %v", err)
			}
		})
	}
}

func TestExecutorSetCloseCancelsAndWaitsForActiveCommand(t *testing.T) {
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
	executor, err := set.For("active")
	if err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(workspace, "started")
	completed := filepath.Join(workspace, "completed")
	var returned atomic.Bool
	runDone := make(chan error, 1)
	go func() {
		_, _, err := executor.RunCommand(context.Background(), workspace,
			"printf started > "+started+"; sleep 30; printf completed > "+completed)
		returned.Store(true)
		runDone <- err
	}()
	waitForPath(t, started)

	const closers = 8
	closeResults := make(chan error, closers)
	for range closers {
		go func() { closeResults <- set.Close() }()
	}
	for range closers {
		if err := <-closeResults; err != nil {
			t.Fatalf("concurrent Close: %v", err)
		}
	}
	if !returned.Load() {
		t.Fatal("Close returned before the active command's Wait completed")
	}
	if err := <-runDone; !errors.Is(err, ErrExecutorClosed) && !errors.Is(err, context.Canceled) {
		t.Fatalf("active run error = %v, want executor closed or context canceled", err)
	}
	if _, err := os.Stat(completed); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled command reached completion marker: %v", err)
	}
}

func waitForPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q", path)
}

func assertOwnerOnlyDir(t *testing.T, path string) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("%q mode = %v, want owner-only directory", path, info.Mode())
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("%q is not absolute", path)
	}
}
