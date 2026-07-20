package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

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
		withExecutorSetExecOptions(withBackend(backend)),
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
	if access := resolveFS(alpha.policy.FS, alpha.home); access&(readFSAccess|writeFSAccess) != readFSAccess|writeFSAccess {
		t.Fatalf("isolated HOME access = %d, want read and write", access)
	}
	if access := resolveFS(alpha.policy.FS, alpha.tmp); access&(readFSAccess|writeFSAccess) != readFSAccess|writeFSAccess {
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

func TestExecutorSetConcurrentMemoization(t *testing.T) {
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: t.TempDir(), WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetExecOptions(withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub})))
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
		withExecutorSetExecOptions(withBackend(backend)))
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
