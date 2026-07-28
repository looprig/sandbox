package exec

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/looprig/sandbox/pkg/network"
)

type reservingProxyBackend struct {
	captureBackend
	reservations atomic.Int32
	releases     atomic.Int32
	proxy        *network.Proxy
	releaseErr   error
	specReleased atomic.Bool
}

func (backend *reservingProxyBackend) ReserveEgressProxy(route network.Route) (*network.Proxy, func() error, error) {
	backend.reservations.Add(1)
	proxy, err := network.NewProxy(route)
	if err != nil {
		return nil, nil, err
	}
	backend.proxy = proxy
	return proxy, func() error {
		backend.releases.Add(1)
		if !backend.specReleased.Load() && len(backend.policies) != 0 {
			return errors.New("proxy reservation released before compiled specs")
		}
		return backend.releaseErr
	}, nil
}

func TestExecutorSetSharesBackendReservedProxyAndReleasesItLast(t *testing.T) {
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Gated, Command: Allow,
	})
	route, err := NewDirectEgressRoute()
	if err != nil {
		t.Fatal(err)
	}
	backend := &reservingProxyBackend{}
	backend.bits = GuaranteeWriteBoundary | GuaranteeNetworkBoundary |
		GuaranteeAddressNetwork | GuaranteeTargetNetwork | GuaranteeEnvScrub
	var specReleases atomic.Int32
	backend.releaseForCompile = func(int) func() error {
		return func() error {
			if specReleases.Add(1) == 2 {
				backend.specReleased.Store(true)
			}
			return nil
		}
	}
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(2),
		WithEgressRoute(route), withExecutorSetConfig(withBackend(backend)))
	if err != nil {
		t.Fatal(err)
	}
	first, err := set.For("first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := set.For("second")
	if err != nil {
		t.Fatal(err)
	}
	if first.proxy == nil || first.proxy != second.proxy {
		t.Fatal("backend-reserved proxy was not shared by the executor set")
	}
	if first.proxyOwned || second.proxyOwned {
		t.Fatal("individual executor claimed ownership of the shared proxy")
	}
	if got := backend.reservations.Load(); got != 1 {
		t.Fatalf("proxy reservations = %d, want 1", got)
	}
	if err := set.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := specReleases.Load(); got != 2 {
		t.Fatalf("compiled spec releases = %d, want 2", got)
	}
	if got := backend.releases.Load(); got != 1 {
		t.Fatalf("proxy reservation releases = %d, want 1", got)
	}
	if err := set.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if got := backend.releases.Load(); got != 1 {
		t.Fatalf("proxy reservation releases after second close = %d, want 1", got)
	}
}

func TestBackendReservedProxyReleasedOnceWhenCompilationFails(t *testing.T) {
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Gated, Command: Allow,
	})
	route, err := NewDirectEgressRoute()
	if err != nil {
		t.Fatal(err)
	}
	compileErr := errors.New("compile failed")
	releaseErr := errors.New("proxy reservation release failed")
	backend := &reservingProxyBackend{}
	backend.compileErr = compileErr
	backend.releaseErr = releaseErr
	backend.compileErrorRelease = func() error {
		backend.specReleased.Store(true)
		return nil
	}
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		WithEgressRoute(route), withExecutorSetConfig(withBackend(backend)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.For("broken"); !errors.Is(err, compileErr) || !errors.Is(err, releaseErr) {
		t.Fatalf("For error = %v, want compile and reservation release failures", err)
	}
	if got := backend.reservations.Load(); got != 1 {
		t.Fatalf("proxy reservations = %d, want 1", got)
	}
	if got := backend.releases.Load(); got != 1 {
		t.Fatalf("proxy reservation releases after compile failure = %d, want 1", got)
	}
	if err := set.Close(); !errors.Is(err, releaseErr) {
		t.Fatalf("Close after compile failure = %v, want memoized reservation release failure", err)
	}
	if got := backend.releases.Load(); got != 1 {
		t.Fatalf("proxy reservation releases after Close = %d, want 1", got)
	}
}

func TestLaterCompilationFailureDoesNotRevokeSharedProxyFromExistingExecutor(t *testing.T) {
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Gated, Command: Allow,
	})
	route, err := NewDirectEgressRoute()
	if err != nil {
		t.Fatal(err)
	}
	compileErr := errors.New("second compile failed")
	backend := &reservingProxyBackend{}
	backend.bits = GuaranteeWriteBoundary | GuaranteeNetworkBoundary |
		GuaranteeAddressNetwork | GuaranteeTargetNetwork | GuaranteeEnvScrub
	backend.compileErr = compileErr
	backend.compileErrAfter = 2
	backend.compileErrorRelease = func() error { return nil }
	backend.releaseForCompile = func(int) func() error {
		return func() error {
			backend.specReleased.Store(true)
			return nil
		}
	}
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(2),
		WithEgressRoute(route), withExecutorSetConfig(withBackend(backend)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := set.For("healthy"); err != nil {
		t.Fatal(err)
	}
	if _, err := set.For("broken"); !errors.Is(err, compileErr) {
		t.Fatalf("second For error = %v, want compile failure", err)
	}
	if got := backend.releases.Load(); got != 0 {
		t.Fatalf("shared proxy released while an executor still owns the set: %d", got)
	}
	if err := set.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := backend.releases.Load(); got != 1 {
		t.Fatalf("proxy reservation releases = %d, want 1", got)
	}
}
