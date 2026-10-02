package windows

import (
	"errors"
	"sync"
	"testing"

	"github.com/looprig/sandbox/internal/policy"
)

// These tests pin restrictedGrantAuthority's lease lifetime on every
// platform. The contract is "one release per lease, by whichever of the base
// spec and its last outstanding grant spec lets go last": a base Release
// with no borrow outstanding releases at once, a base Release with one
// outstanding only marks the authority retiring, and the borrow's give-back
// then performs the release. The second Windows CI run's two
// backend_windows_test.go failures ("base releases = 0, want 1" and "final
// releases ... want each lease released exactly once") were not this
// contract failing: each of those tests compiled one extra probe grant spec
// and never released it, so the borrow it held correctly kept the base lease
// alive past the base Release.

type authorityHarness struct {
	authority *restrictedGrantAuthority
	base      policy.Effective
	releases  int
}

func newAuthorityHarness(t *testing.T, workspace string, releaseErr error) *authorityHarness {
	t.Helper()
	sid, err := ExecutorSID("authority-installation", workspace)
	if err != nil {
		t.Fatal(err)
	}
	harness := &authorityHarness{base: policy.Effective{Workspace: workspace}}
	harness.authority = newRestrictedGrantAuthority(harness.base, restrictedPreparedLease{
		sid:     sid,
		journal: &RestrictedJournal{},
		release: func() error { harness.releases++; return releaseErr },
	})
	return harness
}

func TestRestrictedAuthorityRetireWithoutBorrowReleasesOnce(t *testing.T) {
	harness := newAuthorityHarness(t, `C:\one`, nil)
	if err := harness.authority.retire(); err != nil {
		t.Fatal(err)
	}
	if harness.releases != 1 {
		t.Fatalf("releases after an unborrowed retire = %d, want 1", harness.releases)
	}
	if err := harness.authority.retire(); err != nil || harness.releases != 1 {
		t.Fatalf("second retire = %v with %d releases, want nil and still 1", err, harness.releases)
	}
	if _, _, _, err := harness.authority.borrow(harness.base); err == nil {
		t.Fatal("a released authority lent its lease")
	}
}

func TestRestrictedAuthorityOutstandingBorrowDefersReleaseToGiveBack(t *testing.T) {
	harness := newAuthorityHarness(t, `C:\one`, nil)
	_, _, giveBack, err := harness.authority.borrow(harness.base)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.authority.retire(); err != nil {
		t.Fatal(err)
	}
	if harness.releases != 0 {
		t.Fatalf("retire with a borrow outstanding released the lease (%d)", harness.releases)
	}
	if _, _, _, err := harness.authority.borrow(harness.base); err == nil {
		t.Fatal("a retiring authority lent its lease")
	}
	if err := giveBack(); err != nil {
		t.Fatal(err)
	}
	if harness.releases != 1 {
		t.Fatalf("releases after the last give-back = %d, want 1", harness.releases)
	}
	if err := giveBack(); err != nil || harness.releases != 1 {
		t.Fatalf("repeated give-back = %v with %d releases, want nil and still 1", err, harness.releases)
	}
}

func TestRestrictedAuthorityReturnedBorrowLeavesBaseReleasable(t *testing.T) {
	harness := newAuthorityHarness(t, `C:\one`, nil)
	for round := 0; round < 3; round++ {
		_, _, giveBack, err := harness.authority.borrow(harness.base)
		if err != nil {
			t.Fatalf("borrow %d: %v", round, err)
		}
		if err := giveBack(); err != nil {
			t.Fatal(err)
		}
		if harness.releases != 0 {
			t.Fatalf("a give-back before retire released the lease (%d)", harness.releases)
		}
	}
	if err := harness.authority.retire(); err != nil {
		t.Fatal(err)
	}
	if harness.releases != 1 {
		t.Fatalf("releases after retire with every borrow returned = %d, want 1", harness.releases)
	}
}

func TestRestrictedAuthorityRefusesAnotherExecutorsBase(t *testing.T) {
	first := newAuthorityHarness(t, `C:\one`, nil)
	if _, _, _, err := first.authority.borrow(policy.Effective{Workspace: `C:\two`}); err == nil {
		t.Fatal("an authority lent its lease for another executor's base policy")
	}
	// The refused borrow must not have counted: retire releases at once.
	if err := first.authority.retire(); err != nil || first.releases != 1 {
		t.Fatalf("retire after a refused borrow = %v with %d releases, want nil and 1", err, first.releases)
	}
}

func TestRestrictedAuthorityReportsTheOneReleaseErrorToEveryCaller(t *testing.T) {
	injected := errors.New("injected lease release failure")
	harness := newAuthorityHarness(t, `C:\one`, injected)
	_, _, giveBack, err := harness.authority.borrow(harness.base)
	if err != nil {
		t.Fatal(err)
	}
	if err := harness.authority.retire(); err != nil {
		t.Fatalf("retire with a borrow outstanding = %v, want nil (nothing released yet)", err)
	}
	if err := giveBack(); !errors.Is(err, injected) {
		t.Fatalf("give-back that released = %v, want the release error", err)
	}
	if err := harness.authority.retire(); !errors.Is(err, injected) || harness.releases != 1 {
		t.Fatalf("later retire = %v with %d releases, want the same error and one release", err, harness.releases)
	}
}

func TestRestrictedAuthorityConcurrentBorrowsAndRetireReleaseExactlyOnce(t *testing.T) {
	var mu sync.Mutex
	releases := 0
	sid, err := ExecutorSID("authority-installation", "concurrent")
	if err != nil {
		t.Fatal(err)
	}
	base := policy.Effective{Workspace: `C:\concurrent`}
	authority := newRestrictedGrantAuthority(base, restrictedPreparedLease{
		sid: sid, journal: &RestrictedJournal{},
		release: func() error { mu.Lock(); releases++; mu.Unlock(); return nil },
	})
	var wg sync.WaitGroup
	for worker := 0; worker < 16; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 64; i++ {
				_, _, giveBack, err := authority.borrow(base)
				if err != nil {
					return // retiring: no new borrows, by contract
				}
				_ = giveBack()
			}
		}()
	}
	if err := authority.retire(); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	mu.Lock()
	defer mu.Unlock()
	if releases != 1 {
		t.Fatalf("releases = %d, want exactly 1 however borrows and retire interleave", releases)
	}
}
