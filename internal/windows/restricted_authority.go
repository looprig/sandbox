package windows

import (
	"errors"
	"reflect"
	"sync"

	"github.com/looprig/sandbox/internal/policy"
)

// This file holds the restricted tier's per-executor base-lease authority.
// It names no Windows API, so it builds on every platform and its state
// machine is tested on every platform (restricted_authority_test.go); the
// backend that hands it out (backend_windows.go) is Windows-only.

type restrictedPreparedLease struct {
	sid     SID
	journal *RestrictedJournal
	release func() error
}

// restrictedGrantAuthority is one executor's base lease, carried on that
// executor's compiled spec as enforce.Spec.GrantAuthority. The executor
// returns it to this backend unchanged with every grant compile, so a grant
// always borrows the SID, journal and ACL projections of the lease it was
// issued under — never another executor's.
//
// Borrows keep the lease alive: a transient grant spec's token still names
// the base SID and relies on the base projections, so releasing the base
// spec while a grant spec is outstanding only marks the authority retiring;
// the lease itself is released by whichever of the two lets go last, exactly
// once. A retiring authority lends nothing new.
type restrictedGrantAuthority struct {
	mu       sync.Mutex
	base     policy.Effective
	sid      SID
	journal  *RestrictedJournal
	release  func() error
	borrows  int
	retiring bool
	released bool

	releaseErr error
}

func newRestrictedGrantAuthority(base policy.Effective, lease restrictedPreparedLease) *restrictedGrantAuthority {
	return &restrictedGrantAuthority{base: policy.Clone(base), sid: lease.sid, journal: lease.journal, release: lease.release}
}

// borrow lends the base lease to one grant compile. base must be the policy
// the authority was compiled from (compared on normalised clones, as the
// elevated tier's authority does), which refuses an authority presented on
// behalf of a different executor.
func (authority *restrictedGrantAuthority) borrow(base policy.Effective) (SID, *RestrictedJournal, func() error, error) {
	if authority == nil {
		return SID{}, nil, nil, errors.New("sandbox: restricted base lease is unavailable")
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	if authority.retiring || authority.released || authority.journal == nil {
		return SID{}, nil, nil, errors.New("sandbox: restricted base lease is unavailable: it is released or retiring")
	}
	if !reflect.DeepEqual(authority.base, policy.Clone(base)) {
		return SID{}, nil, nil, errors.New("sandbox: restricted base lease belongs to another executor")
	}
	authority.borrows++
	var once sync.Once
	var releaseErr error
	giveBack := func() error {
		once.Do(func() {
			authority.mu.Lock()
			authority.borrows--
			releaseErr = authority.releaseIfIdleLocked()
			authority.mu.Unlock()
		})
		return releaseErr
	}
	return authority.sid, authority.journal, giveBack, nil
}

// retire is the base spec's Release: idempotent, and it releases the lease
// now only when no grant spec still borrows it.
func (authority *restrictedGrantAuthority) retire() error {
	if authority == nil {
		return nil
	}
	authority.mu.Lock()
	defer authority.mu.Unlock()
	authority.retiring = true
	return authority.releaseIfIdleLocked()
}

// releaseIfIdleLocked releases the lease once it is retiring and unborrowed,
// exactly once, and reports that one release's result to every later caller
// that reaches it. The lease release runs under mu so a concurrent borrow can
// never observe a half-released lease.
func (authority *restrictedGrantAuthority) releaseIfIdleLocked() error {
	if !authority.retiring || authority.borrows != 0 {
		return nil
	}
	if !authority.released {
		authority.released = true
		if authority.release != nil {
			authority.releaseErr = authority.release()
		}
	}
	return authority.releaseErr
}
