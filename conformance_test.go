package sandbox

// This file drives the reusable sandboxtest conformance suite from INSIDE the
// sandbox package, for two reasons an external consumer cannot serve:
//
//  1. The null backend (honest LevelNone) is reachable only through the
//     unexported withBackend seam, so the "no OS enforcement" conformance target
//     — the branch that proves the suite accepts a backend which HONESTLY reports
//     no WriteBoundary — must be constructed here. (The external-consumer proof
//     against the live and external backends lives in sandboxtest/sandboxtest_test.go.)
//  2. sandboxtest mirrors the guarantee-bit and level constants from this
//     package's stdlib seam (so it need not import sandbox, which keeps this very
//     file cycle-free). TestSandboxtestSeamConstantsMatch is the drift guard that
//     pins the mirror to the originals.
//
// No build tag: it compiles on every platform (excluded from `go build`, compiled
// by `go test -c` on darwin) and runs on the host. The null target runs
// everywhere; the live target is whatever platformBackend selects here (rung 2).

import (
	"testing"

	"github.com/looprig/sandbox/sandboxtest"
)

// TestSandboxtestAgainstNullBackend runs the conformance suite against the null
// backend: LevelNone, env scrub the only guarantee, writes unconfined. The suite
// must accept it precisely BECAUSE it reports no WriteBoundary — the honest
// no-op posture. Pinned via the unexported withBackend seam.
func TestSandboxtestAgainstNullBackend(t *testing.T) {
	sandboxtest.RunSuite(t, "null", func(t *testing.T, ws string) sandboxtest.SUT {
		e, err := newExecutorForEffectivePolicy(PolicyFor(Write, ws), withBackend(newNullBackend()))
		if err != nil {
			t.Fatalf("NewExecutor(null): %v", err)
		}
		return e
	})
}

// TestSandboxtestAgainstLiveBackend runs the suite against the platform-selected
// backend (rung 2 on this host). This mirrors the external-consumer proof but
// runs in-package so the null and live targets are exercised together. Init() is
// called by the package TestMain (reexec_main_test.go), satisfying the re-exec
// backend's gate.
func TestSandboxtestAgainstLiveBackend(t *testing.T) {
	sandboxtest.RunSuite(t, "live", func(t *testing.T, ws string) sandboxtest.SUT {
		e, err := newExecutorForEffectivePolicy(PolicyFor(Write, ws))
		if err != nil {
			t.Fatalf("NewExecutor(live): %v", err)
		}
		return e
	})
}

// TestSandboxtestSeamConstantsMatch is the drift guard: sandboxtest mirrors the
// guarantee-bit and level constants (so it stays import-free of this package);
// this test fails the moment a mirrored value diverges from the original, which
// would silently misgate every suite assertion.
func TestSandboxtestSeamConstantsMatch(t *testing.T) {
	t.Parallel()
	bitPairs := []struct {
		name         string
		orig, mirror uint64
	}{
		{"ProcessBoundary", GuaranteeProcessBoundary, sandboxtest.GuaranteeProcessBoundary},
		{"WriteBoundary", GuaranteeWriteBoundary, sandboxtest.GuaranteeWriteBoundary},
		{"ReadBoundary", GuaranteeReadBoundary, sandboxtest.GuaranteeReadBoundary},
		{"EnvScrub", GuaranteeEnvScrub, sandboxtest.GuaranteeEnvScrub},
		{"NetworkBoundary", GuaranteeNetworkBoundary, sandboxtest.GuaranteeNetworkBoundary},
		{"AddressNetwork", GuaranteeAddressNetwork, sandboxtest.GuaranteeAddressNetwork},
		{"ResourceLimits", GuaranteeResourceLimits, sandboxtest.GuaranteeResourceLimits},
	}
	for _, p := range bitPairs {
		if p.orig != p.mirror {
			t.Errorf("guarantee bit %s drifted: sandbox=%#b sandboxtest=%#b", p.name, p.orig, p.mirror)
		}
	}

	levelPairs := []struct {
		name         string
		orig, mirror uint8
	}{
		{"LevelNone", LevelNone, sandboxtest.LevelNone},
		{"LevelDegraded", LevelDegraded, sandboxtest.LevelDegraded},
		{"LevelFull", LevelFull, sandboxtest.LevelFull},
	}
	for _, p := range levelPairs {
		if p.orig != p.mirror {
			t.Errorf("level %s drifted: sandbox=%d sandboxtest=%d", p.name, p.orig, p.mirror)
		}
	}
}
