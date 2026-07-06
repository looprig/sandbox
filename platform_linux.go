//go:build linux

package sandbox

// platformBackend selects the OS enforcement backend on Linux by PROBING the host
// for the strongest achievable rung (SPEC §7.2) and returning the matching backend:
//
//   - rung 1 or rung 2 → the re-exec Linux backend (linuxBackend). Rung 1's
//     namespace/nftables enforcement lands in Task 13; until then a rung-1-capable
//     host runs rung-2 confinement (Landlock FS + seccomp + TCP-port net), which is
//     SOUND (never wider than the policy — it merely enforces less than rung 1
//     could) and is honestly reported as LevelDegraded. The probe is what keeps the
//     selection honest: a host that cannot enforce even rung 2 does NOT get a
//     re-exec backend claiming confinement.
//   - rung none → the null backend (honest LevelNone): no Landlock/seccomp
//     available, so no OS enforcement is claimed rather than a re-exec that would
//     confine nothing.
//
// Init() gate (fail-closed): the re-exec Linux backend requires the consumer to
// have called sandbox.Init() as the first line of main() (SPEC §6) — otherwise a
// spawned stage-2 child, not caught by Init()'s dispatch, would run the consumer's
// own main() instead of the confinement helper (a footgun: it would run the target
// UNCONFINED, or the capability probe would mis-report). When a re-exec backend is
// selected but Init() was not called, construction fails with ErrInitNotCalled
// rather than silently building an executor that cannot actually confine. The null
// backend needs no re-exec, so it is exempt.
//
// A test may still pin a backend through the unexported withBackend seam, which
// bypasses this selector entirely (and the package TestMain calls Init(), so the
// gate is satisfied for tests that do reach this path).
func platformBackend() (backend, error) {
	return selectLinuxBackend(probeLinuxCaps().selectRung(), initWasCalled.Load())
}

// selectLinuxBackend is the pure selection logic behind platformBackend, split out
// so the rung×Init-called matrix is unit-testable without touching the process
// globals. A re-exec rung (1/2) requires initCalled; rung none returns the null
// backend and needs no Init().
func selectLinuxBackend(r rung, initCalled bool) (backend, error) {
	switch r {
	case rungOne, rungTwo:
		if !initCalled {
			return nil, ErrInitNotCalled
		}
		return newLinuxBackend(), nil
	default: // rungNone
		return newNullBackend(), nil
	}
}
