//go:build linux

package sandbox

import (
	"github.com/looprig/sandbox/internal/enforce"
)

// platformBackend selects the OS enforcement backend on Linux by PROBING the host
// for the strongest achievable rung (SPEC §7.2) and returning the matching backend:
//
//   - rung 1 → the full-isolation re-exec backend (newLinuxBackendRung1):
//     user+mount+pid+net namespaces + bind-mount view + in-netns nftables, then
//     Landlock + seccomp + cgroup (Task 13, SPEC §7.2 rung 1). Selected only when
//     the probe confirmed a usable userns+mountns+netns; it reports LevelFull.
//   - rung 2 → the re-exec Landlock+seccomp backend (newLinuxBackend): FS by
//     enumerated Landlock allowlist + seccomp + TCP-port net, no namespaces. Sound
//     (never wider than policy — it enforces less than rung 1 could) and honestly
//     reported as LevelDegraded. The probe keeps the selection honest: a host that
//     cannot enforce even rung 2 does NOT get a re-exec backend claiming confinement.
//   - rung none → enforce.ErrUnavailable. Sandboxed execution never falls through
//     to a direct backend.
//
// Init() gate (fail-closed): the re-exec Linux backend requires the consumer to
// have called sandbox.Init() as the first line of main() (SPEC §6) — otherwise a
// spawned stage-2 child, not caught by Init()'s dispatch, would run the consumer's
// own main() instead of the confinement helper (a footgun: it would run the target
// UNCONFINED, or the capability probe would mis-report). When a re-exec backend is
// selected but Init() was not called, construction fails with ErrInitNotCalled
// rather than silently building an executor that cannot actually confine.
//
// A test may still pin a backend through the unexported withBackend seam, which
// bypasses this selector entirely (and the package TestMain calls Init(), so the
// gate is satisfied for tests that do reach this path).
func platformBackend() (enforce.Backend, error) {
	return selectLinuxBackend(probeLinuxCaps().selectRung(), initWasCalled.Load())
}

// selectLinuxBackend is the pure selection logic behind platformBackend, split out
// so the rung×Init-called matrix is unit-testable without touching the process
// globals. A re-exec rung (1/2) requires initCalled; rung none fails closed.
func selectLinuxBackend(r rung, initCalled bool) (enforce.Backend, error) {
	switch r {
	case rungOne:
		if !initCalled {
			return nil, ErrInitNotCalled
		}
		// Task 13: the full-isolation tier — namespaces + mount view + nftables,
		// then Landlock + seccomp + cgroup. Selected only when the probe confirmed a
		// usable userns+mountns+netns (selectRung -> rungOne).
		return newLinuxBackendRung1(), nil
	case rungTwo:
		if !initCalled {
			return nil, ErrInitNotCalled
		}
		return newLinuxBackend(), nil
	default: // rungNone
		return nil, enforce.ErrUnavailable
	}
}
