//go:build linux

package linux

import (
	"github.com/looprig/sandbox/internal/enforce"
)

// platformBackend selects the OS enforcement backend on Linux by PROBING the host
// for the strongest achievable Rung (SPEC §7.2) and returning the matching backend:
//
//   - Rung 1 → the full-isolation re-exec backend (NewBackendRung1):
//     user+mount+pid+net namespaces + bind-mount view + in-Netns nftables, then
//     Landlock + Seccomp + cgroup (Task 13, SPEC §7.2 Rung 1). Selected only when
//     the probe confirmed a usable Userns+Mountns+Netns; it reports profile.LevelFull.
//   - Rung 2 → the re-exec Landlock+Seccomp backend (NewBackend): FS by
//     enumerated Landlock allowlist + Seccomp + TCP-port net, no namespaces. Sound
//     (never wider than policy — it enforces less than Rung 1 could) and honestly
//     reported as profile.LevelDegraded. The probe keeps the selection honest: a host that
//     cannot enforce even Rung 2 does NOT get a re-exec backend claiming confinement.
//   - Rung none → enforce.ErrUnavailable. Sandboxed execution never falls through
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
// PlatformBackend selects the strongest Linux enforcement backend this host and
// process can actually provide: it probes kernel capabilities, picks a Rung, and
// refuses to hand back a re-exec backend when Init() never ran.
func PlatformBackend() (enforce.Backend, error) {
	return SelectBackend(ProbeCaps().SelectRung(), initWasCalled.Load())
}

// SelectBackend is the pure selection logic behind platformBackend, split out
// so the Rung×Init-called matrix is unit-testable without touching the process
// globals. A re-exec Rung (1/2) requires initCalled; Rung none fails closed.
func SelectBackend(r Rung, initCalled bool) (enforce.Backend, error) {
	switch r {
	case RungOne:
		if !initCalled {
			return nil, ErrInitNotCalled
		}
		// Task 13: the full-isolation tier — namespaces + mount view + nftables,
		// then Landlock + Seccomp + cgroup. Selected only when the probe confirmed a
		// usable Userns+Mountns+Netns (SelectRung -> RungOne).
		return NewBackendRung1(), nil
	case RungTwo:
		if !initCalled {
			return nil, ErrInitNotCalled
		}
		return NewBackend(), nil
	default: // RungNone
		return nil, enforce.ErrUnavailable
	}
}
