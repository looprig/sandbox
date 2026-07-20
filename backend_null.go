package sandbox

import "os/exec"

// nullBackend is the direct-execution backend for an explicitly acknowledged
// Unconfined profile. It is never a fallback for Sandboxed execution.
type nullBackend struct{}

// newNullBackend returns the singleton-shaped null backend. It is stateless, so
// a fresh value per call is fine.
func newNullBackend() *nullBackend { return &nullBackend{} }

// compile rejects every Sandboxed policy. For Unconfined it returns a direct
// passthrough spawnSpec and LevelNone; environment scrubbing is reported only if
// a future valid direct profile actually requests it.
func (nullBackend) compile(p effectivePolicy) (spawnSpec, CompileReport, uint8, uint64, error) {
	if p.Isolation != Unconfined {
		return spawnSpec{}, CompileReport{}, LevelNone, 0, ErrSandboxUnavailable
	}
	spec := spawnSpec{
		// Pure passthrough: run the inner argv exactly as given (the executor has
		// already shell-normalized a RunCommand to /bin/sh -c command). No spawn
		// attributes, no per-spawn resources — configure and cleanup are nil.
		wrap: func(_ string, innerArgv []string) ([]string, func(*exec.Cmd) error, func()) {
			return innerArgv, nil, nil
		},
	}
	var bits uint64
	if !p.Env.Inherit {
		bits = GuaranteeEnvScrub
	}
	return spec, CompileReport{}, LevelNone, bits, nil
}
