package sandbox

import "os/exec"

// nullBackend is the fallback backend: it applies no OS-level enforcement. It
// exists so the executor has a working, honest backend on every platform before
// the real ones land, and so a platform with no available mechanism degrades to
// "no isolation" rather than failing to construct. Its compiled spawnSpec is a
// pure passthrough — commands run exactly as a plain os/exec would — so the only
// property the executor can still guarantee is env scrubbing, which the executor
// performs itself.
type nullBackend struct{}

// newNullBackend returns the singleton-shaped null backend. It is stateless, so
// a fresh value per call is fine.
func newNullBackend() *nullBackend { return &nullBackend{} }

// compile returns a passthrough spawnSpec and the honest null posture: no OS
// enforcement (LevelNone), an empty report (nothing was enforced OR narrowed —
// the null backend does not attempt any feature, so there is nothing to record),
// and GuaranteeEnvScrub as the only guarantee bit it can set — but ONLY when the
// policy actually scrubs the environment (!Env.Inherit). Env scrubbing holds
// independently of any OS backend because the executor assembles the child
// environment from the effectiveEnvPolicy regardless of mechanism; but an Env.Inherit
// (unconfined) policy passes the whole parent environment through, so nothing is
// scrubbed and claiming EnvScrub would be dishonest — guaranteeBits is then 0.
// Every other guarantee stays false (fail-closed) because nothing else is enforced.
func (nullBackend) compile(p effectivePolicy) (spawnSpec, CompileReport, uint8, uint64, error) {
	spec := spawnSpec{
		// Pure passthrough: run the inner argv exactly as given (the executor has
		// already shell-normalized a RunCommand to /bin/sh -c command). No spawn
		// attributes, no per-spawn resources — configure and cleanup are nil.
		wrap: func(_ string, innerArgv []string) ([]string, func(*exec.Cmd), func()) {
			return innerArgv, nil, nil
		},
	}
	var bits uint64
	if !p.Env.Inherit {
		bits = GuaranteeEnvScrub
	}
	return spec, CompileReport{}, LevelNone, bits, nil
}
