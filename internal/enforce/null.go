package enforce

import (
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
	"os/exec"
)

// nullBackend is the direct-execution backend for an explicitly acknowledged
// profile.Unconfined profile. It is never a fallback for Sandboxed execution.
type nullBackend struct{}

// NewNull returns the singleton-shaped null backend. It is stateless, so
// a fresh value per call is fine.
func NewNull() *nullBackend { return &nullBackend{} }

// compile rejects every Sandboxed policy. For profile.Unconfined it returns a direct
// passthrough Spec and profile.LevelNone; environment scrubbing is reported only if
// a future valid direct profile actually requests it.
func (nullBackend) Compile(p policy.Effective) (Spec, profile.CompileReport, uint8, uint64, error) {
	if p.Isolation != profile.Unconfined {
		return Spec{}, profile.CompileReport{}, profile.LevelNone, 0, ErrUnavailable
	}
	spec := Spec{
		// Pure passthrough: run the inner argv exactly as given (the executor has
		// already shell-normalized a RunCommand for the platform). No spawn
		// attributes, no per-spawn resources — configure and cleanup are nil.
		Wrap: func(_ string, innerArgv []string) ([]string, func(*exec.Cmd) error, func()) {
			return innerArgv, nil, nil
		},
		Release: nil,
	}
	var bits uint64
	if !p.Env.Inherit {
		bits = profile.GuaranteeEnvScrub
	}
	return spec, profile.CompileReport{}, profile.LevelNone, bits, nil
}
