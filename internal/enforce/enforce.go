package enforce

import (
	"errors"
	"os/exec"

	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
)

var ErrUnavailable = errors.New("sandbox: OS confinement unavailable")

// This file defines the internal backend seam: the shape every OS enforcement
// backend (Seatbelt on darwin, the namespace/Landlock ladder on Linux) implements.
// The seam is deliberately narrow. A backend never runs a process and
// never assembles an environment; it only decides how a spawn is *wrapped* and
// what spawn attributes are set. The executor owns everything stateful —
// environment assembly, the working directory, running the *exec.Cmd, and the
// exit-code/error convention — so that behaviour stays identical across
// backends and only the enforcement transform varies.

// Spec is a backend's compiled spawn transform. It may own immutable enforcement
// resources for its lifetime; Release idempotently relinquishes those resources.
// Mutable per-spawn state lives only in the fresh closures Wrap returns.
type Spec struct {
	// wrap turns a target spawn — the working directory and the inner argv to run
	// under confinement — into the actual argv the executor execs, plus a fresh
	// per-spawn configure hook and cleanup func.
	//
	// The executor supplies innerArgv already shell-normalized for the current
	// platform; RunArgv passes the caller's argv verbatim. A backend then:
	//   - null: returns innerArgv unchanged (finalArgv == innerArgv).
	//   - seatbelt: prepends "sandbox-exec -p <profile> --" to innerArgv.
	//   - linux: returns ["/proc/self/exe", <stage-2 sentinel>] and a configure
	//     that seals (dir, innerArgv, policy) into the stage-2 child (SysProcAttr
	//     cloneflags for rung 1, the sealed spec via env, cgroup wiring), with a
	//     cleanup that releases that spawn's transient resources.
	//
	// Returning fresh configure/cleanup closures per call is load-bearing: each
	// closes over THIS spawn's (dir, innerArgv), so concurrent spawns never share
	// per-spawn state. configure may be nil (no attributes to set) and cleanup may
	// be nil (nothing to release); null/seatbelt return nil for both and ignore
	// dir. The executor applies configure to the assembled *exec.Cmd; a configure
	// error fails before Start. If cleanup is non-nil, the executor calls it after
	// configure or spawn completes.
	Wrap func(dir string, innerArgv []string) (finalArgv []string, configure func(*exec.Cmd) error, cleanup func())

	// Release relinquishes immutable resources owned by the compiled spec. It may
	// be nil when the spec owns none and must be safe to call idempotently.
	Release func() error
}

// backend compiles a policy.Effective into a reusable Spec plus the achieved isolation
// rollup: the coarse level (SPEC §6), the per-property guarantee bitmask (SPEC
// and a compilation report of what was enforced, narrowed, or left
// unenforced (SPEC §7.5). Compilation is where the soundness invariant lives:
// compiled enforcement is never wider than the policy, and every gap is recorded.
// It returns an error when a policy cannot be compiled at all; a backend
// that merely enforces less than requested reports that via level/bits/report,
// not via err. The direct backend accepts only profile.Unconfined.
type Backend interface {
	Compile(p policy.Effective) (spec Spec, report profile.CompileReport, level uint8, guaranteeBits uint64, err error)
}
