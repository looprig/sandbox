package sandbox

import (
	"errors"
	"os/exec"
)

var ErrSandboxUnavailable = errors.New("sandbox: OS confinement unavailable")

// This file defines the internal backend seam: the shape every OS enforcement
// backend (Seatbelt on darwin, the namespace/Landlock ladder on Linux) implements.
// The seam is deliberately narrow. A backend never runs a process and
// never assembles an environment; it only decides how a spawn is *wrapped* and
// what spawn attributes are set. The executor owns everything stateful —
// environment assembly, the working directory, running the *exec.Cmd, and the
// exit-code/error convention — so that behaviour stays identical across
// backends and only the enforcement transform varies.

// spawnSpec is a backend's compiled per-spawn transform (SPEC §7: "enforcement
// is a stateless per-spawn transform"). It holds nothing long-lived and is
// reused across every RunCommand/RunArgv on an executor; the PER-SPAWN state
// lives in the fresh closures its wrap func returns, not on the spec.
type spawnSpec struct {
	// wrap turns a target spawn — the working directory and the inner argv to run
	// under confinement — into the actual argv the executor execs, plus a fresh
	// per-spawn configure hook and cleanup func.
	//
	// The executor supplies innerArgv already shell-normalized: RunCommand passes
	// []string{"/bin/sh", "-c", command} (running a shell command is /bin/sh -c on
	// every backend), RunArgv passes the caller's argv verbatim. A backend then:
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
	// dir. The executor applies configure to the assembled *exec.Cmd and, if
	// cleanup is non-nil, calls it after the spawn completes.
	wrap func(dir string, innerArgv []string) (finalArgv []string, configure func(*exec.Cmd), cleanup func())
}

// backend compiles a effectivePolicy into a reusable spawnSpec plus the achieved isolation
// rollup: the coarse level (SPEC §6), the per-property guarantee bitmask (SPEC
// §6, §10.3), and a compilation report of what was enforced, narrowed, or left
// unenforced (SPEC §7.5). Compilation is where the soundness invariant lives:
// compiled enforcement is never wider than the policy, and every gap is recorded.
// It returns an error when a policy cannot be compiled at all; a backend
// that merely enforces less than requested reports that via level/bits/report,
// not via err. The direct backend accepts only Unconfined.
type backend interface {
	compile(p effectivePolicy) (spec spawnSpec, report CompileReport, level uint8, guaranteeBits uint64, err error)
}
