package sandbox

import "os/exec"

// This file defines the internal backend seam: the shape every OS enforcement
// backend (Seatbelt on darwin, the namespace/Landlock ladder on Linux) will
// extend. The seam is deliberately narrow. A backend never runs a process and
// never assembles an environment; it only decides how a spawn is *wrapped* and
// what spawn attributes are set. The executor owns everything stateful —
// environment assembly, the working directory, running the *exec.Cmd, and the
// exit-code/error convention — so that behaviour stays identical across
// backends and only the enforcement transform varies.

// spawnSpec is a backend's compiled, stateless per-spawn transform (SPEC §7:
// "enforcement is a stateless per-spawn transform"). It holds nothing long-lived
// and is reused across every RunCommand/RunArgv on an executor. The executor
// calls exactly one of wrapShell/wrapArgv to obtain the argv to exec, then
// applies configure (if non-nil) to the assembled *exec.Cmd.
type spawnSpec struct {
	// wrapShell returns the argv that executes a shell command string. The null
	// backend returns []string{"/bin/sh", "-c", command}; an OS backend prepends
	// its sandbox launcher (e.g. sandbox-exec -p <profile> -- /bin/sh -c command).
	wrapShell func(command string) []string
	// wrapArgv returns the argv that executes a direct argv, no shell. The null
	// backend returns argv unchanged; an OS backend prepends its launcher.
	wrapArgv func(argv []string) []string
	// configure sets spawn attributes on the assembled command (SysProcAttr,
	// cgroup wiring, credentials). It may be nil, meaning no attributes are set;
	// the null backend uses nil.
	configure func(*exec.Cmd)
}

// backend compiles a Policy into a reusable spawnSpec plus the achieved isolation
// rollup: the coarse level (SPEC §6), the per-property guarantee bitmask (SPEC
// §6, §10.3), and a compilation report of what was enforced, narrowed, or left
// unenforced (SPEC §7.5). Compilation is where the soundness invariant lives:
// compiled enforcement is never wider than the policy, and every gap is recorded.
// It returns an error only when a policy cannot be compiled at all; a backend
// that merely enforces less than requested reports that via level/bits/report,
// not via err.
type backend interface {
	compile(p Policy) (spec spawnSpec, report CompileReport, level uint8, guaranteeBits uint64, err error)
}
