//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"syscall"
)

// linuxBackend is the Linux OS-enforcement backend (SPEC §7.2). It compiles a
// policy into a spawnSpec whose wrap re-execs THIS binary (/proc/self/exe) into
// a stage-2 helper (Init -> runStage2) that becomes the confined target.
//
// This is the stage-2 DISPATCH skeleton (Task 11): the re-exec plumbing and the
// sealed-spec pipe are complete and load-bearing, but NO OS confinement is
// applied yet — Landlock (Task 12), namespaces/cgroup (Task 13), and seccomp
// (Task 14) fill in runStage2's confinement stub and this backend's report. It
// therefore honestly reports LevelNone here, claiming only the env-scrub
// guarantee (which the stage-2 execve genuinely upholds via the scrubbed
// spec.Env), and an empty CompileReport.
type linuxBackend struct {
	// Intentionally minimal for the Task 11 stub. Task 12 extends the constructor
	// to carry the probed rung/linuxCaps so compile can select real enforcement.
}

// newLinuxBackend constructs the Linux backend. It takes nothing today (the
// stage-2 dispatch needs no probed capability); Task 12 will widen it to accept
// the probed rung/caps once real confinement is compiled.
func newLinuxBackend() *linuxBackend { return &linuxBackend{} }

// compile builds the re-exec spawnSpec. For this task it applies no confinement,
// so it reports LevelNone and — only when the policy actually scrubs the
// environment (!Env.Inherit) — GuaranteeEnvScrub, since the stage-2 child
// execve's the target with the scrubbed spec.Env. Every other guarantee stays
// clear (fail-closed). The CompileReport is empty until Tasks 12/13/14 record
// what they enforce. It never errors.
func (linuxBackend) compile(p Policy) (spawnSpec, CompileReport, uint8, uint64, error) {
	var bits uint64
	if !p.Env.Inherit {
		bits = GuaranteeEnvScrub
	}
	spec := spawnSpec{wrap: linuxWrap}
	return spec, CompileReport{}, LevelNone, bits, nil
}

// linuxWrap is the per-spawn transform: it re-execs /proc/self/exe and returns a
// fresh configure/cleanup pair that seals THIS spawn's spec into the stage-2
// child over a private pipe. Fresh closures per call are load-bearing — each
// closes over its own (dir, innerArgv) and its own pipe, so concurrent spawns
// never share per-spawn state or a file descriptor.
func linuxWrap(dir string, innerArgv []string) ([]string, func(*exec.Cmd), func()) {
	// Re-exec THIS binary (/proc/self/exe, NOT os.Args[0]): the kernel resolves it
	// even for a deleted binary, and it is the exact image whose Init() dispatches
	// the stage-2 child.
	finalArgv := []string{"/proc/self/exe"}

	// pipeR/pipeW are this spawn's private spec pipe, captured so cleanup can close
	// both ends after the spawn completes.
	var pipeR, pipeW *os.File

	configure := func(cmd *exec.Cmd) {
		// Capture the TARGET environment BEFORE adding the dispatch sentinel, so the
		// execve'd target never observes LRSANDBOX_STAGE2. The executor has already
		// set cmd.Env to the scrubbed child environment at this point.
		targetEnv := append([]string(nil), cmd.Env...)
		spec := stage2Spec{Dir: dir, Argv: innerArgv, Env: targetEnv}

		r, w, err := os.Pipe()
		if err != nil {
			// Fail closed: with no spec pipe the child's fd 3 is absent, its decode
			// fails, and runStage2 exits non-zero rather than running the target.
			// Still add the sentinel so the child dispatches into that fail-closed
			// path instead of running the re-exec'd program as itself.
			cmd.Env = append(cmd.Env, stage2SentinelEnv+"="+stage2SentinelValue)
			cmd.SysProcAttr = &syscall.SysProcAttr{}
			return
		}
		pipeR, pipeW = r, w

		// The read end becomes fd 3 in the child (ExtraFiles[0], since 0/1/2 are
		// stdio) — stage2SpecFD.
		cmd.ExtraFiles = append(cmd.ExtraFiles, r)
		// Add the dispatch sentinel to the CHILD's env only (after capturing the
		// target env above), so the child's Init() runs runStage2.
		cmd.Env = append(cmd.Env, stage2SentinelEnv+"="+stage2SentinelValue)
		// Empty SysProcAttr for now; rung-1 Cloneflags (user/mount/net namespaces)
		// come in Task 13.
		cmd.SysProcAttr = &syscall.SysProcAttr{}

		// Encode the spec on a goroutine: the gob payload is small (fits the pipe
		// buffer), so this completes without blocking even before the child reads,
		// but the goroutine keeps the spawn non-blocking regardless. Best-effort:
		// on an encode failure the child's decode fails closed.
		go func() {
			_ = encodeStage2Spec(w, spec)
			_ = w.Close() // signal EOF so the child's gob decode terminates
		}()
	}

	cleanup := func() {
		// Release this spawn's pipe ends after the spawn completes. The child holds
		// its own dup of the read end; closing the parent's copies here frees the
		// fds. w may already be closed by the encode goroutine — a double close is a
		// harmless best-effort no-op.
		if pipeR != nil {
			_ = pipeR.Close()
		}
		if pipeW != nil {
			_ = pipeW.Close()
		}
	}

	return finalArgv, configure, cleanup
}
