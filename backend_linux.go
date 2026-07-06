//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
)

// linuxBackend is the Linux OS-enforcement backend (SPEC §7.2). It compiles a
// policy into a spawnSpec whose wrap re-execs THIS binary (/proc/self/exe) into
// a stage-2 helper (Init -> runStage2) that becomes the confined target.
//
// Task 12a wires the RUNG-2 filesystem axis: compile distils the policy's FS
// entries into a compiledFS, the per-spawn wrap enumerates that into a flat
// Landlock allowlist against the live filesystem (snapshot semantics), and the
// stage-2 child applies the ruleset before execve. Rung 1 (namespaces/cgroup,
// Task 13), seccomp (Task 14), and network scoping (Task 12c) still fill in
// later; until then the backend reports LevelDegraded with the write-boundary +
// read-deny + env-scrub guarantees a rung-2 FS confinement genuinely upholds.
type linuxBackend struct {
	// Intentionally minimal: rung-2 FS confinement needs only the policy at
	// compile time. Task 13 will widen the constructor to carry the probed
	// rung/linuxCaps so compile can select namespaces vs Landlock-only.
}

// newLinuxBackend constructs the Linux backend. It takes nothing today — rung-2
// FS confinement is compiled from the policy alone; Task 13 will widen it to
// accept the probed rung/caps once namespace enforcement is compiled.
func newLinuxBackend() *linuxBackend { return &linuxBackend{} }

// compile builds the re-exec spawnSpec and applies rung-2 FS confinement. It
// distils the policy's FS axis into a compiledFS (literal allows + literal
// denies; globs dropped), which the per-spawn wrap enumerates into a Landlock
// allowlist. It reports LevelDegraded (rung 2 enforces the write boundary and
// fixed-path denies but cannot express glob denies or address-scoped network for
// subprocesses, §7.5) with GuaranteeWriteBoundary, GuaranteeReadDenies (when the
// policy carries an enforceable fixed-path deny), and GuaranteeEnvScrub (when
// !Env.Inherit). The CompileReport records what was enforced vs narrowed vs
// unenforced. It never errors — a policy that compiles to a narrower ruleset is
// reported via level/bits/report, not via err.
func (linuxBackend) compile(p Policy) (spawnSpec, CompileReport, uint8, uint64, error) {
	cfs := compileFSPolicy(p.FS)

	bits := GuaranteeWriteBoundary
	if cfs.hasLiteralDeny() {
		bits |= GuaranteeReadDenies
	}
	if !p.Env.Inherit {
		bits |= GuaranteeEnvScrub
	}

	spec := spawnSpec{wrap: linuxWrapFS(cfs)}
	return spec, fsCompileReport(p, cfs), LevelDegraded, bits, nil
}

// fsCompileReport records how the rung-2 FS compilation treated each policy
// feature (SPEC §7.5): the write boundary and fixed-path denies are enforced;
// read-only carveouts are narrowed (snapshot semantics on their writable root);
// glob denies are unenforced (inexpressible in Landlock's additive model, left
// to the in-process ReadGuard for native tools). It also notes that nonexistent
// allow paths are dropped at spawn (fail secure).
func fsCompileReport(p Policy, cfs compiledFS) CompileReport {
	entries := []ReportEntry{{
		Feature: "write-boundary",
		Status:  "enforced",
		Detail:  "writes confined to policy writable roots via Landlock (rung 2, ABI v4)",
	}}
	if cfs.hasLiteralDeny() {
		entries = append(entries, ReportEntry{
			Feature: "fixed-path-deny",
			Status:  "enforced",
			Detail:  "fixed-path secret deny-reads enforced by enumerated sibling allows, snapshot at spawn (§7.5)",
		})
	}
	if cfs.hasCarveout() {
		entries = append(entries, ReportEntry{
			Feature: "carveout",
			Status:  "narrowed",
			Detail:  "read-only carveouts (.git/.looprig) enforced by enumerating a writable root's children at spawn; the root itself is not granted, so files created at the root after spawn are inaccessible (snapshot semantics, §7.5 — errs narrow)",
		})
	}
	if policyHasGlobDeny(p) {
		entries = append(entries, ReportEntry{
			Feature: "glob-deny",
			Status:  "unenforced",
			Detail:  "glob deny-reads (e.g. **/.env*) are not expressible in Landlock's additive model at rung 2; the in-process ReadGuard still enforces them for native tools — subprocess reads are the gap (§7.5)",
		})
	}
	entries = append(entries, ReportEntry{
		Feature: "allow-paths",
		Status:  "narrowed",
		Detail:  "allow paths are stat'd at spawn; a nonexistent path or a symlink out of an enumerated tree is dropped rather than granted (fail secure)",
	})
	return CompileReport{Entries: entries}
}

// policyHasGlobDeny reports whether the policy carries any glob DENY entry, which
// rung 2 cannot enforce for subprocesses (recorded unenforced in the report).
func policyHasGlobDeny(p Policy) bool {
	for _, e := range p.FS {
		if e.Access == DenyAccess && strings.ContainsAny(e.Path, globMeta) {
			return true
		}
	}
	return false
}

// linuxWrapFS returns the per-spawn transform for a compiled FS policy: it
// re-execs /proc/self/exe and, on each spawn, enumerates cfs into a fresh
// Landlock allowlist (a snapshot of the live filesystem) that it seals into the
// stage-2 child. Fresh closures per call are load-bearing — each closes over its
// own (dir, innerArgv), its own enumerated rules, and its own pipe, so concurrent
// spawns never share per-spawn state or a file descriptor.
func linuxWrapFS(cfs compiledFS) func(string, []string) ([]string, func(*exec.Cmd), func()) {
	return func(dir string, innerArgv []string) ([]string, func(*exec.Cmd), func()) {
		return linuxWrap(cfs, dir, innerArgv)
	}
}

// linuxWrap is the per-spawn transform body. It re-execs /proc/self/exe and
// returns a fresh configure/cleanup pair that enumerates the FS rules at spawn
// and seals THIS spawn's spec into the stage-2 child over a private pipe.
func linuxWrap(cfs compiledFS, dir string, innerArgv []string) ([]string, func(*exec.Cmd), func()) {
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
		// Enumerate the FS allowlist NOW (per spawn) so it is a fresh snapshot of
		// the live filesystem: a secret that exists when the command starts is
		// carved out; a file the command later creates is not (§7.5 snapshot
		// semantics). The stage-2 child rebuilds the Landlock ruleset from this.
		fsRules := enumerateFSRules(cfs)
		spec := stage2Spec{Dir: dir, Argv: innerArgv, Env: targetEnv, FSRules: fsRules}

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
