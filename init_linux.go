//go:build linux

package sandbox

import (
	"encoding/gob"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// stage2SentinelEnv is the reserved environment variable that flags a re-exec'd
// stage-2 helper child (SPEC §6, §7.2). The Linux backend sets it on the child's
// environment so the child's Init() dispatches into runStage2 before main()/
// testing.M runs. It is captured OUT of the target environment before being set
// (see backend_linux.go), so the execve'd target never observes it — a normal
// harness process, where it is unset, is entirely unaffected.
const stage2SentinelEnv = "LRSANDBOX_STAGE2"

// stage2SentinelValue is the single recognized sentinel value. Any other value
// of stage2SentinelEnv is treated as unset (Init returns, normal path), so a
// stray environment variable can never make a normal process re-exec.
const stage2SentinelValue = "1"

// stage2SpecFD is the fixed file descriptor on which the parent passes the
// gob-encoded stage2Spec to the child. The parent appends the pipe's read end to
// cmd.ExtraFiles, and since fds 0/1/2 are stdio, ExtraFiles[0] becomes fd 3 in
// the child.
const stage2SpecFD = 3

// stage2FailExitCode is the child exit code used when stage-2 setup fails before
// execve. It is non-zero so a fail-closed child is always distinguishable from a
// clean run, and 126 matches the shell convention for "found but not executed".
const stage2FailExitCode = 126

// stage2Spec is the sealed spawn description the parent hands the stage-2 child
// over a private pipe (SPEC §7.2). It carries exactly what the child needs to
// become the confined target: the working directory to chdir into, the target
// argv to execve, and the already-scrubbed environment the target should see.
//
// Confinement extension point (Tasks 12/13/14): the FS rules (Landlock ruleset),
// network scoping (netns/nftables), seccomp filter parameters, and cgroup path
// are added here as additional fields. runStage2 applies them (below) after
// decoding this spec and BEFORE chdir/execve. Keep new fields gob-encodable
// (exported, concrete types) since this crosses the re-exec via encoding/gob.
type stage2Spec struct {
	Dir  string   // working directory to chdir into before exec
	Argv []string // the target argv to execve (already shell-normalized by the executor)
	Env  []string // the scrubbed child environment the TARGET should see (KEY=VALUE)
	// FSRules is the compiled, spawn-time-enumerated Landlock FS allowlist (Task
	// 12a, SPEC §7.2 rung 2). The parent enumerates the policy's FS axis against
	// the live filesystem at spawn (enumerateFSRules) and the stage-2 child
	// rebuilds a go-landlock ruleset from it (applyLandlockRules) and restricts
	// itself before chdir/execve. fsRule is a concrete, gob-encodable type.
	FSRules []fsRule
	// --- Further confinement fields (namespaces/seccomp/net) added by Tasks
	// 13/14 go here. ---
}

// stage2Error is a typed, fail-closed stage-2 setup failure (SPEC §7.2). Every
// step before the final execve — opening the spec fd, decoding the spec,
// chdir — returns one of these on failure so runStage2 can never fall through to
// run the normal program; it wraps the underlying cause for errors.As/Unwrap.
type stage2Error struct {
	Op  string // the failing step, e.g. "decode spec", "chdir", "exec"
	Err error  // the wrapped underlying error
}

func (e *stage2Error) Error() string { return "sandbox: stage2: " + e.Op + ": " + e.Err.Error() }
func (e *stage2Error) Unwrap() error { return e.Err }

// Init is THE re-exec dispatch entry point on Linux (SPEC §6, §7.2). Consumers
// call it as the very first line of main(), before any goroutine, file
// descriptor, or thread state is established. It inspects the reserved re-exec
// sentinels and dispatches exactly one of three ways:
//
//   - stage2SentinelEnv == stage2SentinelValue: this process is a re-exec'd
//     stage-2 helper. runStage2 reads the sealed spec, (later) applies
//     confinement, chdirs, and execve's the target; it never returns on success.
//   - probeSentinelEnv set to a recognized namespace-probe mode: this is a
//     throwaway capability-probe child. Run the one privileged op and os.Exit
//     with its result (0 effective / non-zero denied).
//   - neither set (or any unrecognized value): the normal path. Init returns
//     immediately and is a no-op, so a stray environment variable can never make
//     a normal process exit or exec.
//
// Unifying both re-exec children under this single exported dispatcher (rather
// than a package init()) is deliberate: SPEC §6 makes Init the re-exec entry
// point, and a package init() that re-execs is the footgun moby/reexec avoids
// (it fires in every importer). One dispatcher, one place to audit.
func Init() {
	if os.Getenv(stage2SentinelEnv) == stage2SentinelValue {
		runStage2() // never returns on success
		return      // defense in depth: runStage2 only returns after it has already exited
	}
	switch os.Getenv(probeSentinelEnv) {
	case nsProbeMount:
		os.Exit(runNamespaceProbeChild(nsProbeMount))
	case nsProbeNet:
		os.Exit(runNamespaceProbeChild(nsProbeNet))
	}
	// Neither sentinel recognized: normal process, Init is a no-op.
}

// runStage2 is the stage-2 child body. It performs the setup that must succeed
// before the target runs and, on ANY failure, writes a short diagnostic to
// stderr and exits non-zero — it NEVER falls through to run the normal program
// (fail closed). On success it execve's the target and never returns.
func runStage2() {
	if err := stage2Setup(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(stage2FailExitCode)
	}
	// stage2Setup only returns on error; on success it execve's the target and
	// this line is unreachable. Guard anyway so a future refactor can never leak
	// a stage-2 process into the normal program.
	os.Exit(stage2FailExitCode)
}

// stage2Setup reads the sealed spec from the stage-2 pipe fd, (STUB) applies
// confinement, chdirs into the working directory, and execve's the target. It
// returns a typed error on every pre-exec failure so runStage2 fails closed;
// syscall.Exec only returns when exec itself fails, so a nil return is
// impossible on the success path.
func stage2Setup() error {
	f := os.NewFile(stage2SpecFD, "lrsandbox-stage2-spec")
	if f == nil {
		return &stage2Error{Op: "open spec fd", Err: syscall.EBADF}
	}
	spec, err := decodeStage2Spec(f)
	// The spec is fully read; close the read end best-effort (its data is already
	// decoded, and the process is about to execve regardless).
	_ = f.Close()
	if err != nil {
		return err
	}
	if len(spec.Argv) == 0 {
		return &stage2Error{Op: "spec argv", Err: errEmptyStage2Argv}
	}

	// Apply confinement HERE, before chdir/execve, from the confinement fields on
	// the sealed spec. Each step fails CLOSED via a stage2Error so a confinement
	// failure aborts the spawn rather than running the target unconfined.
	//
	//   - Task 12a (this task): install the Landlock FS allowlist (rung 2). The
	//     ruleset restricts this process AND everything it execve's, so a rung-2
	//     spawn is FS-confined the moment the target starts.
	//   - Tasks 13/14 (later): join namespaces + cgroup (rung 1) and install the
	//     seccomp filter here too.
	if err := applyLandlockRules(spec.FSRules); err != nil {
		return &stage2Error{Op: "landlock", Err: err}
	}

	if err := os.Chdir(spec.Dir); err != nil {
		return &stage2Error{Op: "chdir " + spec.Dir, Err: err}
	}

	// Resolve the executable path. syscall.Exec is a raw execve: unlike the
	// exec.Command path that null/seatbelt use, it does NOT search PATH for a bare
	// argv[0]. Without this, RunArgv([]string{"rg", ...}) would run on null/seatbelt
	// but fail here — an unfaithful drop-in. Resolve a name with no slash against
	// the TARGET's PATH (spec.Env, not the parent's), so lookups match the confined
	// environment. argv is passed through unchanged so the target still sees its
	// invoked name in argv[0] (execve's path and argv[0] are independent).
	execPath := spec.Argv[0]
	if !strings.Contains(execPath, "/") {
		resolved, lerr := lookPathIn(execPath, spec.Env)
		if lerr != nil {
			return &stage2Error{Op: "lookpath " + execPath, Err: lerr}
		}
		execPath = resolved
	}
	// execve the target with the scrubbed spec.Env (which never contains the
	// dispatch sentinel). Returns only on failure.
	if err := syscall.Exec(execPath, spec.Argv, spec.Env); err != nil {
		return &stage2Error{Op: "exec " + spec.Argv[0], Err: err}
	}
	return nil // unreachable: a successful syscall.Exec replaces this process
}

// errNoPathInEnv is the leaf error when a bare argv[0] must be PATH-resolved but
// the target environment carries no PATH.
var errNoPathInEnv = fmt.Errorf("no PATH in target environment")

// lookPathIn resolves a bare executable name against the PATH found in env
// (KEY=VALUE entries), returning the first entry that exists and is executable.
// It mirrors exec.LookPath but searches the TARGET's PATH (env) rather than the
// stage-2 process's own, so resolution matches the confined environment. It does
// not fall back to the ambient PATH: a name that the target's PATH cannot resolve
// fails closed rather than resolving against the harness's environment.
func lookPathIn(name string, env []string) (string, error) {
	var pathList string
	found := false
	for _, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			pathList = v
			found = true
			// Keep scanning: last PATH= wins, matching how the kernel/libc take the
			// final duplicate assignment.
		}
	}
	if !found {
		return "", errNoPathInEnv
	}
	for _, dir := range filepath.SplitList(pathList) {
		if dir == "" {
			dir = "." // POSIX: an empty PATH element means the current directory
		}
		candidate := filepath.Join(dir, name)
		if isExecutableFile(candidate) {
			return candidate, nil
		}
	}
	return "", syscall.ENOENT
}

// isExecutableFile reports whether path is a regular file with an execute bit
// set — the condition execve requires. A directory or a non-executable file is
// skipped, matching exec.LookPath's behaviour.
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode().Perm()&0o111 != 0
}

// errEmptyStage2Argv is the leaf guard for a decoded spec with no argv — a
// malformed spec that must fail the child closed rather than execve nothing.
var errEmptyStage2Argv = fmt.Errorf("empty argv")

// encodeStage2Spec gob-encodes a stage2Spec to w (the parent's pipe write end).
// It is the symmetric counterpart to decodeStage2Spec; the parent runs it on a
// goroutine so a full pipe buffer can never block the spawn. It returns the
// encoder error so callers can decide (the parent treats it best-effort: a
// failed encode leaves the child's decode to fail closed).
func encodeStage2Spec(w io.Writer, spec stage2Spec) error {
	return gob.NewEncoder(w).Encode(spec)
}

// decodeStage2Spec gob-decodes a stage2Spec from the spec pipe. A decode failure
// (truncated pipe, garbage, bad fd) returns a typed stage2Error so the caller
// fails closed. It is a small seam so the codec is unit-testable without a real
// re-exec.
func decodeStage2Spec(f *os.File) (stage2Spec, error) {
	var spec stage2Spec
	if err := gob.NewDecoder(f).Decode(&spec); err != nil {
		return stage2Spec{}, &stage2Error{Op: "decode spec", Err: err}
	}
	return spec, nil
}
