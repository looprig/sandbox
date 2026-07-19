//go:build linux

package sandbox

import (
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
)

// initWasCalled records that Init() ran on the NORMAL path (not a re-exec'd
// stage-2/probe child, which os.Exit before reaching it). platformBackend (linux)
// reads it to fail construction closed when a re-exec backend would be selected
// but the consumer never called Init() — otherwise a stage-2 child would run the
// consumer's main() unconfined. It is atomic because, although Init() is meant to
// run as the first line of main() (before any goroutine), a misuse that races it
// against NewExecutor must not be a data race.
var initWasCalled atomic.Bool

// ErrInitNotCalled is returned by NewExecutor on Linux when a
// re-exec enforcement backend (rung 1/2) would be selected but sandbox.Init() was
// not called first (SPEC §6). It is a leaf sentinel so consumers can errors.Is it.
var ErrInitNotCalled = errors.New("sandbox: Init() was not called — call sandbox.Init() as the very first line of main() before constructing a sandboxed executor on Linux")

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

// stage2Rung values tag the confinement tier a stage-2 spec was compiled for
// (SPEC §7.2). runStage2 branches on it: rung 1 additionally applies the
// bind-mount view + in-netns nftables before the shared Landlock/seccomp axes; a
// zero/unset value is treated as rung 2 (no namespaces), the pre-Task-13 shape,
// so an old-shaped spec can never accidentally trigger the rung-1 mount path.
const (
	stage2RungTwo uint8 = 2 // Landlock + seccomp, no namespaces
	stage2RungOne uint8 = 1 // user+mount+pid+net namespaces + mount view + nftables
)

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
	// Seccomp requests the rung-2 seccomp-BPF filter (Task 12b, SPEC §7.2). When
	// true the stage-2 child installs buildSeccompFilter() AFTER Landlock and
	// BEFORE chdir/execve (installSeccompFilter), so the target inherits it across
	// the execve and dangerous syscalls (UDP/MPTCP sockets, ptrace, io_uring) are
	// soft-denied (EACCES). A bool is gob-encodable; the rung-2 backend sets it.
	Seccomp bool
	// NetConfined requests the rung-2 Landlock TCP-port allowlist (Task 12c, SPEC
	// §7.2, §5.2). When true the stage-2 child calls applyLandlockNet(NetTCPPorts)
	// AFTER seccomp and BEFORE chdir/execve, confining TCP connect to NetTCPPorts
	// (and denying all other TCP) — inherited across the execve. It is false only
	// for open/unconfined egress (effectiveNetPolicy.Open), where TCP is left unrestricted.
	NetConfined bool
	// NetTCPPorts are the TCP ports the target may connect to (Task 12c). An empty
	// slice with NetConfined denies ALL TCP connect.
	// []uint16 is gob-encodable; the rung-2 backend fills it from the effectiveNetPolicy.
	NetTCPPorts []uint16
	// Rung tags the confinement tier (Task 13, SPEC §7.2): stage2RungOne applies
	// the namespaces + mount view + nftables below; stage2RungTwo (or the zero
	// value) is the no-namespace rung-2 path. A uint8 is gob-encodable.
	Rung uint8
	// MountView is the rung-1 bind-mount view (Task 13a/b, SPEC §7.2 rung 1, §7.5):
	// rw/ro/ro-remask binds plus empty-mask targets (fixed denies + glob matches),
	// enumerated at spawn and applied by the stage-2 child (applyMountView) BEFORE
	// Landlock. Empty for a rung-2 spawn. MountViewSpec is a concrete gob type.
	MountView MountViewSpec
	// NftRules is the rung-1 in-netns nftables plan (Task 13c, SPEC §5.2, §5.4):
	// address-scoped egress with the metadata hard-deny, installed by the stage-2
	// child (applyNftRules) inside the netns BEFORE Landlock. NftSpec.Confined is
	// false for open egress. Empty for a rung-2 spawn. NftSpec is a concrete gob type.
	NftRules NftSpec
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
	// Neither sentinel recognized: this is a normal process. Record that Init ran
	// (the re-exec children above os.Exit and never reach here), so platformBackend
	// can require it before handing out a re-exec enforcement backend. Init is
	// otherwise a no-op on the normal path.
	initWasCalled.Store(true)
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
	//   - Task 12a: install the Landlock FS allowlist (rung 2). The ruleset
	//     restricts this process AND everything it execve's, so a rung-2 spawn is
	//     FS-confined the moment the target starts.
	//   - Task 12b: install the seccomp-BPF filter (rung 2) AFTER Landlock and
	//     BEFORE chdir/execve. installSeccompFilter locks the OS thread and never
	//     unlocks it, so the filter thread is the execve thread and the target
	//     inherits the filter (and no_new_privs) across execve.
	//   - Task 12c: apply the Landlock TCP-port allowlist (rung-2 network boundary)
	//     AFTER seccomp, confining TCP connect to the policy's ports (and denying
	//     all other TCP) — stacked with the FS ruleset, inherited across execve.
	//   - Task 13: for a rung-1 spawn, build the bind-mount view (mount namespace)
	//     and install the in-netns nftables address filter (net namespace) HERE,
	//     BEFORE Landlock — both fail closed. The child was already clone'd into the
	//     user+mount+pid(+net) namespaces by the parent's SysProcAttr; this is the
	//     in-namespace setup. Rung 2 leaves spec.Rung != stage2RungOne and skips it.
	if spec.Rung == stage2RungOne {
		if err := applyMountView(spec.MountView); err != nil {
			return err
		}
		if err := applyNftRules(spec.NftRules); err != nil {
			return err
		}
	}

	if err := applyLandlockRules(spec.FSRules); err != nil {
		return &stage2Error{Op: "landlock", Err: err}
	}

	// Seccomp is applied AFTER Landlock: both survive execve, so the order does
	// not change what the target inherits; seccomp is placed last so the pinned
	// filter thread proceeds directly to chdir/execve below on the SAME goroutine
	// (runtime.LockOSThread), guaranteeing filter-thread == execve-thread.
	if spec.Seccomp {
		if err := installSeccompFilter(); err != nil {
			return &stage2Error{Op: "seccomp", Err: err}
		}
	}

	// Task 12c: apply the Landlock TCP-port allowlist (rung-2 network boundary)
	// AFTER seccomp and BEFORE chdir/execve. RestrictNet clears the FS handled-set,
	// so it stacks with the Landlock FS ruleset above (both enforced), and it is
	// inherited across the execve. seccomp does not block any Landlock syscall, so
	// applying it here (on the pinned seccomp thread) is safe. A non-nil error
	// fails CLOSED so the target never runs with unrestricted egress.
	if spec.NetConfined {
		if err := applyLandlockNet(spec.NetTCPPorts); err != nil {
			return &stage2Error{Op: "landlock-net", Err: err}
		}
	}

	if err := os.Chdir(spec.Dir); err != nil {
		return &stage2Error{Op: "chdir " + spec.Dir, Err: err}
	}

	// resolveFS the executable path. syscall.Exec is a raw execve: unlike the
	// exec.Command path that null/seatbelt use, it does NOT search PATH for a bare
	// argv[0]. Without this, RunArgv([]string{"rg", ...}) would run on null/seatbelt
	// but fail here — an unfaithful drop-in. resolveFS a name with no slash against
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
