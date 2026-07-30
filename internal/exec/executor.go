package exec

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/platform"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/network"
	"io"
	"net"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/looprig/sandbox/pkg/profile"
)

// defaultGrantTTL is the lifetime of a minted grant token when WithGrantTTL is
// not supplied (15 minutes).
const defaultGrantTTL = 15 * time.Minute

// spawnWaitGrace bounds cmd.WaitDelay (Go 1.20+): the time Wait spends, AFTER
// the context is cancelled, waiting for a child that fails to actually exit
// despite cmd.Cancel (tree.terminate, a process-group SIGKILL) having already
// been invoked. It is a backstop only — a Kill-after-grace safety net for a
// Cancel that somehow didn't work — not the mechanism that reaps an orphaned
// grandchild descendant that forked away from the immediate child and kept
// its own copy of the stdout/stderr pipe open: run's own tree.terminateAndWait
// (below) unconditionally SIGKILLs and blocks until the ENTIRE process group is
// confirmed gone before it ever reads the drained output, so that case never
// depends on this grace period or on WaitDelay's own I/O-pipe management (which
// does not apply here regardless, since run wires stdout/stderr through its own
// os.Pipe rather than letting exec.Cmd own them). The value trades a brief
// extra-kill window against promptness for the narrow "Cancel didn't work"
// case.
const spawnWaitGrace = time.Second

// Init is defined per-platform (init_linux.go / init_other.go): it is THE
// re-exec dispatch entry point (SPEC §6). Consumers MUST call it as the very
// first line of main(), before any goroutine, file descriptor, or thread state
// is established:
//
//	func main() {
//		sandbox.Init()
//		// ... rest of program
//	}
//
// On non-Linux platforms it is a no-op. On Linux it inspects the reserved
// re-exec sentinels and dispatches a stage-2 helper or namespace-probe child
// (moby/reexec pattern, §7.2); in a normal process it returns immediately.

// executorConfig is the private, concrete input to internal construction.
// Public ownership configuration belongs to ExecutorSetOption; there is no
// direct-executor option surface.
type executorConfig struct {
	grantTTL    time.Duration
	clock       func() time.Time // nil means default time.Now
	backend     enforce.Backend  // nil means select via platformBackend (test seam)
	platform    platform.Options
	lifecycle   *executorLifecycle
	quarantine  quarantineSink
	processTree processTreeFactory
}

// egressProxyBackend is an optional capability implemented by a backend that
// must reserve the loopback proxy endpoint as part of its platform boundary.
// The returned proxy is shared by every Executor in one ExecutorSet. release
// relinquishes any reservation state that remains after Proxy.Close and must be
// safe to call exactly once.
//
// Backends without this capability retain the legacy behavior: ExecutorSet
// creates and owns one network.Proxy per memoized Executor.
type egressProxyBackend interface {
	ReserveEgressProxy(network.Route) (*network.Proxy, func() error, error)
}

// Executor compiles a policy.Effective once via the platform backend and then runs
// commands under the resulting reusable spawn transform (SPEC §6, §7). It
// holds the compiled policy, the chosen backend, its enforce.Spec, the compilation
// report, the achieved level and guarantee bits, and the assembled child
// environment — everything a spawn needs, precomputed at construction.
type Executor struct {
	profile *Profile
	// settings is the snapshot of profile's normalized authority, taken once at
	// construction because a Profile is immutable. It is the read path for every
	// authority check on the spawn hot path.
	settings      profile.Settings
	policy        policy.Effective
	backend       enforce.Backend
	spec          enforce.Spec
	report        CompileReport
	level         uint8
	guaranteeBits uint64
	env           []string // assembled child environment, KEY=VALUE (SPEC §5.5)

	// Grant wiring (SPEC §9.2). The HMAC key is per-executor and never serialized.
	// Tokens also bind the immutable profile, route identity, and guarantee bits.
	// usedGrants provides one-shot replay protection; Close revokes the key.
	grantKey            []byte
	clock               func() time.Time
	grantTTL            time.Duration
	routeFingerprint    string
	proxy               *network.Proxy
	proxyRelease        func() error
	proxyOwned          bool
	proxyReleaseOnce    sync.Once
	proxyReleaseErr     error
	home                string
	tmp                 string
	grantMu             sync.Mutex
	usedGrants          map[[32]byte]int64 // grant ID -> signed expiry Unix milliseconds
	retainedGrantPaths  retainedGrantPaths
	grantExpiryTimer    *time.Timer
	grantExpiryGen      uint64
	grantExpiryRealtime bool
	grantExpiryWG       sync.WaitGroup
	closed              bool
	lifecycle           *executorLifecycle
	quarantine          quarantineSink
	processTree         processTreeFactory
	specReleaseOnce     sync.Once
	specReleaseErr      error
}

// snapshot is the compiled state a single spawn needs.
type snapshot struct {
	spec   enforce.Spec
	env    []string
	policy policy.Effective
}

// newExecutor is the internal direct-construction seam for focused unit tests.
// Production ownership always enters through ExecutorSet.
func newExecutor(prof *Profile, config executorConfig) (*Executor, error) {
	p, err := policy.Compile(prof)
	if err != nil {
		return nil, err
	}
	return newExecutorFromEffective(prof, p, config)
}

func newExecutorFromEffective(prof *Profile, p policy.Effective, config executorConfig) (*Executor, error) {
	// The profile is immutable, so its normalized authority is snapshotted once
	// here and read from the Executor thereafter. A nil profile — only reachable
	// from the unexported unit-test seam — yields the zero Settings, whose every
	// Access is Deny and whose required guarantees are empty.
	var settings profile.Settings
	if prof != nil {
		settings = prof.Settings()
	}
	// Backend selection: platform.Backend(config.platform) for production; a test may pin one via
	// the unexported withBackend seam so executor UNIT tests stay backend-independent.
	// platformBackend can fail (an unsupported platform, or — on Linux — a re-exec
	// backend selected without Init() having been called), which fails construction
	// closed rather than building an executor that would spawn incorrectly.
	b, err := selectExecutorBackend(prof, settings, config)
	if err != nil {
		return nil, err
	}
	spec, report, level, bits, err := b.Compile(p)
	if err != nil {
		return nil, errors.Join(err, releaseSpec(spec))
	}
	if prof != nil {
		missing := settings.RequiredGuarantees &^ bits
		if missing != 0 {
			compileErr := fmt.Errorf("%w: backend missing required guarantees %#x", enforce.ErrUnavailable, missing)
			return nil, errors.Join(compileErr, releaseSpec(spec))
		}
	}

	key, err := newGrantKey()
	if err != nil {
		return nil, errors.Join(fmt.Errorf("sandbox: grant key: %w", err), releaseSpec(spec))
	}

	lifecycle := config.lifecycle
	if lifecycle == nil {
		lifecycle = newExecutorLifecycle()
	}
	quarantine := config.quarantine
	if quarantine == nil {
		quarantine = newAsyncQuarantineReaper()
	}
	processTree := config.processTree
	if processTree == nil {
		processTree = func(cmd *exec.Cmd, options processTreeOptions) (processTreeBoundary, error) {
			return newProcessTree(cmd, options)
		}
	}
	return &Executor{
		profile:             prof,
		settings:            settings,
		policy:              p,
		backend:             b,
		spec:                spec,
		report:              report,
		level:               level,
		guaranteeBits:       bits,
		env:                 assembleEnv(p),
		grantKey:            key,
		clock:               clockOrDefault(config.clock),
		grantTTL:            ttlOrDefault(config.grantTTL),
		routeFingerprint:    defaultRouteIdentity,
		usedGrants:          make(map[[32]byte]int64),
		retainedGrantPaths:  make(retainedGrantPaths),
		grantExpiryRealtime: config.clock == nil,
		lifecycle:           lifecycle,
		quarantine:          quarantine,
		processTree:         processTree,
	}, nil
}

// selectExecutorBackend resolves the backend without compiling a policy.
// ExecutorSet calls it once and pins the result so all keyed executors share
// the same backend instance. The direct unit-test seam may still enter
// newExecutorFromEffective with no preselected backend.
func selectExecutorBackend(prof *Profile, settings profile.Settings, config executorConfig) (enforce.Backend, error) {
	if config.backend != nil {
		return config.backend, nil
	}
	if prof != nil && settings.Isolation == Unconfined {
		return enforce.NewNull(), nil
	}
	return platform.Backend(config.platform)
}

// clockOrDefault resolves the executor clock, defaulting to time.Now.
func clockOrDefault(c func() time.Time) func() time.Time {
	if c == nil {
		return time.Now
	}
	return c
}

// ttlOrDefault resolves the grant TTL, defaulting to defaultGrantTTL when unset.
func ttlOrDefault(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultGrantTTL
	}
	return d
}

// RunCommand runs a shell command string in dir under the compiled policy (SPEC
// It wraps the command via the backend's enforce.Spec, sets the working
// directory and the assembled environment, applies any spawn attributes, and
// runs to completion capturing combined stdout+stderr.
//
// Convention: if the process RAN to a normal exit — even a non-zero one — the
// return is (output, exitCode, nil) carrying the real exit code. A non-nil error
// signals that the process did NOT complete normally: a spawn/setup failure
// (missing dir, binary not found), a signal kill (e.g. SIGKILL), or a context
// timeout/cancel. Callers MUST key on err (not the numeric code) to detect
// "didn't run / was killed": the exit code is -1 in every such case, so -1 does
// not uniquely mean "didn't spawn" — it also arises from signal death and
// context cancellation.
func (e *Executor) RunCommand(ctx context.Context, dir, command string) ([]byte, int, error) {
	lease, err := e.beginExecution(ctx)
	if err != nil {
		return nil, -1, err
	}
	leaseTransferred := false
	defer func() {
		if !leaseTransferred {
			lease.finish()
		}
	}()
	if err := e.commandAccess(); err != nil {
		return nil, -1, err
	}
	s, err := e.resolve()
	if err != nil {
		return nil, -1, err
	}
	s, executionID, err := e.prepareAllowedRoute(s)
	if err != nil {
		return nil, -1, err
	}
	var releases []func() error
	if executionID != "" {
		releases = append(releases, func() error { e.proxy.Release(executionID); return nil })
	}
	leaseTransferred = true
	return e.run(lease, dir, enforce.ShellArgv(command), s, nil, releases...)
}

// resolve returns the immutable compiled snapshot for one spawn.
func (e *Executor) resolve() (snapshot, error) {
	s := snapshot{spec: e.spec, env: e.env, policy: e.policy}
	return s, e.resolveErr(nil)
}

// resolveErr prefers an upstream compile error, else fails closed if the spawn
// spec was never compiled (nil transform), else nil.
func (e *Executor) resolveErr(compileErr error) error {
	if compileErr != nil {
		return compileErr
	}
	if e.spec.Wrap == nil && e.spec.Launch == nil {
		return errors.New("sandbox: executor spawn spec not compiled")
	}
	return nil
}

// RunArgv runs a direct argv in dir under the compiled policy, with no shell
// interposed — for tools that already build argv safely. Same
// exit-code/error convention as RunCommand: key on err, not the numeric code, to
// detect a process that did not complete normally (spawn failure, signal kill,
// or context cancellation all report code -1).
func (e *Executor) RunArgv(ctx context.Context, dir string, argv []string) ([]byte, int, error) {
	lease, err := e.beginExecution(ctx)
	if err != nil {
		return nil, -1, err
	}
	leaseTransferred := false
	defer func() {
		if !leaseTransferred {
			lease.finish()
		}
	}()
	if err := e.commandAccess(); err != nil {
		return nil, -1, err
	}
	s, err := e.resolve()
	if err != nil {
		return nil, -1, err
	}
	s, executionID, err := e.prepareAllowedRoute(s)
	if err != nil {
		return nil, -1, err
	}
	var releases []func() error
	if executionID != "" {
		releases = append(releases, func() error { e.proxy.Release(executionID); return nil })
	}
	leaseTransferred = true
	return e.run(lease, dir, argv, s, nil, releases...)
}

func (e *Executor) prepareAllowedRoute(s snapshot) (snapshot, string, error) {
	if e.profile == nil || e.settings.Network != Allow || e.proxy == nil {
		return s, "", nil
	}
	random := make([]byte, 18)
	if _, err := rand.Read(random); err != nil {
		return snapshot{}, "", fmt.Errorf("sandbox: route execution identity: %w", err)
	}
	executionID := "route-" + base64.RawURLEncoding.EncodeToString(random)
	credential, err := e.proxy.AuthorizeAll(executionID)
	if err != nil {
		return snapshot{}, "", err
	}
	pol := policy.Clone(s.policy)
	proxyURL := e.proxy.URL(executionID, credential)
	applyChildProxyEnv(pol.Env.Set, proxyURL)
	s.policy = pol
	s.env = assembleEnv(pol)
	return s, executionID, nil
}

// run is the shared execution path for RunCommand, RunArgv, and
// RunCommandWithGrants. It hands the backend the (dir, innerArgv) via the
// snapshot's enforce.Spec.Wrap to obtain the final argv plus a fresh per-spawn
// configure/cleanup pair, builds the command, applies the snapshot's environment
// and the backend's spawn attributes, runs it, and normalizes the result to the
// (output, exit, err) convention. The caller supplies one immutable snapshot for
// the whole spawn, and each wrap call yields its own closures, so concurrent
// spawns never share per-spawn state.
func (e *Executor) run(lease *executionLease, dir string, innerArgv []string, s snapshot, observe func(), afterZero ...func() error) (out []byte, code int, runErr error) {
	if s.spec.Launch != nil {
		return e.runBackendOwned(lease, dir, innerArgv, s, observe, afterZero...)
	}
	spawn := newQuarantinedSpawn(nil, nil, lease)
	spawn.observe = observe
	spawn.afterExecution = append(spawn.afterExecution, afterZero...)
	releaseOnReturn := true
	defer func() {
		if releaseOnReturn {
			if releaseErr := spawn.release(false, false, nil); releaseErr != nil {
				runErr = errors.Join(runErr, releaseErr)
				code = -1
			}
		}
	}()
	// Fail closed if the spawn spec never compiled: resolve already guards this,
	// but a nil transform must never reach a spawn (defense in depth).
	if s.spec.Wrap == nil {
		return nil, -1, errors.New("sandbox: executor spawn spec not compiled")
	}
	if len(innerArgv) == 0 {
		return nil, -1, errors.New("sandbox: empty argv")
	}

	argv, configure, cleanup := s.spec.Wrap(dir, innerArgv)
	if cleanup != nil {
		spawn.spawnCleanup = append(spawn.spawnCleanup, func() error { cleanup(); return nil })
	}
	if len(argv) == 0 {
		return nil, -1, errors.New("sandbox: backend produced an empty argv")
	}

	// #nosec G204 -- launching a caller-supplied command IS this module's purpose.
	// argv is not raw caller input: it is the argument list the selected enforce.Backend
	// produced from the compiled policy, and it is passed as a list rather than a
	// shell string, so nothing here is word-split or expanded by a shell.
	// Whether the command may run at all was decided before this point.
	cmd := exec.CommandContext(lease.ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.WaitDelay = spawnWaitGrace // backstop: force-kill if cmd.Cancel's group SIGKILL somehow doesn't stop the child
	cmd.Env = s.env
	// Belt-and-suspenders fail-closed guard: cmd.Env == nil makes exec.Cmd
	// inherit the entire parent environment. assembleEnv never returns nil, but a
	// truly empty child environment must be a non-nil empty slice so a future
	// change can never silently flip to inherit-all.
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	if configure != nil {
		if err := configure(cmd); err != nil {
			return nil, -1, err
		}
	}
	tree, err := e.processTree(cmd, processTreeOptions{
		Sandboxed: s.policy.Isolation != profile.Unconfined,
		Limits:    s.policy.Limits,
	})
	if err != nil {
		return nil, -1, err
	}
	spawn.prover = tree
	spawn.cmd = cmd

	// Stdout/stderr are wired through the same pipe-plumbing primitive
	// (wireOutputPipes, process.go) the pipe-backed asynchronous Process API
	// uses, rather than exec.Cmd's own internal Writer-backed pipes: this is
	// the shared "prepared process" spawning mechanics this run adopts.
	// Everything above and below this block — grant verification, path handle
	// resolution, quarantine, confinement (configure/tree) — is unchanged.
	outR, outW, errR, errW, err := wireOutputPipes(cmd)
	if err != nil {
		return nil, -1, err
	}
	handleCleanup, err := configureChildHandleList(cmd)
	if err != nil {
		_ = errors.Join(outR.Close(), outW.Close(), errR.Close(), errW.Close())
		return nil, -1, err
	}
	spawn.spawnCleanup = append([]func() error{func() error { handleCleanup(); return nil }}, spawn.spawnCleanup...)

	var output bytes.Buffer
	var outputMu sync.Mutex
	var drainWG sync.WaitGroup
	exitCode := -1

	err = lease.start(cmd, tree)
	if err != nil {
		// Nothing was started: no child holds any of these descriptors, so the
		// parent's copies of all four must be released here rather than
		// leaking them.
		_ = errors.Join(outR.Close(), outW.Close(), errR.Close(), errW.Close())
	} else {
		// The parent must drop its own reference to the two child-side
		// descriptors now that the child holds its inherited copies — the
		// same fd-lifetime handling spawnProcess already requires for the
		// asynchronous path (process.go) — otherwise a parent-side leak would
		// keep the read ends from ever observing EOF.
		closeErr := errors.Join(outW.Close(), errW.Close())
		// No stdin is wired for the synchronous path (nil): cmd.Stdin is left
		// exactly as set above (unset), so os/exec connects the child to the
		// null device, matching this path's behavior before this refactor.
		process := newPipeProcess(cmd, outR, errR, nil)
		spawn.spawnCleanup = append(spawn.spawnCleanup, func() error { return process.Close(context.Background()) })
		// Draining starts concurrently with the process running (not after
		// Wait): a full pipe buffer would otherwise block the child from
		// exiting, which would block Wait from ever returning.
		drainWG.Add(2)
		go func() { defer drainWG.Done(); drainCombinedOutput(&outputMu, &output, process.Stdout()) }()
		go func() { defer drainWG.Done(); drainCombinedOutput(&outputMu, &output, process.Stderr()) }()
		// process.Wait reaps the OS process only; unlike the exec.Cmd-owned
		// pipes this replaces, it does not itself wait for the drain
		// goroutines above to observe EOF. That is deliberately provided by
		// tree.terminateAndWait below instead: RunCommand no longer depends on
		// exec.Cmd's own WaitDelay-bounded I/O grace to reap an orphaned
		// grandchild descendant holding a pipe open (see spawnWaitGrace's
		// updated doc comment).
		if result, waitErr := process.Wait(context.Background()); waitErr != nil {
			err = errors.Join(waitErr, closeErr)
		} else {
			exitCode = result.ExitCode
			err = closeErr
		}
	}

	terminateErr, proofErr := tree.terminateAndWait()
	if proofErr != nil {
		releaseOnReturn = false
		spawn.transferTo(e.quarantine)
		// Proof failure is not evidence the drain goroutines have finished (or
		// ever will promptly): take a locked snapshot of whatever has been
		// captured so far instead of joining them, so this return can never
		// block on an unconfirmed descendant.
		outputMu.Lock()
		partial := append([]byte(nil), output.Bytes()...)
		outputMu.Unlock()
		return partial, -1, errors.Join(terminateErr, proofErr)
	}
	// tree.terminateAndWait has now confirmed the entire process group —
	// including any descendant that forked away from the immediate child and
	// inherited its pipe ends — is gone, so the drain goroutines are
	// guaranteed to observe EOF promptly rather than blocking on an orphaned
	// holder of the write end.
	drainWG.Wait()

	// Snapshot cancellation before releasing the execution lease: finish cancels
	// lease.ctx as part of normal teardown and must not be mistaken for a caller
	// cancellation or ExecutorSet close.
	executionCtxErr := lease.ctx.Err()
	callerCtxErr := lease.caller.Err()
	releaseErr := spawn.release(true, false, terminateErr)
	releaseOnReturn = false
	treeErr := releaseErr
	if treeErr != nil {
		err = treeErr
	}
	out = output.Bytes()
	if treeErr != nil {
		return out, -1, treeErr
	}

	// A context timeout/cancel DURING the run surfaces as a signal kill (an
	// ExitError with code -1), which would otherwise be reported as a nil-error
	// non-zero run. Check the context first so a deadline/cancel is a visible
	// error, symmetric with cancel-before-start.
	if executionCtxErr != nil {
		if callerCtxErr != nil {
			return out, -1, callerCtxErr
		}
		return out, -1, ErrExecutorClosed
	}

	if err != nil {
		// A genuine spawn/setup failure (dir missing, binary not found, a
		// close failure, …); a ran-but-nonzero process was already normalized
		// to (exitCode, nil error) above and never reaches this branch.
		return out, -1, err
	}
	return out, exitCode, nil
}

// drainCombinedOutput copies everything read from src into dst, serialized by
// mu, until src returns a read error (io.EOF on a clean pipe close). mu lets
// two goroutines — one draining stdout, one draining stderr — safely share
// one destination buffer, mirroring the serialization exec.Cmd itself already
// guaranteed when Stdout and Stderr were the identical writer ("If Stdout and
// Stderr are the same writer... at most one goroutine at a time will call
// Write").
func drainCombinedOutput(mu *sync.Mutex, dst *bytes.Buffer, src io.Reader) {
	buf := make([]byte, 32*1024)
	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			mu.Lock()
			dst.Write(buf[:n])
			mu.Unlock()
		}
		if readErr != nil {
			return
		}
	}
}

func (e *Executor) runBackendOwned(lease *executionLease, dir string, argv []string, s snapshot, observe func(), afterZero ...func() error) (out []byte, code int, runErr error) {
	spawn := newQuarantinedSpawn(nil, nil, lease)
	spawn.observe = observe
	spawn.afterExecution = append(spawn.afterExecution, afterZero...)
	released := false
	defer func() {
		if !released {
			if releaseErr := spawn.release(false, false, nil); releaseErr != nil {
				runErr = errors.Join(runErr, releaseErr)
				code = -1
			}
		}
	}()
	if len(argv) == 0 {
		return nil, -1, errors.New("sandbox: empty argv")
	}
	if err := lease.authorizeBackendStart(); err != nil {
		return nil, -1, err
	}
	env := append([]string(nil), s.env...)
	if env == nil {
		env = []string{}
	}
	var output bytes.Buffer
	// Launch itself only establishes the backend's OS-level authority and
	// returns promptly (see enforce.Spec.Launch's doc comment); this
	// synchronous RunCommand/RunArgv path immediately calls Wait on the
	// returned execution to reproduce the exact same blocking behavior this
	// call site has always had — same total wall time, same error surfacing
	// — so 10C's characterized RunCommand/RunArgv/Granted results remain
	// byte-for-byte unchanged. A future microtask (Task 11) is what actually
	// lets a caller observe the asynchronous handoff.
	execution, err := s.spec.Launch(enforce.LaunchRequest{
		Context: lease.ctx,
		Dir:     dir,
		Argv:    append([]string(nil), argv...),
		Env:     env,
		Stdin:   bytes.NewReader(nil),
		Stdout:  &output,
		Stderr:  &output,
	})
	var exit int
	if err == nil {
		exit, err = execution.Wait(lease.ctx)
	}
	executionCtxErr := lease.ctx.Err()
	callerCtxErr := lease.caller.Err()
	releaseErr := spawn.release(true, false, nil)
	released = true
	if releaseErr != nil {
		return output.Bytes(), -1, releaseErr
	}
	if executionCtxErr != nil {
		if callerCtxErr != nil {
			return output.Bytes(), -1, callerCtxErr
		}
		return output.Bytes(), -1, ErrExecutorClosed
	}
	if err != nil {
		return output.Bytes(), -1, err
	}
	return output.Bytes(), exit, nil
}

// Level reports the achieved (probed + compiled, not requested) isolation level
// (SPEC §6). The zero value LevelNone is fail-closed.
func (e *Executor) Level() uint8 {
	return e.level
}

// Report returns the per-feature compilation outcomes for the chosen enforce.Backend
// what was enforced, narrowed, or left unenforced.
func (e *Executor) Report() CompileReport {
	return e.report
}

// Guarantees returns the rich per-property statement of what the enforce.Backend
// actually enforced. Each field is fail-closed.
func (e *Executor) Guarantees() Guarantees { return profile.GuaranteesFromBits(e.GuaranteeBits()) }

// GuaranteeBits returns the same guarantees as the seam-facing bitmask so a
// consumer can probe interface{ GuaranteeBits() uint64 } without importing this
// package.
func (e *Executor) GuaranteeBits() uint64 {
	return e.guaranteeBits
}

func (e *Executor) commandAccess() error {
	if e == nil {
		return ErrExecutorClosed
	}
	e.grantMu.Lock()
	defer e.grantMu.Unlock()
	if e.closed {
		return ErrExecutorClosed
	}
	if e.profile == nil {
		return nil
	}
	switch e.settings.Command {
	case Allow:
		return nil
	case Gated:
		return ErrGrantRequired
	default:
		return ErrGrantDenied
	}
}

// GrantVersion reports the scalar grant ABI implemented by this executor.
func (e *Executor) GrantVersion() uint16 {
	if e == nil {
		return 0
	}
	return currentGrantVersion
}

// IssueGrant mints a single-use, executor-bound capability grant.
func (e *Executor) IssueGrant(ctx context.Context, executionID, command, cwd, kind, scope, class, target string, expiryUnixMilli int64) (string, error) {
	return e.issueGrant(ctx, executionID, command, cwd, kind, scope, class, target, expiryUnixMilli, validateGrantTargetAvailability)
}

type grantTargetAvailabilityFunc func(grantDelta) error

// grantClassBackend is an optional narrowing seam for a backend whose platform
// cannot enforce one of the canonical grant classes. Absence preserves the
// canonical cross-platform behavior; an explicit false always fails closed
// before a token is minted or consumed.
type grantClassBackend interface {
	SupportsGrantClass(string) bool
}

func (e *Executor) supportsGrantClass(class string) bool {
	if e == nil || e.backend == nil {
		return false
	}
	support, ok := e.backend.(grantClassBackend)
	return !ok || support.SupportsGrantClass(class)
}

// issueGrant accepts the platform availability check as a narrow test seam so
// ordering tests can prove that no target probe precedes canonical validation.
func (e *Executor) issueGrant(ctx context.Context, executionID, command, cwd, kind, scope, class, target string, expiryUnixMilli int64, checkAvailability grantTargetAvailabilityFunc) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if e == nil || e.profile == nil || e.profile.Validate() != nil {
		return "", ErrInvalidProfile
	}
	if !validGrantText(executionID) || !validGrantText(command) {
		return "", ErrGrantMalformed
	}
	canonicalCWD, err := canonicalWorkingDirectory(cwd)
	if err != nil {
		return "", fmt.Errorf("%w: cwd: %v", ErrGrantMalformed, err)
	}
	// Validate and authorize the lexical request before resolving or probing its
	// target. Canonicalization is a resource operation on Windows, so doing it
	// earlier would disclose target availability to an unauthorized caller.
	authorizedScope, authorizedTarget, err := prepareGrantRequestForAuthorization(scope, class, target)
	if err != nil {
		return "", fmt.Errorf("%w: target: %v", ErrGrantMalformed, err)
	}
	_, _, err = validateGrantClass(kind, authorizedScope, class, authorizedTarget)
	if err != nil {
		return "", err
	}
	if class == GrantClassCommandStart && target != command {
		return "", ErrGrantWrongCommand
	}
	if class == GrantClassNetworkProxyTarget && e.proxy == nil {
		return "", ErrGrantUnsupported
	}
	if !e.supportsGrantClass(class) {
		return "", ErrGrantUnsupported
	}
	if err := e.authorizeGrantScope(kind, authorizedScope); err != nil {
		return "", err
	}
	scope, target, err = normalizeGrantScopeTarget(authorizedScope, class, authorizedTarget)
	if err != nil {
		return "", fmt.Errorf("%w: target: %v", ErrGrantMalformed, err)
	}
	delta, requiredBits, err := validateGrantClass(kind, scope, class, target)
	if err != nil {
		return "", err
	}
	// Resolution may change path spelling or reveal a reparse target. Re-check
	// the canonical scope so lexical authorization can never widen authority.
	if err := e.authorizeGrantScope(kind, scope); err != nil {
		return "", err
	}
	if checkAvailability == nil {
		return "", ErrGrantUnsupported
	}
	if err := checkAvailability(delta); err != nil {
		return "", err
	}
	e.grantMu.Lock()
	defer e.grantMu.Unlock()
	if e.closed {
		return "", ErrExecutorClosed
	}
	now := e.clock()
	e.retainedGrantPaths.prune(now.UnixMilli())
	expiry := expiryFromMillis(expiryUnixMilli)
	if !expiry.After(now) || expiry.After(now.Add(e.grantTTL)) {
		return "", ErrGrantExpired
	}
	if requiredBits != 0 && e.guaranteeBits&requiredBits != requiredBits {
		return "", ErrGrantGuaranteeMismatch
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", fmt.Errorf("sandbox: grant nonce: %w", err)
	}
	var pathBinding *policy.PathBinding
	var retained retainedPathHandle
	if delta.entry != nil && filepath.IsAbs(delta.entry.Path) {
		binding, err := policy.CapturePathBinding(delta.entry.Path)
		if err != nil {
			if errors.Is(err, policy.ErrUnsupportedClass) {
				return "", ErrGrantUnsupported
			}
			return "", fmt.Errorf("%w: bind target: %v", ErrGrantMalformed, err)
		}
		handle, err := policy.AcquirePathHandle(&binding, delta.entry.Path, delta.entry.Exact)
		if err != nil {
			if errors.Is(err, policy.ErrUnsupportedClass) {
				return "", ErrGrantUnsupported
			}
			return "", err
		}
		if handle == nil {
			retained = noOpRetainedPathHandle{}
		} else {
			retained = handle
		}
		pathBinding = &binding
	}
	payload := grantPayload{
		ExecutionID: executionID, Command: command, WorkingDirectory: canonicalCWD,
		ProfileFingerprint: e.settings.Fingerprint, RouteFingerprint: e.routeFingerprint,
		GuaranteeBits: e.guaranteeBits, Class: class, Target: target,
		PathBinding: pathBinding, ExpiryUnixMilli: expiryUnixMilli, Nonce: nonce,
	}
	token, err := mintGrant(e.grantKey, payload)
	if err != nil {
		if retained != nil {
			_ = retained.Close()
		}
		return "", err
	}
	if retained != nil {
		if err := e.retainedGrantPaths.add(grantID(token), retainedGrantPath{
			binding: *pathBinding, target: delta.entry.Path, exact: delta.entry.Exact,
			expiryUnixMilli: expiryUnixMilli, handle: retained,
		}); err != nil {
			return "", err
		}
		e.rescheduleRetainedGrantExpiryLocked()
	}
	return token, nil
}

// authorizeGrantScope maps one validated request scope to grant semantics.
// Keeping this decision separate from target resolution makes the ordering
// explicit and ensures every canonicalized scope is authorized again.
func (e *Executor) authorizeGrantScope(kind, scope string) error {
	access, err := e.profile.AccessFor(kind, scope)
	if err != nil {
		return err
	}
	switch Access(access) {
	case Deny:
		return ErrGrantDenied
	case Gated:
		return nil
	default:
		return ErrGrantUnsupported
	}
}

// RunCommandWithGrants verifies all grants, compiles their least-authority
// deltas for this spawn, atomically consumes them, and then starts the command.
func (e *Executor) RunCommandWithGrants(ctx context.Context, executionID, dir, command string, grants []string) ([]byte, int, error) {
	acquire := grantPathAcquirer(policy.AcquirePathHandle)
	if backend, ok := e.backend.(grantACLPathAcquirer); ok {
		acquire = backend.AcquireGrantPathHandle
	}
	return e.runCommandWithGrants(ctx, executionID, dir, command, grants, acquire)
}

type grantPathAcquirer func(*policy.PathBinding, string, bool) (*policy.PathHandle, error)

// grantACLPathAcquirer is implemented by backends whose enforcement authority
// must be acquired by the same identity-validation open. Generic backends keep
// the ordinary read-only PathHandle acquisition path.
type grantACLPathAcquirer interface {
	AcquireGrantPathHandle(*policy.PathBinding, string, bool) (*policy.PathHandle, error)
}

type pendingGrantPath struct {
	id              [32]byte
	binding         *policy.PathBinding
	target          string
	exact           bool
	access          policy.FSAccess
	expiryUnixMilli int64
}

func (e *Executor) runCommandWithGrants(ctx context.Context, executionID, dir, command string, grants []string, acquire grantPathAcquirer) ([]byte, int, error) {
	lease, err := e.beginExecution(ctx)
	if err != nil {
		return nil, -1, err
	}
	leaseTransferred := false
	defer func() {
		if !leaseTransferred {
			lease.finish()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, -1, err
	}
	canonicalCWD, err := canonicalWorkingDirectory(dir)
	if err != nil {
		return nil, -1, fmt.Errorf("%w: cwd: %v", ErrGrantMalformed, err)
	}
	if !validGrantText(executionID) || !validGrantText(command) {
		return nil, -1, ErrGrantMalformed
	}
	e.grantMu.Lock()
	defer e.grantMu.Unlock()
	if e.closed {
		return nil, -1, ErrExecutorClosed
	}
	if e.profile == nil {
		return nil, -1, ErrInvalidProfile
	}
	pol := policy.Clone(e.policy)
	now := e.clock()
	e.pruneUsedGrantsLocked(now.UnixMilli())
	e.retainedGrantPaths.prune(now.UnixMilli())
	e.rescheduleRetainedGrantExpiryLocked()
	seen := make(map[[32]byte]int64, len(grants))
	commandGrant := e.settings.Command == Allow
	expectedGuarantees := e.guaranteeBits
	var proxyTargets []NetworkTarget
	var pendingPaths []pendingGrantPath
	var pathHandles policy.PathHandleSet
	defer pathHandles.Close()
	for _, token := range grants {
		id := grantID(token)
		if _, ok := e.usedGrants[id]; ok {
			return nil, -1, ErrGrantReplay
		}
		if _, ok := seen[id]; ok {
			return nil, -1, ErrGrantReplay
		}
		seen[id] = 0
		payload, err := authenticateGrant(e.grantKey, token)
		if err != nil {
			return nil, -1, err
		}
		if err := verifyGrantBinding(payload, now, executionID, command, canonicalCWD, e.settings.Fingerprint, e.routeFingerprint, e.guaranteeBits); err != nil {
			return nil, -1, err
		}
		seen[id] = payload.ExpiryUnixMilli
		delta, requiredBits, err := validateGrantClass(classKind(payload.Class), classScope(payload.Class, payload.Target), payload.Class, payload.Target)
		if err != nil {
			return nil, -1, err
		}
		if !e.supportsGrantClass(payload.Class) {
			return nil, -1, ErrGrantUnsupported
		}
		if requiredBits != 0 && e.guaranteeBits&requiredBits != requiredBits {
			return nil, -1, ErrGrantGuaranteeMismatch
		}
		if delta.entry != nil && filepath.IsAbs(delta.entry.Path) {
			pendingPaths = append(pendingPaths, pendingGrantPath{
				id: id, binding: payload.PathBinding, target: delta.entry.Path,
				exact: delta.entry.Exact, access: delta.entry.Access,
				expiryUnixMilli: payload.ExpiryUnixMilli,
			})
		}
		if delta.class == GrantClassCommandStart {
			if payload.Target != command {
				return nil, -1, ErrGrantWrongCommand
			}
			commandGrant = true
		}
		if delta.entry != nil {
			pol.FS = applyFilesystemGrant(pol.FS, *delta.entry)
		}
		dropped := delta.droppedGuarantees
		if dropped&GuaranteeReadBoundary != 0 && policy.IsAccessRestricted(pol.FS, policy.ReadAccess|policy.ExecAccess) {
			dropped &^= GuaranteeReadBoundary
		}
		if dropped&GuaranteeWriteBoundary != 0 && policy.IsAccessRestricted(pol.FS, policy.WriteAccess) {
			dropped &^= GuaranteeWriteBoundary
		}
		expectedGuarantees &^= dropped
		if delta.port != 0 && !policy.ContainsPort(pol.Net.Ports, delta.port) {
			pol.Net.Ports = append(pol.Net.Ports, delta.port)
		}
		pol.Net.DNS = pol.Net.DNS || delta.dns
		if delta.target != nil {
			proxyTargets = append(proxyTargets, *delta.target)
		}
	}
	if e.settings.Command == Deny {
		return nil, -1, ErrGrantDenied
	}
	if !commandGrant {
		return nil, -1, ErrGrantRequired
	}
	if len(proxyTargets) != 0 {
		if e.proxy == nil {
			return nil, -1, ErrGrantUnsupported
		}
		_, portText, err := net.SplitHostPort(e.proxy.Addr())
		if err != nil {
			return nil, -1, ErrGrantUnsupported
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return nil, -1, ErrGrantUnsupported
		}
		pol.Net = policy.NetPolicy{ProxyPort: uint16(port)}
	}
	for _, pending := range pendingPaths {
		retained, err := e.retainedGrantPaths.borrow(pending.id, pending.binding, pending.target, pending.exact, pending.expiryUnixMilli)
		if err != nil {
			return nil, -1, err
		}
		validation, err := acquire(pending.binding, pending.target, pending.exact)
		if err != nil {
			return nil, -1, err
		}
		retainedHandle, retainedIsPathHandle := retained.(*policy.PathHandle)
		if retainedIsPathHandle != (validation != nil) ||
			(retainedIsPathHandle && !policy.SamePathHandleIdentity(retainedHandle, validation)) {
			if validation != nil {
				_ = validation.Close()
			}
			return nil, -1, ErrGrantTargetChanged
		}
		if validation != nil {
			validation.SetAccess(pending.access)
			if err := pathHandles.Add(validation); err != nil {
				return nil, -1, err
			}
		}
	}
	spec, _, _, bits, err := compileBackendWithGrantPaths(e.backend, e.spec.GrantAuthority, e.policy, pol, pathHandles.Sorted())
	if err != nil {
		return nil, -1, finishExecutionAndRelease(lease, spec, err)
	}
	bits = e.composeRouteGuarantees(bits)
	if bits != expectedGuarantees {
		return nil, -1, finishExecutionAndRelease(lease, spec, ErrGrantGuaranteeMismatch)
	}
	if len(proxyTargets) != 0 {
		credential, err := e.proxy.Authorize(executionID, proxyTargets)
		if err != nil {
			return nil, -1, finishExecutionAndRelease(lease, spec, err)
		}
		proxyURL := e.proxy.URL(executionID, credential)
		applyChildProxyEnv(pol.Env.Set, proxyURL)
	}
	pathIDs := make([][32]byte, len(pendingPaths))
	for i := range pendingPaths {
		pathIDs[i] = pendingPaths[i].id
	}
	retainedHandles, err := e.retainedGrantPaths.commit(pathIDs)
	if err != nil {
		return nil, -1, finishExecutionAndRelease(lease, spec, err)
	}
	var retainedCloseErr error
	for _, handle := range retainedHandles {
		retainedCloseErr = errors.Join(retainedCloseErr, handle.Close())
	}
	for id, expiryUnixMilli := range seen {
		e.usedGrants[id] = expiryUnixMilli
	}
	e.rescheduleRetainedGrantExpiryLocked()
	if retainedCloseErr != nil {
		return nil, -1, finishExecutionAndRelease(lease, spec, retainedCloseErr)
	}
	s := snapshot{spec: spec, env: assembleEnv(pol), policy: pol}
	e.grantMu.Unlock()
	var denial error
	releases := []func() error{func() error { return releaseSpec(spec) }}
	if len(proxyTargets) != 0 {
		releases = append(releases, func() error {
			e.proxy.Release(executionID)
			return nil
		})
	}
	var observe func()
	if len(proxyTargets) != 0 {
		observe = func() { denial = e.proxy.Denial(executionID) }
	}
	leaseTransferred = true
	out, code, runErr := e.run(lease, canonicalCWD, enforce.ShellArgv(command), s, observe, releases...)
	e.grantMu.Lock()
	if denial != nil {
		runErr = network.NewTargetDeniedError(code, runErr, denial)
	}
	return out, code, runErr
}

func finishExecutionAndRelease(lease *executionLease, spec enforce.Spec, executionErr error) error {
	lease.finish()
	return errors.Join(executionErr, releaseSpec(spec))
}

func releaseSpec(spec enforce.Spec) error {
	if spec.Release == nil {
		return nil
	}
	return spec.Release()
}

func (e *Executor) releaseCompiledSpec() error {
	if e == nil {
		return nil
	}
	e.specReleaseOnce.Do(func() {
		e.specReleaseErr = releaseSpec(e.spec)
	})
	return e.specReleaseErr
}

// pruneUsedGrantsLocked removes entries only after their signed validity
// window. verifyGrantBinding accepts a token at exact expiry equality, so replay
// protection must do the same and prune only when expiry < now.
func (e *Executor) pruneUsedGrantsLocked(nowUnixMilli int64) {
	for id, expiryUnixMilli := range e.usedGrants {
		if expiryUnixMilli < nowUnixMilli {
			delete(e.usedGrants, id)
		}
	}
}

func (e *Executor) rescheduleRetainedGrantExpiryLocked() {
	e.grantExpiryGen++
	if e.grantExpiryTimer != nil {
		if e.grantExpiryTimer.Stop() {
			e.grantExpiryWG.Done()
		}
		e.grantExpiryTimer = nil
	}
	if e.closed || !e.grantExpiryRealtime || len(e.retainedGrantPaths) == 0 {
		return
	}
	nearest := int64(0)
	for _, entry := range e.retainedGrantPaths {
		if nearest == 0 || entry.expiryUnixMilli < nearest {
			nearest = entry.expiryUnixMilli
		}
	}
	now := time.Now()
	if e.clock != nil {
		now = e.clock()
	}
	delay := time.Duration(nearest-now.UnixMilli()+1) * time.Millisecond
	if delay < 0 {
		delay = 0
	}
	generation := e.grantExpiryGen
	e.grantExpiryWG.Add(1)
	e.grantExpiryTimer = time.AfterFunc(delay, func() {
		defer e.grantExpiryWG.Done()
		e.expireRetainedGrantPaths(generation)
	})
}

func (e *Executor) expireRetainedGrantPaths(generation uint64) {
	e.grantMu.Lock()
	defer e.grantMu.Unlock()
	if e.closed || generation != e.grantExpiryGen {
		return
	}
	e.grantExpiryTimer = nil
	now := time.Now()
	if e.clock != nil {
		now = e.clock()
	}
	e.retainedGrantPaths.prune(now.UnixMilli())
	e.rescheduleRetainedGrantExpiryLocked()
}

func (e *Executor) stopRetainedGrantExpiryLocked() {
	e.grantExpiryGen++
	if e.grantExpiryTimer != nil {
		if e.grantExpiryTimer.Stop() {
			e.grantExpiryWG.Done()
		}
		e.grantExpiryTimer = nil
	}
}

type grantPathBackend interface {
	CompileWithPathHandles(policy.Effective, []*policy.PathHandle) (enforce.Spec, profile.CompileReport, uint8, uint64, error)
}

type retainedGrantPathBackend interface {
	CompileWithRetainedPathHandles(any, policy.Effective, policy.Effective, []*policy.PathHandle) (enforce.Spec, profile.CompileReport, uint8, uint64, error)
}

func compileBackendWithGrantPaths(b enforce.Backend, authority any, base, pol policy.Effective, handles []*policy.PathHandle) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	if len(handles) != 0 {
		if retained, ok := b.(retainedGrantPathBackend); ok {
			return retained.CompileWithRetainedPathHandles(authority, policy.Clone(base), pol, handles)
		}
		if pathBackend, ok := b.(grantPathBackend); ok {
			return pathBackend.CompileWithPathHandles(pol, handles)
		}
	}
	return b.Compile(pol)
}

func (e *Executor) composeRouteGuarantees(bits uint64) uint64 {
	if e == nil || e.proxy == nil {
		return bits
	}
	bits &^= GuaranteeAddressNetwork
	if bits&GuaranteeTargetNetwork != 0 && e.proxy.Route().AddressGuarantee() {
		bits |= GuaranteeAddressNetwork
	}
	return bits
}

func applyFilesystemGrant(entries []policy.FSEntry, grant policy.FSEntry) []policy.FSEntry {
	for i := range entries {
		if entries[i].Path == grant.Path && entries[i].Exact == grant.Exact {
			entries[i].Denied &^= grant.Access
		}
	}
	return append(entries, grant)
}

func classKind(class string) string {
	switch {
	case class == GrantClassCommandStart:
		return "command.execute"
	case strings.HasPrefix(class, "filesystem.") && strings.HasSuffix(class, ".read.v1"):
		return "filesystem.read"
	case strings.HasPrefix(class, "filesystem.") && strings.HasSuffix(class, ".write.v1"):
		return "filesystem.write"
	case strings.HasPrefix(class, "network."):
		return "network"
	default:
		return ""
	}
}

func classScope(class, target string) string {
	switch {
	case strings.Contains(class, ".host."):
		return "host:*"
	case strings.Contains(class, ".tree."):
		return "tree:" + target
	case strings.Contains(class, ".path."):
		return target
	default:
		return ""
	}
}

// applyChildProxyEnv forces the loopback proxy environment onto a child's
// env-Set overrides: it points all four proxy variables at proxyURL and clears
// both spellings of NO_PROXY so nothing can bypass the loopback proxy. It is
// the single proxy-env injection path shared by the plain allowed-route run
// (prepareAllowedRoute) and the grant-bound run (runCommandWithGrants) so the
// two egress-containment paths can never inject different proxy env.
func applyChildProxyEnv(set map[string]string, proxyURL string) {
	for _, name := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		set[name] = proxyURL
	}
	set["NO_PROXY"] = ""
	set["no_proxy"] = ""
}

// assembleEnv builds the child environment from a policy.Effective's policy.EnvPolicy (SPEC §5.5).
// It is shared by every backend and lives on the executor side because env
// scrubbing holds regardless of OS mechanism.
//
//   - Inherit: start from the full parent environment (os.Environ), then force
//     the Set overrides. Used by unconfined and explicit opt-in.
//   - otherwise (the fail-closed default): keep only parent variables whose NAME
//     matches the §5.5 baseline allowlist or one of policy.EnvPolicy.Allow (name globs
//     via filepath.Match), then force the Set overrides (including TMPDIR).
//     Everything else — GITHUB_TOKEN, AWS_*, LLM keys, SSH_AUTH_SOCK, … — is
//     absent.
//
// The result is a KEY=VALUE slice suitable for exec.Cmd.Env.
func assembleEnv(p policy.Effective) []string {
	if p.Env.Inherit {
		return applySet(os.Environ(), p.Env.Set)
	}

	// Baseline allowlist plus caller additions. policy.BaselineEnvAllowlist returns a
	// fresh slice, so appending never mutates shared state.
	allow := append(policy.BaselineEnvAllowlist(), p.Env.Allow...)

	// A non-nil empty slice is load-bearing: a scrub policy that admits no vars
	// and has an empty Set must yield an empty (not nil) env, because cmd.Env ==
	// nil makes exec.Cmd inherit the ENTIRE parent environment — a full secret
	// leak that would invert the very guarantee (EnvScrub) this branch exists to
	// provide. Fail closed to a truly empty child environment.
	kept := []string{}
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if envNameMatches(name, allow) {
			kept = append(kept, kv)
		}
	}
	return applySet(kept, p.Env.Set)
}

// envNameMatches reports whether an environment variable name matches any of the
// allowlist patterns, using path.Match on the NAME (so "LC_*" and "CARGO_*"
// work). path.Match — not filepath.Match — is deliberate: env names are not
// filesystem paths, and filepath.Match uses "\"-separator semantics on Windows,
// whereas path.Match is always "/"-based, which is correct for a plain name. A
// malformed pattern fails closed: path.Match's error is treated as a non-match,
// so a bad glob never widens the allowlist.
func envNameMatches(name string, patterns []string) bool {
	for _, pat := range patterns {
		if ok, err := path.Match(pat, name); err == nil && ok {
			return true
		}
	}
	return false
}

// applySet forces the policy.EnvPolicy.Set values onto an assembled env slice: an
// existing KEY is overwritten in place (so no duplicate keys), and a new KEY is
// appended. Newly appended keys are sorted for a deterministic result. env is
// assumed to be freshly owned by the caller (os.Environ() or a freshly built
// slice), so overwriting in place is safe.
func applySet(env []string, set map[string]string) []string {
	if len(set) == 0 {
		return env
	}

	forced := make(map[string]bool, len(set))
	for i, kv := range env {
		name, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if v, isForced := set[name]; isForced {
			env[i] = name + "=" + v
			forced[name] = true
		}
	}

	var add []string
	for k := range set {
		if !forced[k] {
			add = append(add, k)
		}
	}
	slices.Sort(add)
	for _, k := range add {
		env = append(env, k+"="+set[k])
	}
	return env
}
