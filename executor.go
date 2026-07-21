package sandbox

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/network"
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

// spawnWaitGrace bounds how long a spawn's Wait/CombinedOutput blocks for I/O
// AFTER the context is cancelled and the child is killed (exec.Cmd.WaitDelay,
// Go 1.20+). It exists because on Linux a shell may FORK the target (e.g. dash
// runs `sh -c "sleep 5"` as a child, unlike macOS's exec-replacing /bin/sh): when
// the immediate child is SIGKILLed on a deadline, the orphaned grandchild
// inherits the stdout/stderr pipe and holds it open, so CombinedOutput would
// otherwise block reading that pipe until the grandchild exits on its own — well
// past the deadline. WaitDelay makes the deadline prompt by force-closing the
// pipes and returning after the grace. It only ever fires after the context is
// done or the process has exited, so a live command under a healthy context is
// never truncated. The value trades a brief I/O-flush window against promptness.
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
	grantTTL  time.Duration
	clock     func() time.Time // nil means default time.Now
	backend   backend          // nil means select via platformBackend (test seam)
	lifecycle *executorLifecycle
}

// Executor compiles a policy.Effective once via the platform backend and then runs
// commands under the resulting stateless per-spawn transform (SPEC §6, §7). It
// holds the compiled policy, the chosen backend, its spawnSpec, the compilation
// report, the achieved level and guarantee bits, and the assembled child
// environment — everything a spawn needs, precomputed at construction.
type Executor struct {
	profile *Profile
	// settings is the snapshot of profile's normalized authority, taken once at
	// construction because a Profile is immutable. It is the read path for every
	// authority check on the spawn hot path.
	settings      profile.Settings
	policy        policy.Effective
	backend       backend
	spec          spawnSpec
	report        CompileReport
	level         uint8
	guaranteeBits uint64
	env           []string // assembled child environment, KEY=VALUE (SPEC §5.5)

	// Grant wiring (SPEC §9.2). The HMAC key is per-executor and never serialized.
	// Tokens also bind the immutable profile, route identity, and guarantee bits.
	// usedGrants provides one-shot replay protection; Close revokes the key.
	grantKey         []byte
	clock            func() time.Time
	grantTTL         time.Duration
	routeFingerprint string
	proxy            *network.Proxy
	home             string
	tmp              string
	grantMu          sync.Mutex
	usedGrants       map[[32]byte]int64 // grant ID -> signed expiry Unix milliseconds
	closed           bool
	lifecycle        *executorLifecycle
}

// snapshot is the compiled state a single spawn needs.
type snapshot struct {
	spec   spawnSpec
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
	// Backend selection: platformBackend() for production; a test may pin one via
	// the unexported withBackend seam so executor UNIT tests stay backend-independent.
	// platformBackend can fail (an unsupported platform, or — on Linux — a re-exec
	// backend selected without Init() having been called), which fails construction
	// closed rather than building an executor that would spawn incorrectly.
	b := config.backend
	if b == nil {
		if prof != nil && settings.Isolation == Unconfined {
			b = newNullBackend()
		} else {
			var berr error
			b, berr = platformBackend()
			if berr != nil {
				return nil, berr
			}
		}
	}
	spec, report, level, bits, err := b.compile(p)
	if err != nil {
		return nil, err
	}
	if prof != nil {
		missing := settings.RequiredGuarantees &^ bits
		if missing != 0 {
			return nil, fmt.Errorf("%w: backend missing required guarantees %#x", ErrSandboxUnavailable, missing)
		}
	}

	key, err := newGrantKey()
	if err != nil {
		return nil, fmt.Errorf("sandbox: grant key: %w", err)
	}

	lifecycle := config.lifecycle
	if lifecycle == nil {
		lifecycle = newExecutorLifecycle()
	}
	return &Executor{
		profile:          prof,
		settings:         settings,
		policy:           p,
		backend:          b,
		spec:             spec,
		report:           report,
		level:            level,
		guaranteeBits:    bits,
		env:              assembleEnv(p),
		grantKey:         key,
		clock:            clockOrDefault(config.clock),
		grantTTL:         ttlOrDefault(config.grantTTL),
		routeFingerprint: defaultRouteIdentity,
		usedGrants:       make(map[[32]byte]int64),
		lifecycle:        lifecycle,
	}, nil
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
// It wraps the command via the backend's spawnSpec, sets the working
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
	defer lease.finish()
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
	if executionID != "" {
		defer e.proxy.Release(executionID)
	}
	return e.run(lease, dir, shellArgv(command), s)
}

// shellArgv is the universal shell-normalization: running a command STRING means
// executing /bin/sh -c <command> under confinement, on every backend. The backend
// wraps this inner argv (sandbox-exec prefix, stage-2 re-exec, or nothing); the
// executor owns the shell form so the backends only ever wrap an argv.
func shellArgv(command string) []string { return []string{"/bin/sh", "-c", command} }

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
	if e.spec.wrap == nil {
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
	defer lease.finish()
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
	if executionID != "" {
		defer e.proxy.Release(executionID)
	}
	return e.run(lease, dir, argv, s)
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
// snapshot's spawnSpec.wrap to obtain the final argv plus a fresh per-spawn
// configure/cleanup pair, builds the command, applies the snapshot's environment
// and the backend's spawn attributes, runs it, and normalizes the result to the
// (output, exit, err) convention. The caller supplies one immutable snapshot for
// the whole spawn, and each wrap call yields its own closures, so concurrent
// spawns never share per-spawn state.
func (e *Executor) run(lease *executionLease, dir string, innerArgv []string, s snapshot) ([]byte, int, error) {
	// Fail closed if the spawn spec never compiled: resolve already guards this,
	// but a nil transform must never reach a spawn (defense in depth).
	if s.spec.wrap == nil {
		return nil, -1, errors.New("sandbox: executor spawn spec not compiled")
	}
	if len(innerArgv) == 0 {
		return nil, -1, errors.New("sandbox: empty argv")
	}

	argv, configure, cleanup := s.spec.wrap(dir, innerArgv)
	if cleanup != nil {
		defer cleanup()
	}
	if len(argv) == 0 {
		return nil, -1, errors.New("sandbox: backend produced an empty argv")
	}

	// #nosec G204 -- launching a caller-supplied command IS this module's purpose.
	// argv is not raw caller input: it is the argument list the selected backend
	// produced from the compiled policy, and it is passed as a list rather than a
	// shell string, so nothing here is word-split or expanded by a shell.
	// Whether the command may run at all was decided before this point.
	cmd := exec.CommandContext(lease.ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.WaitDelay = spawnWaitGrace // bound deadline latency when a forked grandchild holds the output pipe
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
	tree, err := newProcessTree(cmd)
	if err != nil {
		return nil, -1, err
	}
	defer tree.close()

	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err = lease.start(cmd, tree)
	if err == nil {
		err = cmd.Wait()
	}
	treeErr := tree.terminateAndWait()
	if treeErr != nil {
		err = treeErr
	}
	out := output.Bytes()
	if treeErr != nil {
		return out, -1, treeErr
	}

	// A context timeout/cancel DURING the run surfaces as a signal kill (an
	// ExitError with code -1), which would otherwise be reported as a nil-error
	// non-zero run. Check the context first so a deadline/cancel is a visible
	// error, symmetric with cancel-before-start.
	if lease.ctx.Err() != nil {
		if lease.caller.Err() != nil {
			return out, -1, lease.caller.Err()
		}
		return out, -1, ErrExecutorClosed
	}

	if err != nil {
		// A ran-but-nonzero process is not an error under our convention: surface
		// the real exit code and a nil error.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out, ee.ExitCode(), nil
		}
		// A genuine spawn/setup failure: dir missing, binary not found, etc.
		return out, -1, err
	}
	return out, 0, nil
}

// Level reports the achieved (probed + compiled, not requested) isolation level
// (SPEC §6). The zero value LevelNone is fail-closed.
func (e *Executor) Level() uint8 {
	return e.level
}

// Report returns the per-feature compilation outcomes for the chosen backend
// what was enforced, narrowed, or left unenforced.
func (e *Executor) Report() CompileReport {
	return e.report
}

// Guarantees returns the rich per-property statement of what the backend
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
	scope, target, err = normalizeGrantScopeTarget(scope, class, target)
	if err != nil {
		return "", fmt.Errorf("%w: target: %v", ErrGrantMalformed, err)
	}
	delta, requiredBits, err := validateGrantClass(kind, scope, class, target)
	if err != nil {
		return "", err
	}
	if class == GrantClassCommandStart && target != command {
		return "", ErrGrantWrongCommand
	}
	if class == GrantClassNetworkProxyTarget && e.proxy == nil {
		return "", ErrGrantUnsupported
	}
	var pathBinding *policy.PathBinding
	if delta.entry != nil && filepath.IsAbs(delta.entry.Path) {
		binding, err := policy.CapturePathBinding(delta.entry.Path)
		if err != nil {
			return "", fmt.Errorf("%w: bind target: %v", ErrGrantMalformed, err)
		}
		pathBinding = &binding
	}
	access, err := e.profile.AccessFor(kind, scope)
	if err != nil {
		return "", err
	}
	if Access(access) == Deny {
		return "", ErrGrantDenied
	}
	if Access(access) != Gated {
		return "", ErrGrantUnsupported
	}
	e.grantMu.Lock()
	defer e.grantMu.Unlock()
	if e.closed {
		return "", ErrExecutorClosed
	}
	now := e.clock()
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
	return mintGrant(e.grantKey, grantPayload{
		ExecutionID: executionID, Command: command, WorkingDirectory: canonicalCWD,
		ProfileFingerprint: e.settings.Fingerprint, RouteFingerprint: e.routeFingerprint,
		GuaranteeBits: e.guaranteeBits, Class: class, Target: target,
		PathBinding: pathBinding, ExpiryUnixMilli: expiryUnixMilli, Nonce: nonce,
	})
}

// RunCommandWithGrants verifies all grants, compiles their least-authority
// deltas for this spawn, atomically consumes them, and then starts the command.
func (e *Executor) RunCommandWithGrants(ctx context.Context, executionID, dir, command string, grants []string) ([]byte, int, error) {
	return e.runCommandWithGrants(ctx, executionID, dir, command, grants, policy.AcquirePathHandle)
}

type grantPathAcquirer func(*policy.PathBinding, string, bool) (*policy.PathHandle, error)

func (e *Executor) runCommandWithGrants(ctx context.Context, executionID, dir, command string, grants []string, acquire grantPathAcquirer) ([]byte, int, error) {
	lease, err := e.beginExecution(ctx)
	if err != nil {
		return nil, -1, err
	}
	defer lease.finish()
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
	seen := make(map[[32]byte]int64, len(grants))
	commandGrant := e.settings.Command == Allow
	expectedGuarantees := e.guaranteeBits
	var proxyTargets []NetworkTarget
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
		if requiredBits != 0 && e.guaranteeBits&requiredBits != requiredBits {
			return nil, -1, ErrGrantGuaranteeMismatch
		}
		if delta.entry != nil && filepath.IsAbs(delta.entry.Path) {
			handle, err := acquire(payload.PathBinding, delta.entry.Path, delta.entry.Exact)
			if err != nil {
				return nil, -1, err
			}
			if handle != nil {
				handle.SetAccess(delta.entry.Access)
				if err := pathHandles.Add(handle); err != nil {
					return nil, -1, err
				}
			}
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
	spec, _, _, bits, err := compileBackendWithGrantPaths(e.backend, pol, pathHandles.Sorted())
	if err != nil {
		return nil, -1, err
	}
	bits = e.composeRouteGuarantees(bits)
	if bits != expectedGuarantees {
		return nil, -1, ErrGrantGuaranteeMismatch
	}
	if len(proxyTargets) != 0 {
		credential, err := e.proxy.Authorize(executionID, proxyTargets)
		if err != nil {
			return nil, -1, err
		}
		proxyURL := e.proxy.URL(executionID, credential)
		applyChildProxyEnv(pol.Env.Set, proxyURL)
	}
	for id, expiryUnixMilli := range seen {
		e.usedGrants[id] = expiryUnixMilli
	}
	s := snapshot{spec: spec, env: assembleEnv(pol), policy: pol}
	e.grantMu.Unlock()
	out, code, runErr := e.run(lease, canonicalCWD, shellArgv(command), s)
	var denial error
	if len(proxyTargets) != 0 {
		denial = e.proxy.Denial(executionID)
		e.proxy.Release(executionID)
	}
	e.grantMu.Lock()
	if denial != nil {
		return out, code, network.NewTargetDeniedError(code, runErr, denial)
	}
	return out, code, runErr
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

type grantPathBackend interface {
	compileWithGrantPaths(policy.Effective, []*policy.PathHandle) (spawnSpec, CompileReport, uint8, uint64, error)
}

func compileBackendWithGrantPaths(b backend, pol policy.Effective, handles []*policy.PathHandle) (spawnSpec, CompileReport, uint8, uint64, error) {
	if len(handles) != 0 {
		if pathBackend, ok := b.(grantPathBackend); ok {
			return pathBackend.compileWithGrantPaths(pol, handles)
		}
	}
	return b.compile(pol)
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
