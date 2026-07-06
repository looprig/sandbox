package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
)

// defaultGrantTTL is the lifetime of a minted grant token when WithGrantTTL is
// not supplied (SPEC §9.2, §13 decision 5: 15 minutes).
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

// fullGuarantees is every defined guarantee bit set — the FULL posture. Only an
// external executor asserts it, by explicit deployment declaration (SPEC §11);
// no probing ever mints it.
const fullGuarantees = GuaranteeProcessBoundary | GuaranteeWriteBoundary | GuaranteeReadDenies |
	GuaranteeEnvScrub | GuaranteeNetworkBoundary | GuaranteeAddressNetwork | GuaranteeResourceLimits

// ErrUnconfinedNotAcked is returned when a policy that grants unconfined access
// is used to build (NewExecutor) or recompile (a dynamic ModeSource flipping to
// Unconfined) an executor without Policy.AckUnconfined set (SPEC §4, §6).
// Unconfined is stepping off the ladder — full user-level authority — so it
// demands an explicit acknowledgement; its absence fails CLOSED. An external
// executor is exempt: it declares deployment-level trust and never validates.
var ErrUnconfinedNotAcked = errors.New("sandbox: unconfined policy requires AckUnconfined")

// grantsUnconfined reports whether a policy leaves no meaningful confinement
// (SPEC §4, §6). Env.Inherit (the child inherits the entire parent environment —
// every secret) and Net.Open (unrestricted egress) are set ONLY by the Unconfined
// preset or an explicit consumer opt-in (WithEnv(EnvPolicy{Inherit:true}) /
// WithNet(NetPolicy{Open:true})); either flag alone means the sandbox no longer
// confines the spawn. The FS shape is deliberately NOT consulted: a broad-read
// policy is still confined by env scrub and network denial, so it is not
// "unconfined".
func grantsUnconfined(p Policy) bool { return p.Env.Inherit || p.Net.Open }

// validatePolicy enforces the construction/recompile invariants shared by the
// static and dynamic paths. Today the sole rule is the unconfined ack gate: a
// policy that grants unconfined access MUST carry AckUnconfined (SPEC §6). It is
// called from NewExecutor (static construction) and recompileLocked (dynamic
// recompile, so a mode flip to Unconfined without WithAckUnconfined fails the
// spawn closed). NewExternalExecutor never passes through it.
func validatePolicy(p Policy) error {
	if grantsUnconfined(p) && !p.AckUnconfined {
		return ErrUnconfinedNotAcked
	}
	return nil
}

// Init is called first in the consumer's main() (SPEC §6). It is a no-op stub
// today, but consumers MUST call it as the very first line of main() regardless:
//
//	func main() {
//		sandbox.Init()
//		// ... rest of program
//	}
//
// It becomes load-bearing on Linux, where the sandbox re-executes the process as
// a stage-2 helper (moby/reexec pattern, §7.2, Task 11) before any other
// goroutine, file descriptor, or thread state is established. Wiring the call
// from day one means consumers never have to retrofit it.
func Init() {}

// execConfig accumulates ExecOption settings before they are stored on the
// Executor. It exists so the option functions have a single mutable target
// during NewExecutor.
type execConfig struct {
	grantTTL     time.Duration
	cgroupParent string
	clock        func() time.Time // nil means default time.Now
	backend      backend          // nil means select via platformBackend (test seam)
}

// ExecOption configures a NewExecutor call (SPEC §6).
type ExecOption func(*execConfig)

// WithGrantTTL sets the lifetime of grant tokens minted by this executor (SPEC
// §9.2). Stored for the grant-wiring task; unused until then.
func WithGrantTTL(d time.Duration) ExecOption {
	return func(c *execConfig) { c.grantTTL = d }
}

// WithCgroupParent sets the parent cgroup under which resource-limited children
// are placed on Linux (SPEC §7.4). Stored for the resource-limit task; unused
// until then.
func WithCgroupParent(path string) ExecOption {
	return func(c *execConfig) { c.cgroupParent = path }
}

// withClock overrides the executor's clock, used only by tests for deterministic
// grant expiry. It is deliberately UNEXPORTED: the public ExecOption surface is
// WithGrantTTL/WithCgroupParent only.
func withClock(f func() time.Time) ExecOption {
	return func(c *execConfig) { c.clock = f }
}

// withBackend forces the executor's backend, bypassing platformBackend()
// selection. It is deliberately UNEXPORTED — a test-only seam. Once platformBackend
// returns a real OS backend on the host (e.g. Seatbelt on darwin), the executor
// UNIT tests that assert null-backend semantics (LevelNone, EnvScrub-only
// guarantees, the argv-not-found spawn-error convention) would otherwise observe
// the platform backend instead. Pinning them to newNullBackend() via this option
// keeps those tests deterministic and platform-independent, so they still test
// executor logic — not the enforcement backend — and pass on every OS. Production
// construction never sets it and always goes through platformBackend().
func withBackend(b backend) ExecOption {
	return func(c *execConfig) { c.backend = b }
}

// Executor compiles a Policy once via the platform backend and then runs
// commands under the resulting stateless per-spawn transform (SPEC §6, §7). It
// holds the compiled policy, the chosen backend, its spawnSpec, the compilation
// report, the achieved level and guarantee bits, and the assembled child
// environment — everything a spawn needs, precomputed at construction.
type Executor struct {
	policy        Policy
	backend       backend
	spec          spawnSpec
	report        CompileReport
	level         uint8
	guaranteeBits uint64
	env           []string // assembled child environment, KEY=VALUE (SPEC §5.5)

	// Grant wiring (SPEC §9.2). grantKey is the per-executor HMAC key (never
	// serialized — the instance binding); policyGen is the generation bound into
	// minted tokens (bumped on every dynamic recompile so a mode change voids all
	// prior tokens); clock is injectable for deterministic tests; grantTTL is the
	// minted-token lifetime (default 15 min).
	grantKey  []byte
	policyGen uint64
	clock     func() time.Time
	grantTTL  time.Duration

	cgroupParent string // stored for the cgroup task (SPEC §7.4); unused here

	// Dynamic mode (SPEC §8). When src != nil the executor recompiles
	// PolicyFor(src.Current(), workspace, popts...) per spawn, cached per mode and
	// guarded by mu; each genuine mode change bumps policyGen. Static executors
	// leave src nil and never recompile.
	src       ModeSource
	workspace string
	popts     []PolicyOption
	mu        sync.Mutex // guards the compiled snapshot + lastMode/haveMode for dynamic
	lastMode  Mode       // last compiled mode (valid only when haveMode)
	haveMode  bool       // whether a compile has happened (Mode's zero value is a valid mode)

	// readOnly marks a ReadOnlyView (SPEC §10.1): every (re)compile strips write
	// bits from FS, forces Net blocked, and PlanGrants returns nil — the read path
	// never escalates.
	readOnly bool

	// compileErr latches a construction-time compile failure of a ReadOnlyView
	// (whose signature has no error return). resolve returns it thereafter so a
	// view that never compiled fails CLOSED at spawn instead of leaving a nil
	// spawnSpec that would panic. It is only ever set for a static view; a dynamic
	// view re-attempts compilation on each resolve, so its failures surface live.
	compileErr error
}

// snapshot is the compiled state a single spawn needs, read atomically so a
// concurrent dynamic recompile cannot tear a spawn across two generations. For a
// static executor it mirrors the immutable fields; for a dynamic one it is read
// under mu right after any needed recompile.
type snapshot struct {
	spec      spawnSpec
	env       []string
	policy    Policy
	policyGen uint64
}

// ModeSource supplies the live mode for a dynamic executor (SPEC §6, §8). It is
// read once per spawn; a change since the last spawn triggers a recompile.
type ModeSource interface{ Current() Mode }

// NewExecutor selects the platform backend, compiles the policy, and assembles
// the child environment (SPEC §6). It returns an error only when the backend
// cannot compile the policy at all, or when the home directory is unresolvable
// for a non-unconfined policy (see below); a backend that enforces less than
// requested still constructs an executor and reports the shortfall via Level/
// Report/Guarantees.
//
// Ack gate (fail-closed): a policy that grants unconfined access (grantsUnconfined
// — Env.Inherit or Net.Open) MUST carry AckUnconfined, or construction fails with
// ErrUnconfinedNotAcked (SPEC §4, §6). This runs BEFORE the home guard so an
// unacked unconfined policy is rejected regardless of home resolvability; for an
// Inherit policy the home guard is exempt anyway, so the ack error is what surfaces.
//
// Home guard (fail-closed): a non-unconfined policy's §5.3 secret deny-reads are
// anchored under the user's home (~/.ssh, ~/.aws, …). If os.UserHomeDir errors
// those denials cannot materialize, so NewExecutor refuses to build a broad-read
// executor rather than silently omitting them. Unconfined is exempt: it sets
// Env.Inherit and emits no secret denials, so !p.Env.Inherit is the proxy for
// "non-unconfined, has secret denials to protect".
func NewExecutor(p Policy, opts ...ExecOption) (*Executor, error) {
	var cfg execConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	if err := validatePolicy(p); err != nil {
		return nil, err
	}

	if !p.Env.Inherit {
		if _, err := os.UserHomeDir(); err != nil {
			return nil, fmt.Errorf("sandbox: cannot resolve home directory for secret deny-reads: %w", err)
		}
	}

	// Backend selection: platformBackend() for production; a test may pin one via
	// the unexported withBackend seam so executor UNIT tests stay backend-independent.
	b := cfg.backend
	if b == nil {
		b = platformBackend()
	}
	spec, report, level, bits, err := b.compile(p)
	if err != nil {
		return nil, err
	}

	key, err := newGrantKey()
	if err != nil {
		return nil, fmt.Errorf("sandbox: grant key: %w", err)
	}

	return &Executor{
		policy:        p,
		backend:       b,
		spec:          spec,
		report:        report,
		level:         level,
		guaranteeBits: bits,
		env:           assembleEnv(p),
		grantKey:      key,
		policyGen:     1, // static executors have a constant generation
		clock:         clockOrDefault(cfg.clock),
		grantTTL:      ttlOrDefault(cfg.grantTTL),
		cgroupParent:  cfg.cgroupParent,
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

// NewExecutorDynamic builds a dynamic-mode executor that recompiles
// PolicyFor(src.Current(), workspace, popts...) per spawn (SPEC §6, §8). It
// compiles the current mode once at construction, then on each spawn re-reads
// src.Current() and recompiles (bumping policyGen, which voids grants bound to an
// earlier generation) whenever the mode differs from the last compiled one.
//
// Home guard: unlike NewExecutor this ALWAYS errors on an unresolvable home,
// because a dynamic executor can compile non-unconfined modes (whose secret
// deny-reads are home-anchored) at any later moment; there is no single policy to
// exempt.
//
// By design (SPEC §6) this takes PolicyOptions only, not ExecOptions: a dynamic
// executor therefore uses the default grant TTL (15 min) and clock (time.Now),
// which are not customizable through the public API. Tests inject a clock via the
// white-box withClock field.
func NewExecutorDynamic(src ModeSource, workspace string, popts ...PolicyOption) (*Executor, error) {
	if _, err := os.UserHomeDir(); err != nil {
		return nil, fmt.Errorf("sandbox: cannot resolve home directory for secret deny-reads: %w", err)
	}

	key, err := newGrantKey()
	if err != nil {
		return nil, fmt.Errorf("sandbox: grant key: %w", err)
	}

	e := &Executor{
		backend:   platformBackend(),
		grantKey:  key,
		policyGen: 1,
		clock:     time.Now,
		grantTTL:  defaultGrantTTL,
		src:       src,
		workspace: workspace,
		popts:     popts,
	}
	// Compile the current mode once so Level/Guarantees are populated before the
	// first spawn. haveMode is false here, so this initial compile does NOT bump
	// policyGen (it stays 1); only a later mode change bumps it.
	if err := e.recompileLocked(); err != nil {
		return nil, err
	}
	return e, nil
}

// NewExternalExecutor declares that the surrounding environment is the isolation
// boundary (SPEC §11): a container, gVisor, or microVM. Construction cannot fail
// (there is no probe or compile), so it returns no error. The spawnSpec is a pure
// passthrough — commands run as a plain os/exec would — but the environment is
// still scrubbed from decl.Env (§11: scrubbing costs nothing and remains
// valuable). It reports LevelExternal and the FULL guarantee set: trust by
// explicit deployment declaration, the only source of LevelExternal.
//
// EnvScrub honesty: EnvScrub is the one guarantee we can actually check against
// decl.Env rather than take on declaration. A decl.Env with Inherit passes the
// whole parent environment through unscrubbed, so EnvScrub is cleared (guarantee
// honesty, mirroring the null backend); the other 6 stay set by trust-by-declaration.
func NewExternalExecutor(decl ExternalDecl) *Executor {
	b := newNullBackend()
	spec, _, _, _, _ := b.compile(Policy{}) // passthrough spawnSpec only
	p := Policy{Env: decl.Env}

	bits := fullGuarantees
	if decl.Env.Inherit {
		bits &^= GuaranteeEnvScrub // env not scrubbed under Inherit — do not claim it
	}

	// crypto/rand.Read cannot return a non-nil error on Go >= 1.24 (it panics on a
	// catastrophic RNG failure), so this key is always valid; the ignored error is
	// a formality that never fires.
	key, _ := newGrantKey()

	return &Executor{
		policy:        p,
		backend:       b,
		spec:          spec,
		report:        CompileReport{},
		level:         LevelExternal,
		guaranteeBits: bits,
		env:           assembleEnv(p),
		grantKey:      key,
		policyGen:     1,
		clock:         time.Now,
		grantTTL:      defaultGrantTTL,
	}
}

// RunCommand runs a shell command string in dir under the compiled policy (SPEC
// §6, §10.1). It wraps the command via the backend's spawnSpec, sets the working
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
	s, err := e.resolve()
	if err != nil {
		return nil, -1, err
	}
	return e.run(ctx, dir, shellArgv(command), s)
}

// shellArgv is the universal shell-normalization: running a command STRING means
// executing /bin/sh -c <command> under confinement, on every backend. The backend
// wraps this inner argv (sandbox-exec prefix, stage-2 re-exec, or nothing); the
// executor owns the shell form so the backends only ever wrap an argv.
func shellArgv(command string) []string { return []string{"/bin/sh", "-c", command} }

// recompileLocked ensures the compiled snapshot matches src.Current() for a
// dynamic executor, applying the read-only mask when this is a ReadOnlyView. It
// is a no-op when the mode has not changed since the last compile. On a genuine
// mode change (haveMode already set) it bumps policyGen so grants bound to the
// prior generation stop verifying (SPEC §8, §9.2). The caller holds e.mu (or is
// the single-threaded constructor). It returns the compile error; the null
// backend never errors.
func (e *Executor) recompileLocked() error {
	m := e.src.Current()
	if e.haveMode && m == e.lastMode {
		return nil
	}
	p := PolicyFor(m, e.workspace, e.popts...)
	if e.readOnly {
		p = readOnlyMask(p)
	}
	// Ack gate: a mode flip to Unconfined without WithAckUnconfined in popts must
	// fail the spawn CLOSED (via resolve) rather than silently run unconfined. Keep
	// the last good compiled state and do not advance the generation on refusal.
	// This intentionally validates the POST-readOnlyMask policy: readOnlyMask zeroes
	// Net (clearing Net.Open), so a ReadOnlyView of a policy that was unconfined only
	// via Net.Open genuinely is no longer net-unconfined and correctly stops tripping
	// the ack gate after masking.
	if err := validatePolicy(p); err != nil {
		return err
	}
	spec, report, level, bits, err := e.backend.compile(p)
	if err != nil {
		// Keep the last good compiled state; do not advance the generation.
		return err
	}
	if e.haveMode {
		e.policyGen++ // a real mode change invalidates prior grants
	}
	e.policy = p
	e.spec = spec
	e.report = report
	e.level = level
	e.guaranteeBits = bits
	e.env = assembleEnv(p)
	e.lastMode = m
	e.haveMode = true
	return nil
}

// resolve returns the compiled snapshot for a single spawn, plus an error that
// every spawn path propagates so a never-compiled or freshly-failed executor
// fails CLOSED rather than spawning with a nil transform.
//
//   - Static executor: reads the immutable fields with no lock. Returns
//     e.compileErr, which is nil for a normally-constructed executor and non-nil
//     only for a static ReadOnlyView whose one-time compile failed.
//   - Dynamic executor: takes e.mu, recompiles if the mode changed (bumping
//     policyGen), and reads the fresh snapshot under the same lock so a spawn
//     never tears across a generation change. A live recompile failure is
//     returned (fail-closed for this spawn); a self-healing later mode may
//     compile cleanly.
//
// As a final guard the resolved spawnSpec is checked: an uncompiled spec (nil
// wrap) yields an error instead of a later nil-func call.
func (e *Executor) resolve() (snapshot, error) {
	if e.src == nil {
		s := snapshot{spec: e.spec, env: e.env, policy: e.policy, policyGen: e.policyGen}
		return s, e.resolveErr(e.compileErr)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	err := e.recompileLocked()
	s := snapshot{spec: e.spec, env: e.env, policy: e.policy, policyGen: e.policyGen}
	return s, e.resolveErr(err)
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
// interposed (SPEC §6, §10.1) — for tools that already build argv safely. Same
// exit-code/error convention as RunCommand: key on err, not the numeric code, to
// detect a process that did not complete normally (spawn failure, signal kill,
// or context cancellation all report code -1).
func (e *Executor) RunArgv(ctx context.Context, dir string, argv []string) ([]byte, int, error) {
	s, err := e.resolve()
	if err != nil {
		return nil, -1, err
	}
	return e.run(ctx, dir, argv, s)
}

// run is the shared execution path for RunCommand, RunArgv, and
// RunCommandWithGrants. It hands the backend the (dir, innerArgv) via the
// snapshot's spawnSpec.wrap to obtain the final argv plus a fresh per-spawn
// configure/cleanup pair, builds the command, applies the snapshot's environment
// and the backend's spawn attributes, runs it, and normalizes the result to the
// (output, exit, err) convention. The snapshot is read once by the caller (via
// resolve) so a concurrent dynamic recompile cannot change the env or spawn
// transform mid-spawn; each wrap call yields its own closures, so concurrent
// spawns never share per-spawn state.
func (e *Executor) run(ctx context.Context, dir string, innerArgv []string, s snapshot) ([]byte, int, error) {
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

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
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
		configure(cmd)
	}

	out, err := cmd.CombinedOutput()

	// A context timeout/cancel DURING the run surfaces as a signal kill (an
	// ExitError with code -1), which would otherwise be reported as a nil-error
	// non-zero run. Check the context first so a deadline/cancel is a visible
	// error, symmetric with cancel-before-start.
	if ctx.Err() != nil {
		return out, -1, ctx.Err()
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
// (SPEC §6). The zero value LevelNone is fail-closed. For a dynamic executor it
// reports the last compiled mode's level (it does not itself recompile) under
// the mutex, so it is race-free against a concurrent spawn's recompile.
func (e *Executor) Level() uint8 {
	if e.src == nil {
		return e.level
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.level
}

// Report returns the per-feature compilation outcomes for the chosen backend
// (SPEC §7.5): what was enforced, narrowed, or left unenforced. See Level for the
// dynamic-executor locking note.
func (e *Executor) Report() CompileReport {
	if e.src == nil {
		return e.report
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.report
}

// Guarantees returns the rich per-property statement of what the backend
// actually enforced (SPEC §6, §10.3). Each field is fail-closed. See Level for
// the dynamic-executor locking note.
func (e *Executor) Guarantees() Guarantees { return guaranteesFromBits(e.GuaranteeBits()) }

// GuaranteeBits returns the same guarantees as the seam-facing bitmask so a
// consumer can probe interface{ GuaranteeBits() uint64 } without importing this
// package (SPEC §6, §10.3). See Level for the dynamic-executor locking note.
func (e *Executor) GuaranteeBits() uint64 {
	if e.src == nil {
		return e.guaranteeBits
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.guaranteeBits
}

// netBlocked reports whether a policy grants no outbound network at all: no
// address class (Loopback/Private/DNS/Open) and no explicit ports. It is the
// signal PlanGrants uses to decide the network capability is currently denied.
func netBlocked(p Policy) bool {
	n := p.Net
	return !n.Loopback && !n.Private && !n.DNS && !n.Open && len(n.Ports) == 0
}

// PlanGrants mints CANDIDATE grant tokens for capabilities the current compiled
// policy blocks (SPEC §9.2). Each token is bound to (dir, command), the current
// policy generation, and an expiry (clock + grantTTL), and carries a MAC-covered
// description so the approval prompt cannot be inflated.
//
// For this task the only planned axis is network: when the policy blocks egress
// (netBlocked) a single "net" delta is offered. A ReadOnlyView never plans grants
// — the read path never escalates — so it returns nil immediately.
//
// An external executor (LevelExternal) also plans nothing: its zero-Net policy
// would trip netBlocked, but egress there is infra-handled and the boundary is
// already fully trusted, so offering an "allow network egress" escalation would
// be incoherent. A resolve failure (uncompiled view) likewise yields nil — no
// escalation from a fail-closed executor.
//
// Task 9: a per-command classifier ("does THIS command actually need net") will
// gate the candidate; here we plan purely from the policy-denied axes.
func (e *Executor) PlanGrants(dir, command string) []string {
	// e.src == nil guards the e.level read: LevelExternal is only ever set on a
	// static external executor, so a dynamic executor short-circuits before the
	// read and never races recompileLocked's write of e.level.
	if e.readOnly || (e.src == nil && e.level == LevelExternal) {
		return nil
	}
	s, err := e.resolve()
	if err != nil {
		return nil
	}

	var tokens []string
	if netBlocked(s.policy) {
		tok, err := mintGrant(e.grantKey, grantPayload{
			PolicyGen:   s.policyGen,
			CmdHash:     hashCommand(dir, command),
			Delta:       "net",
			Description: "allow network egress for: " + command,
			Expiry:      e.clock().Add(e.grantTTL),
		})
		if err == nil { // skip the candidate on a mint failure
			tokens = append(tokens, tok)
		}
	}
	return tokens
}

// DescribeGrant MAC-verifies a token and returns its bound, MAC-covered
// description for prompt display (SPEC §9.2). A fabricated or tampered token
// fails verification and returns ("", false), so it can never even generate an
// approval prompt. It does NOT check expiry or binding — a genuine-but-stale
// token can still be described; never authorize a spawn on this result.
func (e *Executor) DescribeGrant(token string) (string, bool) {
	p, err := decodeGrantForDisplay(e.grantKey, token)
	if err != nil {
		return "", false
	}
	return p.Description, true
}

// RunCommandWithGrants verifies each supplied grant against the current policy
// generation and the exact (dir, command), then — only if every grant is valid —
// applies the deltas and runs the command (SPEC §9.2, §9.3). If ANY grant fails
// verification it returns a typed error wrapping the sentinel (errors.Is finds
// ErrGrantExpired/ErrGrantWrongGeneration/…) and does NOT run.
//
// Delta application is a NO-OP on the null backend: null enforces nothing, so
// there is nothing to loosen for this one spawn. On a real OS backend each
// verified delta loosens the compiled policy for THIS spawn only (e.g. permit
// egress) before running; that per-spawn loosening lands with the OS backends.
//
// A ReadOnlyView fails closed on redeem as well as on mint: the read path never
// escalates, so even a grant its parent minted (shared key, same generation)
// cannot loosen a view whose policy forced writes off and Net blocked.
func (e *Executor) RunCommandWithGrants(ctx context.Context, dir, command string, grants []string) ([]byte, int, error) {
	if e.readOnly {
		return nil, -1, errors.New("sandbox: granting disabled on read-only view")
	}
	s, err := e.resolve()
	if err != nil {
		return nil, -1, err
	}
	now := e.clock()
	want := hashCommand(dir, command)
	for _, tok := range grants {
		if _, verr := verifyGrant(e.grantKey, tok, now, s.policyGen, want); verr != nil {
			return nil, -1, fmt.Errorf("grant: %w", verr)
		}
	}
	return e.run(ctx, dir, shellArgv(command), s)
}

// readOnlyMask derives a read-only policy: every FS entry's WriteAccess bit is
// masked off (deny entries, whose Access is zero, are unaffected) and the network
// is forced blocked (SPEC §6, §10.1). It returns a copy; the input is not
// mutated, so the parent's compiled policy is untouched.
func readOnlyMask(p Policy) Policy {
	out := p
	fs := make([]FSEntry, len(p.FS))
	for i, entry := range p.FS {
		entry.Access &^= WriteAccess
		fs[i] = entry
	}
	out.FS = fs
	out.Net = NetPolicy{} // forced blocked
	return out
}

// ReadOnlyView returns a derived executor for read-path tools (e.g. Grep, SPEC
// §10.1): it shares the parent's policy source (a static policy or the same
// ModeSource) and REUSES the parent's already-probed backend — no re-probe —
// recompiling the write-stripped, Net-blocked policy through it (so its own
// level/report/guarantees reflect the masked policy). Granting is disabled on
// both sides: PlanGrants returns nil and RunCommandWithGrants fails closed — the
// read path never escalates. For a dynamic parent the mask is applied on every
// recompile.
//
// The signature has no error return (SPEC §6), so a construction-time compile
// failure is latched: a static view stores it in compileErr and a dynamic view
// re-attempts on each resolve — either way spawns fail CLOSED rather than
// panicking on a nil spawnSpec.
func (e *Executor) ReadOnlyView() *Executor {
	v := &Executor{
		backend:      e.backend, // reuse the parent's probe result; do NOT re-select
		grantKey:     e.grantKey,
		policyGen:    1,
		clock:        e.clock,
		grantTTL:     e.grantTTL,
		cgroupParent: e.cgroupParent,
		readOnly:     true,
		src:          e.src,
		workspace:    e.workspace,
		popts:        e.popts,
	}
	if e.src != nil {
		// Dynamic parent: compile the current mode through the mask now so the view
		// is usable before its first spawn; recompiles re-apply the mask. A failure
		// here re-surfaces on the next resolve (haveMode stays false), so it need
		// not be latched.
		_ = v.recompileLocked()
		return v
	}
	// Static parent: mask the parent's compiled policy once and recompile it
	// through the reused backend. Latch any failure so resolve fails closed.
	p := readOnlyMask(e.policy)
	spec, report, level, bits, err := e.backend.compile(p)
	if err != nil {
		v.compileErr = err
		return v
	}
	v.policy = p
	v.spec = spec
	v.report = report
	v.level = level
	v.guaranteeBits = bits
	v.env = assembleEnv(p)
	return v
}

// Wrap applies the sandbox to a caller-built *exec.Cmd for non-harness users
// (SPEC §6). It wraps the command's argv via the backend's spawnSpec, forces the
// scrubbed environment (enforcing the env scrub even for externally constructed
// commands), and applies any backend spawn attributes. On the null backend this
// effectively just replaces cmd.Env with the scrubbed environment.
//
// Wrap hands the *exec.Cmd back for the caller to run, so — unlike RunCommand/
// RunArgv — it cannot own the spawn's lifetime. A backend that allocates
// per-spawn resources needing teardown (a non-nil cleanup from wrap) therefore
// cannot be driven through Wrap: rather than silently leak that resource, Wrap
// fails closed with an error. Every backend that returns a nil cleanup
// (null, seatbelt, and Linux spawns with no transient cgroup) works through Wrap.
func (e *Executor) Wrap(cmd *exec.Cmd) (*exec.Cmd, error) {
	s, err := e.resolve()
	if err != nil {
		return nil, err
	}
	finalArgv, configure, cleanup := s.spec.wrap(cmd.Dir, cmd.Args)
	if cleanup != nil {
		cleanup() // release what wrap allocated; we cannot defer it across the caller's Run
		return nil, errors.New("sandbox: this backend allocates per-spawn resources and cannot be used via Wrap; use RunCommand/RunArgv")
	}
	if len(finalArgv) == 0 {
		return nil, errors.New("sandbox: cannot wrap a command with empty Args")
	}
	cmd.Path = finalArgv[0]
	cmd.Args = finalArgv
	cmd.Env = s.env
	if cmd.Env == nil {
		cmd.Env = []string{} // same fail-closed guard as run
	}
	if cmd.WaitDelay == 0 {
		cmd.WaitDelay = spawnWaitGrace // default deadline-latency bound; the caller may override
	}
	if configure != nil {
		configure(cmd)
	}
	return cmd, nil
}

// assembleEnv builds the child environment from a Policy's EnvPolicy (SPEC §5.5).
// It is shared by every backend and lives on the executor side because env
// scrubbing holds regardless of OS mechanism.
//
//   - Inherit: start from the full parent environment (os.Environ), then force
//     the Set overrides. Used by unconfined and explicit opt-in.
//   - otherwise (the fail-closed default): keep only parent variables whose NAME
//     matches the §5.5 baseline allowlist or one of EnvPolicy.Allow (name globs
//     via filepath.Match), then force the Set overrides (including TMPDIR).
//     Everything else — GITHUB_TOKEN, AWS_*, LLM keys, SSH_AUTH_SOCK, … — is
//     absent.
//
// The result is a KEY=VALUE slice suitable for exec.Cmd.Env.
func assembleEnv(p Policy) []string {
	if p.Env.Inherit {
		return applySet(os.Environ(), p.Env.Set)
	}

	// Baseline allowlist plus caller additions. BaselineEnvAllowlist returns a
	// fresh slice, so appending never mutates the shared preset.
	allow := append(BaselineEnvAllowlist(), p.Env.Allow...)

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

// applySet forces the EnvPolicy.Set values onto an assembled env slice: an
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
