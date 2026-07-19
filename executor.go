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

// Executor compiles a effectivePolicy once via the platform backend and then runs
// commands under the resulting stateless per-spawn transform (SPEC §6, §7). It
// holds the compiled policy, the chosen backend, its spawnSpec, the compilation
// report, the achieved level and guarantee bits, and the assembled child
// environment — everything a spawn needs, precomputed at construction.
type Executor struct {
	profile       *Profile
	policy        effectivePolicy
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
}

// snapshot is the compiled state a single spawn needs, read atomically so a
// concurrent dynamic recompile cannot tear a spawn across two generations. For a
// static executor it mirrors the immutable fields; for a dynamic one it is read
// under mu right after any needed recompile.
type snapshot struct {
	spec      spawnSpec
	env       []string
	policy    effectivePolicy
	policyGen uint64
}

// NewExecutor selects a backend and compiles one immutable profile. Profile
// validation is platform-independent; backend availability is checked here.
func NewExecutor(profile *Profile, opts ...ExecOption) (*Executor, error) {
	p, err := compileEffectivePolicy(profile)
	if err != nil {
		return nil, err
	}
	return newExecutorFromEffective(profile, p, opts...)
}

func newExecutorFromEffective(profile *Profile, p effectivePolicy, opts ...ExecOption) (*Executor, error) {
	var cfg execConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	// Backend selection: platformBackend() for production; a test may pin one via
	// the unexported withBackend seam so executor UNIT tests stay backend-independent.
	// platformBackend can fail (an unsupported platform, or — on Linux — a re-exec
	// backend selected without Init() having been called), which fails construction
	// closed rather than building an executor that would spawn incorrectly.
	b := cfg.backend
	if b == nil {
		if profile != nil && profile.isolation == Unconfined {
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

	key, err := newGrantKey()
	if err != nil {
		return nil, fmt.Errorf("sandbox: grant key: %w", err)
	}

	return &Executor{
		profile:       profile,
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

// resolve returns the immutable compiled snapshot for one spawn.
func (e *Executor) resolve() (snapshot, error) {
	s := snapshot{spec: e.spec, env: e.env, policy: e.policy, policyGen: e.policyGen}
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
	return e.level
}

// Report returns the per-feature compilation outcomes for the chosen backend
// (SPEC §7.5): what was enforced, narrowed, or left unenforced. See Level for the
// dynamic-executor locking note.
func (e *Executor) Report() CompileReport {
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
	return e.guaranteeBits
}

// netBlocked reports whether a policy grants no outbound network at all: no
// address class (Loopback/Private/DNS/Open) and no explicit ports. It is the
// signal PlanGrants uses to decide the network capability is currently denied.
func netBlocked(p effectivePolicy) bool {
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
// Task 9: a per-command classifier ("does THIS command actually need net") will
// gate the candidate; here we plan purely from the policy-denied axes.
func (e *Executor) PlanGrants(dir, command string) []string {
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

// assembleEnv builds the child environment from a effectivePolicy's effectiveEnvPolicy (SPEC §5.5).
// It is shared by every backend and lives on the executor side because env
// scrubbing holds regardless of OS mechanism.
//
//   - Inherit: start from the full parent environment (os.Environ), then force
//     the Set overrides. Used by unconfined and explicit opt-in.
//   - otherwise (the fail-closed default): keep only parent variables whose NAME
//     matches the §5.5 baseline allowlist or one of effectiveEnvPolicy.Allow (name globs
//     via filepath.Match), then force the Set overrides (including TMPDIR).
//     Everything else — GITHUB_TOKEN, AWS_*, LLM keys, SSH_AUTH_SOCK, … — is
//     absent.
//
// The result is a KEY=VALUE slice suitable for exec.Cmd.Env.
func assembleEnv(p effectivePolicy) []string {
	if p.Env.Inherit {
		return applySet(os.Environ(), p.Env.Set)
	}

	// Baseline allowlist plus caller additions. baselineEnvAllowlist returns a
	// fresh slice, so appending never mutates the shared preset.
	allow := append(baselineEnvAllowlist(), p.Env.Allow...)

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

// applySet forces the effectiveEnvPolicy.Set values onto an assembled env slice: an
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
