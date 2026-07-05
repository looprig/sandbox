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

// fullGuarantees is every defined guarantee bit set — the FULL posture. Only an
// external executor asserts it, by explicit deployment declaration (SPEC §11);
// no probing ever mints it.
const fullGuarantees = GuaranteeProcessBoundary | GuaranteeWriteBoundary | GuaranteeReadDenies |
	GuaranteeEnvScrub | GuaranteeNetworkBoundary | GuaranteeAddressNetwork | GuaranteeResourceLimits

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
// Report/Guarantees. (AckUnconfined validation is a later task; NewExecutor does
// not perform it yet.)
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

	if !p.Env.Inherit {
		if _, err := os.UserHomeDir(); err != nil {
			return nil, fmt.Errorf("sandbox: cannot resolve home directory for secret deny-reads: %w", err)
		}
	}

	b := platformBackend()
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
func NewExternalExecutor(decl ExternalDecl) *Executor {
	b := newNullBackend()
	spec, _, _, _, _ := b.compile(Policy{}) // passthrough spawnSpec only
	p := Policy{Env: decl.Env}

	// A grant key lets PlanGrants/DescribeGrant work without panicking; crypto/rand
	// effectively never fails, and since construction cannot fail we fall back to a
	// nil key (HMAC over an empty key still verifies self-consistently) rather than
	// surface an error the signature has no room for.
	key, _ := newGrantKey()

	return &Executor{
		policy:        p,
		backend:       b,
		spec:          spec,
		report:        CompileReport{},
		level:         LevelExternal,
		guaranteeBits: fullGuarantees,
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
	s := e.resolve()
	return e.run(ctx, dir, s.spec.wrapShell(command), s)
}

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

// resolve returns the compiled snapshot for a single spawn. For a static
// executor it reads the immutable fields with no lock. For a dynamic executor it
// takes e.mu, recompiles if the mode changed (bumping policyGen), and reads the
// fresh snapshot under the same lock so a spawn never tears across a generation
// change. A recompile error is ignored here — the last good snapshot is reused —
// because construction already performed the first successful compile.
func (e *Executor) resolve() snapshot {
	if e.src == nil {
		return snapshot{spec: e.spec, env: e.env, policy: e.policy, policyGen: e.policyGen}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	_ = e.recompileLocked()
	return snapshot{spec: e.spec, env: e.env, policy: e.policy, policyGen: e.policyGen}
}

// RunArgv runs a direct argv in dir under the compiled policy, with no shell
// interposed (SPEC §6, §10.1) — for tools that already build argv safely. Same
// exit-code/error convention as RunCommand: key on err, not the numeric code, to
// detect a process that did not complete normally (spawn failure, signal kill,
// or context cancellation all report code -1).
func (e *Executor) RunArgv(ctx context.Context, dir string, argv []string) ([]byte, int, error) {
	s := e.resolve()
	return e.run(ctx, dir, s.spec.wrapArgv(argv), s)
}

// run is the shared execution path for RunCommand, RunArgv, and
// RunCommandWithGrants. It builds the command from a fully wrapped argv, applies
// the snapshot's environment and the backend's spawn attributes, and normalizes
// the result to the (output, exit, err) convention. The snapshot is read once by
// the caller (via resolve) so a concurrent dynamic recompile cannot change the
// env or spawn transform mid-spawn.
func (e *Executor) run(ctx context.Context, dir string, argv []string, s snapshot) ([]byte, int, error) {
	if len(argv) == 0 {
		return nil, -1, errors.New("sandbox: empty argv")
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = s.env
	// Belt-and-suspenders fail-closed guard: cmd.Env == nil makes exec.Cmd
	// inherit the entire parent environment. assembleEnv never returns nil, but a
	// truly empty child environment must be a non-nil empty slice so a future
	// change can never silently flip to inherit-all.
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	if s.spec.configure != nil {
		s.spec.configure(cmd)
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
// Task 9: a per-command classifier ("does THIS command actually need net") will
// gate the candidate; here we plan purely from the policy-denied axes.
func (e *Executor) PlanGrants(dir, command string) []string {
	if e.readOnly {
		return nil
	}
	s := e.resolve()

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
func (e *Executor) RunCommandWithGrants(ctx context.Context, dir, command string, grants []string) ([]byte, int, error) {
	s := e.resolve()
	now := e.clock()
	want := hashCommand(dir, command)
	for _, tok := range grants {
		if _, err := verifyGrant(e.grantKey, tok, now, s.policyGen, want); err != nil {
			return nil, -1, fmt.Errorf("grant: %w", err)
		}
	}
	return e.run(ctx, dir, s.spec.wrapShell(command), s)
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
// ModeSource) and REUSES the parent's already-probed backend and level — no
// re-probe — but strips writes from every FS entry, forces the network blocked,
// and disables granting (PlanGrants returns nil). For a dynamic parent the mask
// is applied on every recompile.
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
		// is usable before its first spawn; recompiles re-apply the mask.
		v.recompileLocked()
		return v
	}
	// Static parent: mask the parent's compiled policy once and recompile it
	// through the reused backend.
	p := readOnlyMask(e.policy)
	spec, report, level, bits, _ := e.backend.compile(p)
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
func (e *Executor) Wrap(cmd *exec.Cmd) (*exec.Cmd, error) {
	s := e.resolve()
	finalArgv := s.spec.wrapArgv(cmd.Args)
	if len(finalArgv) == 0 {
		return nil, errors.New("sandbox: cannot wrap a command with empty Args")
	}
	cmd.Path = finalArgv[0]
	cmd.Args = finalArgv
	cmd.Env = s.env
	if cmd.Env == nil {
		cmd.Env = []string{} // same fail-closed guard as run
	}
	if s.spec.configure != nil {
		s.spec.configure(cmd)
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
