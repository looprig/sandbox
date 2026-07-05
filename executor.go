package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

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

	// Stored for later tasks (grants, cgroups); unused in the executor core.
	grantTTL     time.Duration
	cgroupParent string
}

// NewExecutor selects the platform backend, compiles the policy, and assembles
// the child environment (SPEC §6). It returns an error only when the backend
// cannot compile the policy at all; a backend that enforces less than requested
// still constructs an executor and reports the shortfall via Level/Report/
// Guarantees. (The home-resolution guard and AckUnconfined validation are later
// tasks; NewExecutor does not perform them yet.)
func NewExecutor(p Policy, opts ...ExecOption) (*Executor, error) {
	var cfg execConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	b := platformBackend()
	spec, report, level, bits, err := b.compile(p)
	if err != nil {
		return nil, err
	}

	return &Executor{
		policy:        p,
		backend:       b,
		spec:          spec,
		report:        report,
		level:         level,
		guaranteeBits: bits,
		env:           assembleEnv(p),
		grantTTL:      cfg.grantTTL,
		cgroupParent:  cfg.cgroupParent,
	}, nil
}

// RunCommand runs a shell command string in dir under the compiled policy (SPEC
// §6, §10.1). It wraps the command via the backend's spawnSpec, sets the working
// directory and the assembled environment, applies any spawn attributes, and
// runs to completion capturing combined stdout+stderr.
//
// Convention: if the process RAN — even with a non-zero exit — the return is
// (output, exitCode, nil) carrying the real exit code. A non-nil error is
// returned only on a spawn/setup failure (missing dir, binary not found), in
// which case the exit code is a sentinel -1.
func (e *Executor) RunCommand(ctx context.Context, dir, command string) ([]byte, int, error) {
	return e.run(ctx, dir, e.spec.wrapShell(command))
}

// RunArgv runs a direct argv in dir under the compiled policy, with no shell
// interposed (SPEC §6, §10.1) — for tools that already build argv safely. Same
// exit-code/error convention as RunCommand.
func (e *Executor) RunArgv(ctx context.Context, dir string, argv []string) ([]byte, int, error) {
	return e.run(ctx, dir, e.spec.wrapArgv(argv))
}

// run is the shared execution path for RunCommand and RunArgv. It builds the
// command from a fully wrapped argv, applies the executor's environment and the
// backend's spawn attributes, and normalizes the result to the (output, exit,
// err) convention.
func (e *Executor) run(ctx context.Context, dir string, argv []string) ([]byte, int, error) {
	if len(argv) == 0 {
		return nil, -1, errors.New("sandbox: empty argv")
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir
	cmd.Env = e.env
	if e.spec.configure != nil {
		e.spec.configure(cmd)
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		// A ran-but-nonzero process is not an error under our convention: surface
		// the real exit code and a nil error.
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return out, ee.ExitCode(), nil
		}
		// A genuine spawn/setup failure: dir missing, binary not found, context
		// cancelled before start, etc.
		return out, -1, err
	}
	return out, 0, nil
}

// Level reports the achieved (probed + compiled, not requested) isolation level
// (SPEC §6). The zero value LevelNone is fail-closed.
func (e *Executor) Level() uint8 { return e.level }

// Report returns the per-feature compilation outcomes for the chosen backend
// (SPEC §7.5): what was enforced, narrowed, or left unenforced.
func (e *Executor) Report() CompileReport { return e.report }

// Guarantees returns the rich per-property statement of what the backend
// actually enforced (SPEC §6, §10.3). Each field is fail-closed.
func (e *Executor) Guarantees() Guarantees { return guaranteesFromBits(e.guaranteeBits) }

// GuaranteeBits returns the same guarantees as the seam-facing bitmask so a
// consumer can probe interface{ GuaranteeBits() uint64 } without importing this
// package (SPEC §6, §10.3).
func (e *Executor) GuaranteeBits() uint64 { return e.guaranteeBits }

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

	var kept []string
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
// allowlist patterns, using filepath.Match on the NAME (so "LC_*" and "CARGO_*"
// work). A malformed pattern fails closed: filepath.Match's error is treated as
// a non-match, so a bad glob never widens the allowlist.
func envNameMatches(name string, patterns []string) bool {
	for _, pat := range patterns {
		if ok, err := filepath.Match(pat, name); err == nil && ok {
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
	sort.Strings(add)
	for _, k := range add {
		env = append(env, k+"="+set[k])
	}
	return env
}
