package sandbox

import "path/filepath"

// PolicyOption adjusts a Policy during expansion. Options are applied in order
// after the mode preset seeds the builder, so later options observe and extend
// the mode's choices (e.g. WithEnv merges into the mode's env, WithWritable adds
// to the mode's writable roots).
type PolicyOption func(*policyBuilder)

// policyBuilder holds the semantic intent of a mode plus any option
// adjustments; build materializes it into a Policy's FSEntry list. Keeping the
// intent separate from the flattened FS list lets options compose (add writable
// roots, drop the secret denials, merge env) before a single ordered emission.
type policyBuilder struct {
	workspace string

	// Filesystem intent.
	fullAccess    bool // {"/" : Read|Write|Exec} — unconfined
	broadRead     bool // {"/" : Read|Exec} — readonly/write/trusted
	systemReads   bool // MinimalSystemReadPaths (Read|Exec) — zerotrust
	workspaceRead bool // {ws : Read} — zerotrust
	workspaceRW   bool // {ws : Read|Write|Exec} — write/trusted
	tmpWrite      bool // {"/tmp" : Read|Write|Exec} — write/trusted
	applySecrets  bool // append DefaultSecretDenials as DenyAccess entries

	extraWritable []string // WithWritable additions (Read|Write|Exec project roots)
	carveoutNames []string // ".git", ".looprig" + WithCarveouts additions
	extraDenies   []string // WithDenyRead globs

	net    NetPolicy
	env    EnvPolicy
	limits Limits

	ackUnconfined bool
}

// writableTmpRoot is the single writable tmp root (SPEC §5.1). TMPDIR (§5.5) is
// pinned to it and, in write/trusted, it is the FS grant — the const keeps the
// two in lockstep.
const writableTmpRoot = "/tmp"

// nullDevicePath is process plumbing rather than persistent storage. Programs
// commonly open it read-write during startup even when their actual work is
// read-only, so every mode grants access without weakening a filesystem write
// boundary.
const nullDevicePath = "/dev/null"

// baselineEnv is the non-unconfined environment posture: no inheritance of the
// harness process environment, with TMPDIR set uniformly to /tmp
// (writableTmpRoot) in every non-unconfined mode — regardless of whether /tmp is
// actually writable in that mode (zerotrust/readonly set TMPDIR but grant no
// write to /tmp) — so tools never reach for an out-of-policy $TMPDIR such as
// macOS /var/folders/... (SPEC §5.1, §5.5). The baseline allowlist
// (BaselineEnvAllowlist) is implicit and applied at env-assembly time in a later
// task; it is not stored in Allow.
func baselineEnv() EnvPolicy {
	return EnvPolicy{
		Inherit: false,
		Set:     map[string]string{"TMPDIR": writableTmpRoot},
	}
}

// PolicyFor expands a mode into a fully materialized Policy for the given
// workspace, then applies options (SPEC §4, §5). It only builds the Policy
// shape: resolution of overlapping FS entries (deny > write > read), env
// assembly, and the metadata-deny invariant belong to later tasks and backends.
func PolicyFor(mode Mode, workspace string, opts ...PolicyOption) Policy {
	b := &policyBuilder{
		workspace:     filepath.Clean(workspace),
		carveoutNames: []string{".git", ".looprig"},
	}

	switch mode {
	case ZeroTrust:
		b.seedZeroTrust()
	case ReadOnly:
		b.broadRead = true
		b.applySecrets = true
		b.net = NetPolicy{} // gated; nothing OS-granted here
		b.env = baselineEnv()
	case Write:
		b.broadRead = true
		b.workspaceRW = true
		b.tmpWrite = true
		b.applySecrets = true
		b.net = NetPolicy{} // gated
		b.env = baselineEnv()
	case Trusted:
		b.broadRead = true
		b.workspaceRW = true
		b.tmpWrite = true
		b.applySecrets = true
		b.net = NetPolicy{Loopback: true, Private: true, Ports: []uint16{443}, DNS: true}
		b.env = baselineEnv()
	case Unconfined:
		b.fullAccess = true
		b.applySecrets = false // no deny-reads, no metadata invariant, no carveouts
		b.net = NetPolicy{Open: true}
		b.env = EnvPolicy{Inherit: true}
	default:
		// An out-of-range Mode fails closed to ZeroTrust (the most restrictive
		// mode), never to an all-denied policy with a zero EnvPolicy (no
		// baseline, no TMPDIR).
		b.seedZeroTrust()
	}

	for _, opt := range opts {
		opt(b)
	}

	return b.build()
}

// seedZeroTrust applies the ZeroTrust preset: workspace read-only, minimal
// system reads, secret deny-reads, network hard-denied, baseline env.
func (b *policyBuilder) seedZeroTrust() {
	b.workspaceRead = true
	b.systemReads = true
	b.applySecrets = true
	b.net = NetPolicy{} // hard-deny
	b.env = baselineEnv()
}

// build flattens the builder's intent into an ordered FSEntry list: reads, then
// writable roots, then read-only carveouts, then deny entries. Ordering is for
// readability only — the FS resolver in a later task decides precedence.
func (b *policyBuilder) build() Policy {
	var fs []FSEntry

	// Reads.
	if b.fullAccess {
		fs = append(fs, FSEntry{Path: "/", Access: ReadAccess | WriteAccess | ExecAccess})
	}
	if b.broadRead {
		fs = append(fs, FSEntry{Path: "/", Access: ReadAccess | ExecAccess})
	}
	if b.systemReads {
		for _, p := range MinimalSystemReadPaths() {
			fs = append(fs, FSEntry{Path: p, Access: ReadAccess | ExecAccess})
		}
	}
	if b.workspaceRead {
		fs = append(fs, FSEntry{Path: b.workspace, Access: ReadAccess})
	}

	// The null device safely discards writes and is required by ordinary
	// toolchains (including Git). Keep it explicit so read-only modes do not need
	// a broad writable system path.
	fs = append(fs, FSEntry{Path: nullDevicePath, Access: ReadAccess | WriteAccess})

	// Writable project roots (workspace + WithWritable). These are the roots
	// that carry read-only carveouts.
	var writableRoots []string
	if b.workspaceRW {
		fs = append(fs, FSEntry{Path: b.workspace, Access: ReadAccess | WriteAccess | ExecAccess})
		writableRoots = append(writableRoots, b.workspace)
	}
	for _, w := range b.extraWritable {
		w = filepath.Clean(w)
		fs = append(fs, FSEntry{Path: w, Access: ReadAccess | WriteAccess | ExecAccess})
		writableRoots = append(writableRoots, w)
	}

	// Writable tmp root — no carveouts (SPEC §5.1: carveouts live under project
	// roots, not the shared tmp root).
	if b.tmpWrite {
		fs = append(fs, FSEntry{Path: writableTmpRoot, Access: ReadAccess | WriteAccess | ExecAccess})
	}

	// Carveouts: re-mask protected subpaths of each writable project root
	// read-only (SPEC §5.1) so the agent cannot rewrite history or its own
	// configuration.
	for _, root := range writableRoots {
		for _, name := range b.carveoutNames {
			fs = append(fs, FSEntry{Path: filepath.Join(root, name), Access: ReadAccess})
		}
	}

	// Secret deny-reads (SPEC §5.3). Emitted as DenyAccess entries; the FS
	// resolver makes deny win in a later task.
	if b.applySecrets {
		for _, p := range DefaultSecretDenials() {
			fs = append(fs, FSEntry{Path: p, Access: DenyAccess})
		}
	}
	for _, g := range b.extraDenies {
		fs = append(fs, FSEntry{Path: g, Access: DenyAccess})
	}

	return Policy{
		Workspace:     b.workspace,
		FS:            fs,
		Net:           b.net,
		Env:           b.env,
		Limits:        b.limits,
		AckUnconfined: b.ackUnconfined,
	}
}

// WithWritable adds an OS-writable project root beyond the mode default. The
// root also receives the read-only carveouts (.git, .looprig, and any
// WithCarveouts additions).
func WithWritable(path string) PolicyOption {
	return func(b *policyBuilder) { b.extraWritable = append(b.extraWritable, path) }
}

// WithDenyRead adds a deny-read entry (a path or glob) beyond the default secret
// denials.
func WithDenyRead(glob string) PolicyOption {
	return func(b *policyBuilder) { b.extraDenies = append(b.extraDenies, glob) }
}

// WithNet replaces the mode's network policy wholesale.
func WithNet(n NetPolicy) PolicyOption {
	return func(b *policyBuilder) { b.net = n }
}

// WithEnv merges into the mode's environment policy: Allow entries are appended,
// Set values are merged (later keys win), and Inherit is OR-ed in. TMPDIR set by
// the mode survives unless the caller's Set overrides it.
func WithEnv(e EnvPolicy) PolicyOption {
	return func(b *policyBuilder) {
		if e.Inherit {
			b.env.Inherit = true
		}
		b.env.Allow = append(b.env.Allow, e.Allow...)
		if len(e.Set) > 0 {
			if b.env.Set == nil {
				b.env.Set = make(map[string]string, len(e.Set))
			}
			for k, v := range e.Set {
				b.env.Set[k] = v
			}
		}
	}
}

// WithLimits replaces the mode's resource limits.
func WithLimits(l Limits) PolicyOption {
	return func(b *policyBuilder) { b.limits = l }
}

// WithCarveouts adds names re-masked read-only inside every writable project
// root, on top of the default .git and .looprig.
func WithCarveouts(names ...string) PolicyOption {
	return func(b *policyBuilder) { b.carveoutNames = append(b.carveoutNames, names...) }
}

// WithoutSecretDenials drops the default §5.3 secret deny-reads. This is an
// explicit, loggable loosening of a security default and should be surfaced to
// the operator, not applied silently.
func WithoutSecretDenials() PolicyOption {
	return func(b *policyBuilder) { b.applySecrets = false }
}

// WithAckUnconfined sets Policy.AckUnconfined. Unconfined access requires this
// acknowledgement; the validation that ties the two together lives in a later
// task — PolicyFor only records the flag.
func WithAckUnconfined() PolicyOption {
	return func(b *policyBuilder) { b.ackUnconfined = true }
}
