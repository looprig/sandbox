package sandbox

// Mode is the single user-facing knob bundling OS enforcement and gate posture
// coherently (SPEC §4). The modes form an ordered ladder from most to least
// restrictive; the zero value is the most restrictive (fail-closed).
type Mode uint8

const (
	// ZeroTrust is the most restrictive mode and the zero value: writes denied,
	// reads limited to the workspace and minimal system paths, network
	// hard-denied. Fail-closed.
	ZeroTrust Mode = iota
	// ReadOnly permits broad host reads but no writes (writes are gated) and
	// gated network.
	ReadOnly
	// Write confines writes to the workspace and tmp, with gated network.
	Write
	// Trusted is the maximum sandboxed tier: still workspace+tmp write-confined,
	// but with default egress to HTTPS, DNS, loopback, and private networks
	// (RFC1918 + ULA; see NetPolicy.Private).
	Trusted
	// Unconfined steps off the ladder entirely: no wrapper applied, full
	// user-level authority. Constructing it requires Policy.AckUnconfined.
	Unconfined
)

// FSAccess is a bitmask describing filesystem access to a path (SPEC §5.1). The
// zero value grants no access (fail-closed). Read, exec, and write are separate
// bits and OR-combine.
type FSAccess uint8

// DenyAccess is the zero value: no access (fail-closed).
const DenyAccess FSAccess = 0

const (
	// ReadAccess permits reading files and listing/traversing directories.
	ReadAccess FSAccess = 1 << iota // 1
	// ExecAccess permits executing binaries (Linux requires this explicitly).
	ExecAccess // 2
	// WriteAccess permits creating, modifying, and deleting.
	WriteAccess // 4
)

// FSEntry grants a set of filesystem accesses to a path (SPEC §5.1).
type FSEntry struct {
	// Path is absolute and supports glob patterns.
	Path string
	// Access is the set of permissions granted at Path.
	Access FSAccess
}

// NetPolicy describes permitted outbound network access (SPEC §5.2). The zero
// value blocks everything (fail-closed); domain-level allowlists are v2.
type NetPolicy struct {
	// Loopback permits traffic to loopback addresses.
	Loopback bool
	// Private permits traffic to RFC1918 and ULA ranges.
	Private bool
	// Ports lists outbound TCP ports permitted to any host, e.g. {443}.
	Ports []uint16
	// DNS permits name resolution (53/udp+tcp and platform resolver paths).
	DNS bool
	// Open permits unrestricted egress; unconfined only.
	Open bool
}

// containsPort reports whether ports contains p. It is a platform-independent
// helper on NetPolicy.Ports, used by the foreign-agent preset and every backend.
func containsPort(ports []uint16, p uint16) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}

// EnvPolicy controls the environment spawned commands inherit (SPEC §5.5). The
// zero value is the baseline allowlist (fail-closed): the harness process
// environment is not passed through.
type EnvPolicy struct {
	// Inherit passes the entire parent environment through; unconfined or
	// explicit opt-in only.
	Inherit bool
	// Allow lists names or globs added to the baseline allowlist,
	// e.g. "GOFLAGS", "CARGO_*".
	Allow []string
	// Set forces specific values; the sandbox always sets TMPDIR here.
	Set map[string]string
}

// Limits describes resource limits applied to spawned commands (SPEC §6, §7.4).
// The zero value means per-mode defaults apply.
type Limits struct {
	// MaxPIDs caps the number of processes/threads.
	MaxPIDs int
	// MaxMemBytes caps memory usage in bytes.
	MaxMemBytes int64
	// MaxCPUPct caps CPU usage as a percentage of a single core (100 = one full
	// core; may exceed 100 on multi-core hosts, e.g. 200 = two cores).
	MaxCPUPct int
	// Disabled is an explicit opt-out; the zero value means mode defaults apply.
	Disabled bool
}

// Policy is the fully expanded, orthogonal-axis description of what a spawned
// command may touch (SPEC §5, §6). Modes are presets that expand into a Policy;
// consumers may also construct or adjust one directly.
type Policy struct {
	// Workspace is the root the command operates within.
	Workspace string
	// FS is the fully expanded filesystem policy: mode preset + carveouts +
	// deny presets + consumer options.
	FS []FSEntry
	// Net is the network policy.
	Net NetPolicy
	// Env is the environment policy.
	Env EnvPolicy
	// Limits is the resource-limit policy; the zero value means mode defaults.
	Limits Limits
	// AckUnconfined must be true iff the policy grants unconfined access.
	AckUnconfined bool
}

// ExternalDecl is an explicit declaration that the surrounding environment is
// the isolation boundary (SPEC §11): a container, gVisor, or microVM. It is the
// only source of LevelExternal.
type ExternalDecl struct {
	// Boundary names the isolation mechanism: "docker", "gvisor",
	// "firecracker", "kata", or a free-form value.
	Boundary string
	// NetworkVia records what handles egress, e.g. "infra-proxy"; audit field.
	NetworkVia string
	// Note is free-form documentation.
	Note string
	// Env is the environment policy; scrubbing still applies inside external
	// boundaries.
	Env EnvPolicy
}

// ReportEntry records how one policy feature was compiled by a backend
// (SPEC §7.5): enforced, narrowed, or unenforced.
type ReportEntry struct {
	// Feature names the policy feature, e.g. "glob-deny" or "address-network".
	Feature string
	// Status is the compilation outcome, e.g. "enforced", "narrowed",
	// "unenforced".
	Status string
	// Detail is a human-readable explanation.
	Detail string
}

// CompileReport is the set of per-feature compilation outcomes for a backend
// (SPEC §7.5): what was enforced, narrowed, or left unenforced.
type CompileReport struct {
	// Entries is the per-feature compilation record.
	Entries []ReportEntry
}

// Isolation levels are the coarse, achieved (probed + compiled) isolation
// rollup reported by an executor (SPEC §6). They are plain uint8 values, not a
// named type, so harness can probe interface{ Level() uint8 } structurally
// without importing this package. The zero value is fail-closed.
const (
	// LevelNone means no isolation was achieved.
	LevelNone uint8 = iota
	// LevelDegraded means the write boundary holds but some policy features are
	// narrowed or unenforced.
	LevelDegraded
	// LevelFull means every policy feature was enforced by the mechanism.
	LevelFull
	// LevelExternal means the environment is the boundary, by explicit
	// declaration (NewExternalExecutor only).
	LevelExternal
)

// Guarantees is the machine-readable, per-property statement of what a backend
// actually enforced (SPEC §6, §10.3). Each field is fail-closed: false unless
// the backend genuinely enforced that property. The field order matches the
// Guarantee* bit constants below.
type Guarantees struct {
	// ProcessBoundary: the command was spawned inside an isolating boundary
	// (namespace / seatbelt / external).
	ProcessBoundary bool
	// WriteBoundary: writes were confined to policy-writable roots.
	WriteBoundary bool
	// ReadDenies: the §5.3 secret deny-reads were enforced for subprocesses.
	ReadDenies bool
	// EnvScrub: the child saw the EnvPolicy baseline; harness secrets absent.
	EnvScrub bool
	// NetworkBoundary: egress was restricted to policy (at least port-level).
	NetworkBoundary bool
	// AddressNetwork: address-scoped rules (Loopback/Private/metadata) enforced.
	AddressNetwork bool
	// ResourceLimits: cgroup/ulimit limits were applied.
	ResourceLimits bool
}

// Guarantee bits are the seam-facing bitmask form of Guarantees (SPEC §6,
// §10.3). They are plain uint64 values, not a named type, so harness can probe
// interface{ GuaranteeBits() uint64 } structurally without importing this
// package. Bit order matches the Guarantees struct field order.
const (
	// GuaranteeProcessBoundary mirrors Guarantees.ProcessBoundary.
	GuaranteeProcessBoundary uint64 = 1 << iota
	// GuaranteeWriteBoundary mirrors Guarantees.WriteBoundary.
	GuaranteeWriteBoundary
	// GuaranteeReadDenies mirrors Guarantees.ReadDenies.
	GuaranteeReadDenies
	// GuaranteeEnvScrub mirrors Guarantees.EnvScrub.
	GuaranteeEnvScrub
	// GuaranteeNetworkBoundary mirrors Guarantees.NetworkBoundary.
	GuaranteeNetworkBoundary
	// GuaranteeAddressNetwork mirrors Guarantees.AddressNetwork.
	GuaranteeAddressNetwork
	// GuaranteeResourceLimits mirrors Guarantees.ResourceLimits.
	GuaranteeResourceLimits
)

// guaranteesFromBits expands the seam-facing guarantee bitmask into the rich
// Guarantees struct. It is the inverse of Guarantees.bits: the two map the same
// seven bit positions to the same seven fields, in the same order. A backend
// reports guarantees as a bitmask (the stdlib-only seam form, §2); the executor
// stores those bits and expands them here for Guarantees().
func guaranteesFromBits(bits uint64) Guarantees {
	return Guarantees{
		ProcessBoundary: bits&GuaranteeProcessBoundary != 0,
		WriteBoundary:   bits&GuaranteeWriteBoundary != 0,
		ReadDenies:      bits&GuaranteeReadDenies != 0,
		EnvScrub:        bits&GuaranteeEnvScrub != 0,
		NetworkBoundary: bits&GuaranteeNetworkBoundary != 0,
		AddressNetwork:  bits&GuaranteeAddressNetwork != 0,
		ResourceLimits:  bits&GuaranteeResourceLimits != 0,
	}
}

// bits is the inverse of guaranteesFromBits: it folds the Guarantees struct back
// into the seam-facing bitmask. Keeping both directions adjacent makes the
// field/bit correspondence a single place to audit.
func (g Guarantees) bits() uint64 {
	var b uint64
	if g.ProcessBoundary {
		b |= GuaranteeProcessBoundary
	}
	if g.WriteBoundary {
		b |= GuaranteeWriteBoundary
	}
	if g.ReadDenies {
		b |= GuaranteeReadDenies
	}
	if g.EnvScrub {
		b |= GuaranteeEnvScrub
	}
	if g.NetworkBoundary {
		b |= GuaranteeNetworkBoundary
	}
	if g.AddressNetwork {
		b |= GuaranteeAddressNetwork
	}
	if g.ResourceLimits {
		b |= GuaranteeResourceLimits
	}
	return b
}
