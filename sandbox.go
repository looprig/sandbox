package sandbox

import (
	"context"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/exec"
	"github.com/looprig/sandbox/internal/windows"
	"github.com/looprig/sandbox/pkg/network"
	"github.com/looprig/sandbox/pkg/profile"
)

// This file is the module's public facade. Every identifier below is an alias
// or a thin forwarder to the package that owns the behaviour, so the import
// path `github.com/looprig/sandbox` remains the single stable surface while
// the implementation lives in `pkg/` and `internal/`. Aliases — not wrapper
// types — are used deliberately: a value produced by an inner package is the
// same type as the facade name, so consumers can mix the two freely and
// `errors.Is` keeps working against the re-exported sentinels.

// Access, Home, and Isolation are the consumer-selected authority enums.
type (
	// Access is the requested authority for one profile capability.
	Access = profile.Access
	// Home selects the HOME value exposed to a child process.
	Home = profile.Home
	// Isolation selects whether process authority is OS-confined.
	Isolation = profile.Isolation
	// RootAccess describes read and write authority for one additional root.
	RootAccess = profile.RootAccess
	// ProfileConfig contains every consumer-selected sandbox authority value.
	ProfileConfig = profile.ProfileConfig
	// Profile is an immutable, normalized access profile.
	Profile = profile.Profile
	// ReportEntry records how one requested feature was compiled by a backend.
	ReportEntry = profile.ReportEntry
	// CompileReport records enforced, narrowed, and unavailable features.
	CompileReport = profile.CompileReport
	// Guarantees reports properties actually enforced by the selected backend.
	Guarantees = profile.Guarantees
)

// Access values.
const (
	Deny  = profile.Deny
	Gated = profile.Gated
	Allow = profile.Allow
)

// Home values.
const (
	IsolatedHome = profile.IsolatedHome
	RealHome     = profile.RealHome
)

// Isolation values.
const (
	Sandboxed  = profile.Sandboxed
	Unconfined = profile.Unconfined
)

// Achieved enforcement levels.
const (
	LevelNone     = profile.LevelNone
	LevelDegraded = profile.LevelDegraded
	LevelFull     = profile.LevelFull
)

// Guarantee bits reported by a backend.
const (
	GuaranteeProcessBoundary = profile.GuaranteeProcessBoundary
	GuaranteeWriteBoundary   = profile.GuaranteeWriteBoundary
	GuaranteeReadBoundary    = profile.GuaranteeReadBoundary
	GuaranteeEnvScrub        = profile.GuaranteeEnvScrub
	GuaranteeNetworkBoundary = profile.GuaranteeNetworkBoundary
	GuaranteeAddressNetwork  = profile.GuaranteeAddressNetwork
	GuaranteeResourceLimits  = profile.GuaranteeResourceLimits
	GuaranteeTargetNetwork   = profile.GuaranteeTargetNetwork
)

// ErrInvalidProfile identifies malformed, unconstructed, or inconsistent
// profiles. Details are wrapped for diagnostics; callers may use errors.Is.
var ErrInvalidProfile = profile.ErrInvalidProfile

// NewProfile validates, canonicalizes, and owns a copy of config.
func NewProfile(config ProfileConfig) (*Profile, error) { return profile.NewProfile(config) }

// Restrict returns the component-wise intersection of base and ceiling.
func Restrict(base, ceiling *Profile) (*Profile, error) { return profile.Restrict(base, ceiling) }

// Egress vocabulary. The inner package drops the redundant Egress/Network
// prefixes its own name already supplies; the facade keeps the original spelling.
type (
	// NetworkTarget is one normalized transport/host/port egress destination.
	NetworkTarget = network.Target
	// EgressRoute is how a sandboxed process reaches the network.
	EgressRoute = network.Route
	// EgressRouteResolver selects a route per target.
	EgressRouteResolver = network.RouteResolver
	// NetworkTargetDeniedError reports a spawn that ran but was denied a target.
	NetworkTargetDeniedError = network.TargetDeniedError
)

// ErrEgressRouteDenied reports that no configured route may carry a target.
var ErrEgressRouteDenied = network.ErrRouteDenied

// ErrNetworkTargetDenied reports that the proxy refused a network target.
var ErrNetworkTargetDenied = network.ErrTargetDenied

// ParseNetworkTarget parses a normalized "transport:host:port" target.
func ParseNetworkTarget(raw string) (NetworkTarget, error) { return network.ParseTarget(raw) }

// NewDirectEgressRoute builds the route that dials targets itself.
func NewDirectEgressRoute() (EgressRoute, error) { return network.NewDirectRoute() }

// NewUpstreamEgressRoute builds a route that hands targets to an upstream proxy.
func NewUpstreamEgressRoute(rawURL string, trustedAddressGuarantee bool) (EgressRoute, error) {
	return network.NewUpstreamRoute(rawURL, trustedAddressGuarantee)
}

// NewEgressRouteResolver builds a resolver over the supplied routes.
func NewEgressRouteResolver(routes []EgressRoute, selector func(context.Context, NetworkTarget) string) (*EgressRouteResolver, error) {
	return network.NewRouteResolver(routes, selector)
}

// ErrSandboxUnavailable reports that no production OS confinement backend is
// available on this host, so a Sandboxed profile cannot be honoured.
var ErrSandboxUnavailable = enforce.ErrUnavailable

// Windows sandbox selection and elevated setup vocabulary.
type (
	WindowsSandboxMode      = windows.SandboxMode
	WindowsSetupConfig      = windows.SetupConfig
	WindowsSetupProblemCode = windows.WindowsSetupProblemCode
	WindowsSetupProblem     = windows.SetupProblem
	WindowsSetupStatus      = windows.SetupStatus
)

const (
	WindowsAuto            = windows.Auto
	WindowsRestrictedToken = windows.RestrictedToken
	WindowsElevated        = windows.Elevated

	WindowsSetupProblemUnknown               = windows.SetupProblemUnknown
	WindowsSetupProblemManifestMissing       = windows.SetupProblemManifestMissing
	WindowsSetupProblemOwnerMismatch         = windows.SetupProblemOwnerMismatch
	WindowsSetupProblemHostBinaryStale       = windows.SetupProblemHostBinaryStale
	WindowsSetupProblemServiceUnavailable    = windows.SetupProblemServiceUnavailable
	WindowsSetupProblemAccountMissing        = windows.SetupProblemAccountMissing
	WindowsSetupProblemCredentialUnavailable = windows.SetupProblemCredentialUnavailable
	WindowsSetupProblemFirewallOverridden    = windows.SetupProblemFirewallOverridden
	WindowsSetupProblemFirewallRuleChanged   = windows.SetupProblemFirewallRuleChanged
	WindowsSetupProblemPortInUse             = windows.SetupProblemPortInUse
	WindowsSetupProblemRuntimeBaselineGap    = windows.SetupProblemRuntimeBaselineGap
	WindowsSetupProblemLeaseRecoveryPending  = windows.SetupProblemLeaseRecoveryPending
	WindowsSetupProblemProtocolMismatch      = windows.SetupProblemProtocolMismatch
)

var (
	ErrWindowsSetupRequired     = windows.ErrSetupRequired
	ErrWindowsSetupStale        = windows.ErrSetupStale
	ErrWindowsElevationRequired = windows.ErrElevationRequired
)

func InspectWindowsSandbox(ctx context.Context, config WindowsSetupConfig) (WindowsSetupStatus, error) {
	return windows.Inspect(ctx, config)
}

func SetupWindowsSandbox(ctx context.Context, config WindowsSetupConfig) error {
	return windows.Setup(ctx, config)
}

func RemoveWindowsSandbox(ctx context.Context, config WindowsSetupConfig) error {
	return windows.Remove(ctx, config)
}

// Executor ownership. The executor and the single-spawn grant tokens it mints
// and verifies live in internal/exec; these are the names consumers use.
type (
	// Executor compiles a policy once and runs commands under it.
	Executor = exec.Executor
	// ExecutorSet owns per-key executors, their grant keys, and isolated HOMEs.
	ExecutorSet = exec.ExecutorSet
	// ExecutorSetOption configures executor ownership and resource limits.
	ExecutorSetOption = exec.ExecutorSetOption
)

// NewExecutorSet creates one owner-only child beneath a required scratch root.
func NewExecutorSet(p *Profile, options ...ExecutorSetOption) (*ExecutorSet, error) {
	return exec.NewExecutorSet(p, options...)
}

// WithScratchRoot supplies the caller-owned parent for the set's owned child.
func WithScratchRoot(path string) ExecutorSetOption { return exec.WithScratchRoot(path) }

// WithMaxExecutors sets the hard number of memoized executor identities.
func WithMaxExecutors(max int) ExecutorSetOption { return exec.WithMaxExecutors(max) }

// WithGrantTTL sets the maximum lifetime of grants minted by every executor.
func WithGrantTTL(duration time.Duration) ExecutorSetOption { return exec.WithGrantTTL(duration) }

// WithEgressRoute configures the explicit route used by target-scoped grants.
func WithEgressRoute(route EgressRoute) ExecutorSetOption { return exec.WithEgressRoute(route) }

// WithWindowsSandboxMode selects the Windows confinement tier.
func WithWindowsSandboxMode(mode WindowsSandboxMode) ExecutorSetOption {
	return exec.WithWindowsSandboxMode(mode)
}

// WithWindowsSandboxStateRoot selects the Windows elevated installation root.
func WithWindowsSandboxStateRoot(path string) ExecutorSetOption {
	return exec.WithWindowsSandboxStateRoot(path)
}

// Executor lifecycle sentinels.
var (
	ErrExecutorLimit     = exec.ErrExecutorLimit
	ErrExecutorSetClosed = exec.ErrExecutorSetClosed
	ErrExecutorClosed    = exec.ErrExecutorClosed
)

// Grant sentinels. Each is the single value raised anywhere in the module, so
// errors.Is answers the same regardless of which layer refused.
var (
	ErrGrantMalformed             = exec.ErrGrantMalformed
	ErrGrantBadMAC                = exec.ErrGrantBadMAC
	ErrGrantExpired               = exec.ErrGrantExpired
	ErrGrantWrongCommand          = exec.ErrGrantWrongCommand
	ErrGrantWrongExecution        = exec.ErrGrantWrongExecution
	ErrGrantWrongWorkingDirectory = exec.ErrGrantWrongWorkingDirectory
	ErrGrantProfileMismatch       = exec.ErrGrantProfileMismatch
	ErrGrantGuaranteeMismatch     = exec.ErrGrantGuaranteeMismatch
	ErrGrantRouteMismatch         = exec.ErrGrantRouteMismatch
	ErrGrantTargetChanged         = exec.ErrGrantTargetChanged
	ErrGrantReplay                = exec.ErrGrantReplay
	ErrGrantRequired              = exec.ErrGrantRequired
	ErrGrantDenied                = exec.ErrGrantDenied
	ErrGrantUnsupported           = exec.ErrGrantUnsupported
)

// Grant enforcement-class identifiers. These string VALUES are the shipped
// wire contract between this module and whatever mints grants against it.
const (
	GrantClassCommandStart        = exec.GrantClassCommandStart
	GrantClassNetworkProxyTarget  = exec.GrantClassNetworkProxyTarget
	GrantClassNetworkBroad        = exec.GrantClassNetworkBroad
	GrantClassFilesystemPathRead  = exec.GrantClassFilesystemPathRead
	GrantClassFilesystemTreeRead  = exec.GrantClassFilesystemTreeRead
	GrantClassFilesystemHostRead  = exec.GrantClassFilesystemHostRead
	GrantClassFilesystemPathWrite = exec.GrantClassFilesystemPathWrite
	GrantClassFilesystemTreeWrite = exec.GrantClassFilesystemTreeWrite
	GrantClassFilesystemHostWrite = exec.GrantClassFilesystemHostWrite
)

// Pipe-backed asynchronous process vocabulary. Executor.PrepareProcess (a
// method promoted through the Executor alias above) is this microtask's
// entry point; ProcessOptions/PreparedProcess/Process/ProcessResult are its
// request and result types. These are Sandbox's own named types: their
// method shapes structurally match Harness's
// tool.AsyncProcessRunner/PreparedProcess/Process (github.com/looprig/harness/
// pkg/tool) so a consumer can adapt between the two, but this module never
// imports Harness (SPEC's module-boundary rule).
type (
	// ProcessOptions describes one asynchronous process admission request.
	ProcessOptions = exec.ProcessOptions
	// PreparedProcess is a validated, single-use process start.
	PreparedProcess = exec.PreparedProcess
	// Process is a running asynchronous process with live stdio pipes.
	Process = exec.Process
	// ProcessResult is the terminal result of an asynchronous process.
	ProcessResult = exec.ProcessResult
	// ProcessAccess is the authoritative, immutable description of a
	// prepared process's workspace access.
	ProcessAccess = exec.ProcessAccess
	// ProcessAccessKind classifies ProcessAccess.
	ProcessAccessKind = exec.ProcessAccessKind
	// ProcessActivity reports one unit of workspace activity from a running
	// process.
	ProcessActivity = exec.ProcessActivity
	// ProcessActivityKind classifies ProcessActivity.
	ProcessActivityKind = exec.ProcessActivityKind
)

// ProcessAccessKind values.
const (
	ProcessAccessReadOnly    = exec.ProcessAccessReadOnly
	ProcessAccessScopedWrite = exec.ProcessAccessScopedWrite
	ProcessAccessBroadWrite  = exec.ProcessAccessBroadWrite
)

// ProcessActivityKind values.
const (
	ProcessActivityWrite      = exec.ProcessActivityWrite
	ProcessActivityBroadWrite = exec.ProcessActivityBroadWrite
)

// Process/PreparedProcess sentinels.
var (
	ErrProcessClosed         = exec.ErrProcessClosed
	ErrProcessAlreadyStarted = exec.ErrProcessAlreadyStarted
	ErrProcessTTYUnsupported = exec.ErrProcessTTYUnsupported
	// ErrProcessConPTYUnavailable reports that a TTY-backed process request
	// on Windows resolved to a host that does not export the
	// CreatePseudoConsole API (Windows 10 1809+ / Windows Server 2019+
	// only) — a runtime capability gap distinct from
	// ErrProcessTTYUnsupported's own compile-time/backend-dispatch checks.
	// See exec.ErrProcessConPTYUnavailable's own doc comment
	// (internal/exec/process_errors.go) for the full distinction.
	ErrProcessConPTYUnavailable = exec.ErrProcessConPTYUnavailable
	ErrProcessStdinClosed       = exec.ErrProcessStdinClosed
	// ErrLifetimeContainmentUnavailable reports that a Supervised (async,
	// PreparedProcess.Start) spawn cannot be given an exact, kernel-enforced
	// process-tree teardown proof before it starts, so it was rejected before
	// any child process was created rather than run with only a best-effort
	// process-group signal-and-poll fallback. On Darwin this is returned for
	// every real Seatbelt-confined Supervised spawn until a concrete
	// containment primitive is wired for this platform; on Linux it is
	// returned only when Rung 2 selects a spawn with no delegated cgroup v2
	// pids ancestor available.
	ErrLifetimeContainmentUnavailable = enforce.ErrLifetimeContainmentUnavailable
)
