package exec

import (
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/pkg/network"
	"github.com/looprig/sandbox/pkg/profile"
)

// The executor and its grant layer are written against the profile vocabulary,
// and the root facade re-exports the same names. Aliasing them here — rather
// than qualifying several hundred call sites — keeps this package's code and
// the facade spelled identically, which matters because the two are read
// together whenever the public contract is being checked.
type (
	Access        = profile.Access
	Home          = profile.Home
	Isolation     = profile.Isolation
	RootAccess    = profile.RootAccess
	Profile       = profile.Profile
	ProfileConfig = profile.ProfileConfig
	CompileReport = profile.CompileReport
	ReportEntry   = profile.ReportEntry
	Guarantees    = profile.Guarantees
)

const (
	Deny  = profile.Deny
	Gated = profile.Gated
	Allow = profile.Allow

	IsolatedHome = profile.IsolatedHome
	RealHome     = profile.RealHome

	Sandboxed  = profile.Sandboxed
	Unconfined = profile.Unconfined

	LevelNone     = profile.LevelNone
	LevelDegraded = profile.LevelDegraded
	LevelFull     = profile.LevelFull

	GuaranteeProcessBoundary = profile.GuaranteeProcessBoundary
	GuaranteeWriteBoundary   = profile.GuaranteeWriteBoundary
	GuaranteeReadBoundary    = profile.GuaranteeReadBoundary
	GuaranteeEnvScrub        = profile.GuaranteeEnvScrub
	GuaranteeNetworkBoundary = profile.GuaranteeNetworkBoundary
	GuaranteeAddressNetwork  = profile.GuaranteeAddressNetwork
	GuaranteeResourceLimits  = profile.GuaranteeResourceLimits
	GuaranteeTargetNetwork   = profile.GuaranteeTargetNetwork
)

// ErrInvalidProfile is re-exported so a profile rejection raised here is the
// same value consumers match at the facade.
var ErrInvalidProfile = profile.ErrInvalidProfile

// NewProfile is re-exported for this package's tests, which build profiles
// directly rather than through the facade.
func NewProfile(config ProfileConfig) (*Profile, error) { return profile.NewProfile(config) }

// Egress vocabulary, aliased for the same reason as the profile vocabulary above.
type (
	EgressRoute   = network.Route
	NetworkTarget = network.Target
)

// ParseNetworkTarget parses a normalized "transport:host:port" egress target.
func ParseNetworkTarget(raw string) (NetworkTarget, error) { return network.ParseTarget(raw) }

// Route constructors, aliased for this package's tests.
func NewDirectEgressRoute() (EgressRoute, error) { return network.NewDirectRoute() }

func NewUpstreamEgressRoute(rawURL string, trustedAddressGuarantee bool) (EgressRoute, error) {
	return network.NewUpstreamRoute(rawURL, trustedAddressGuarantee)
}

// Restrict returns the component-wise intersection of base and ceiling.
func Restrict(base, ceiling *Profile) (*Profile, error) { return profile.Restrict(base, ceiling) }

// ErrSandboxUnavailable and ErrNetworkTargetDenied are re-exported so this
// package's tests match the same values the facade exposes.
var (
	ErrSandboxUnavailable  = enforce.ErrUnavailable
	ErrNetworkTargetDenied = network.ErrTargetDenied
	ErrEgressRouteDenied   = network.ErrRouteDenied
)
