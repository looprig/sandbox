package sandbox

import (
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
