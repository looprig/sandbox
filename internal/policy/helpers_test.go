package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/looprig/sandbox/pkg/profile"
)

// This package cannot import internal/testsupport — testsupport builds
// policy.Effective values, so the dependency would be circular. The two helpers
// this suite needs from it are therefore re-declared here, small enough that
// duplication costs less than an external test package would.

// ProfileConfig is aliased so the existing table literals read unchanged.
type (
	ProfileConfig = profile.ProfileConfig
	RootAccess    = profile.RootAccess
	Profile       = profile.Profile
)

func mustProfile(t *testing.T, config ProfileConfig) *profile.Profile {
	t.Helper()
	p, err := profile.NewProfile(config)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	return p
}

// workspaceWriteFixtureFS mirrors testsupport.FixturePolicy(FixtureWorkspaceWrite)
// exactly: a broadly readable host, a writable workspace and /tmp, read-only
// carveouts for .git and .looprig, /dev/null, and the secret denial globs.
func workspaceWriteFixtureFS(workspace string) []FSEntry {
	workspace = filepath.Clean(workspace)
	fs := []FSEntry{
		{Path: "/", Access: ReadAccess | ExecAccess},
		{Path: workspace, Access: ReadAccess | WriteAccess | ExecAccess},
		{Path: "/tmp", Access: ReadAccess | WriteAccess | ExecAccess},
		{Path: filepath.Join(workspace, ".git"), Access: ReadAccess, Denied: ExecAccess | WriteAccess},
		{Path: filepath.Join(workspace, ".looprig"), Access: ReadAccess, Denied: ExecAccess | WriteAccess},
		{Path: NullDevicePath, Access: ReadAccess | WriteAccess},
	}
	return append(fs, secretDenialFixtures()...)
}

func secretDenialFixtures() []FSEntry {
	paths := []string{"**/.env*", "/Library/Keychains"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, ".ssh"), filepath.Join(home, ".aws"),
			filepath.Join(home, ".gnupg"), filepath.Join(home, ".kube"),
		)
	}
	entries := make([]FSEntry, 0, len(paths))
	for _, path := range paths {
		entries = append(entries, FSEntry{Path: path, Denied: AllAccess})
	}
	return entries
}

// Access value aliases, so the existing profile literals in this suite read
// exactly as they did when Profile lived in the same package.
const (
	Deny         = profile.Deny
	Gated        = profile.Gated
	Allow        = profile.Allow
	IsolatedHome = profile.IsolatedHome
	RealHomeDir  = profile.RealHome
	Sandboxed    = profile.Sandboxed
	Unconfined   = profile.Unconfined
)

// Guarantee bit aliases, for the same reason as the Access aliases above.
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

// ErrInvalidProfile is re-exported for the same reason as the aliases above.
var ErrInvalidProfile = profile.ErrInvalidProfile
