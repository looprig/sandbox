// Package testsupport holds construction helpers shared by the test suites of
// several internal packages. It exists so that splitting the module into
// packages did not force each one to re-declare the same profile fixtures.
// It is internal and test-only by convention; production code never imports it.
package testsupport

import (
	"testing"

	"github.com/looprig/sandbox/pkg/profile"
)

// MustProfile builds a Profile from config or fails the test.
func MustProfile(t *testing.T, config profile.ProfileConfig) *profile.Profile {
	t.Helper()
	p, err := profile.NewProfile(config)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	return p
}

// UnconfinedConfig is the minimum configuration a valid Unconfined profile
// requires: every filesystem and network authority at Allow, plus the explicit
// acknowledgement. Pass ack=false to build the invalid variant on purpose.
func UnconfinedConfig(workspace string, ack bool) profile.ProfileConfig {
	return profile.ProfileConfig{
		WorkspaceRoot:  workspace,
		WorkspaceRead:  profile.Allow,
		WorkspaceWrite: profile.Allow,
		HostRead:       profile.Allow,
		HostWrite:      profile.Allow,
		Network:        profile.Allow,
		Command:        profile.Allow,
		Home:           profile.RealHome,
		Isolation:      profile.Unconfined,
		AckUnconfined:  ack,
	}
}
