//go:build windows

package policyenforcement_test

import (
	"testing"

	"github.com/looprig/sandbox"
)

// TestWindowsExampleProfilesExposeRequiredGuarantees is a deterministic
// Windows-targeted contract. It does not inspect setup, tokens, ACLs, or live
// workers; the repository's Windows cross-build compiles this test for every
// supported architecture while the live example reports setup outcomes at
// runtime.
func TestWindowsExampleProfilesExposeRequiredGuarantees(t *testing.T) {
	workspace := t.TempDir()

	available := newProfile(t, sandbox.ProfileConfig{
		WorkspaceRoot:  workspace,
		WorkspaceRead:  sandbox.Allow,
		WorkspaceWrite: sandbox.Allow,
		HostRead:       sandbox.Allow,
		HostWrite:      sandbox.Allow,
		Network:        sandbox.Allow,
		Command:        sandbox.Allow,
		Home:           sandbox.IsolatedHome,
		Isolation:      sandbox.Sandboxed,
	})
	if got := available.Settings().RequiredGuarantees; got != sandbox.GuaranteeEnvScrub {
		t.Fatalf("available profile required guarantees = %#x, want EnvScrub %#x", got, sandbox.GuaranteeEnvScrub)
	}
	gated := newProfile(t, sandbox.ProfileConfig{
		WorkspaceRoot:  workspace,
		WorkspaceRead:  sandbox.Allow,
		WorkspaceWrite: sandbox.Allow,
		HostRead:       sandbox.Allow,
		HostWrite:      sandbox.Allow,
		Network:        sandbox.Allow,
		Command:        sandbox.Gated,
		Home:           sandbox.IsolatedHome,
		Isolation:      sandbox.Sandboxed,
	})
	if got := gated.Settings().RequiredGuarantees; got != sandbox.GuaranteeEnvScrub {
		t.Fatalf("gated profile required guarantees = %#x, want EnvScrub %#x", got, sandbox.GuaranteeEnvScrub)
	}

	required := newProfile(t, sandbox.ProfileConfig{
		WorkspaceRoot:  workspace,
		WorkspaceRead:  sandbox.Allow,
		WorkspaceWrite: sandbox.Deny,
		HostRead:       sandbox.Allow,
		HostWrite:      sandbox.Deny,
		Network:        sandbox.Deny,
		Command:        sandbox.Allow,
		Home:           sandbox.IsolatedHome,
		Isolation:      sandbox.Sandboxed,
	})
	want := sandbox.GuaranteeEnvScrub | sandbox.GuaranteeWriteBoundary | sandbox.GuaranteeNetworkBoundary
	if got := required.Settings().RequiredGuarantees; got != want {
		t.Fatalf("required profile guarantees = %#x, want EnvScrub|WriteBoundary|NetworkBoundary %#x", got, want)
	}
}
