package sandbox

import (
	"testing"

	"github.com/looprig/sandbox/internal/testsupport"
	"github.com/looprig/sandbox/pkg/profile"
)

// mustProfile and unconfinedConfig used to live in profile_test.go alongside the
// Profile implementation. Both moved to internal/testsupport when the profile
// type moved to pkg/profile; these shims keep every existing call site in this
// package's tests unchanged.

func mustProfile(t *testing.T, config ProfileConfig) *Profile {
	t.Helper()
	return testsupport.MustProfile(t, config)
}

func unconfinedConfig(workspace string, ack bool) ProfileConfig {
	return testsupport.UnconfinedConfig(workspace, ack)
}

func pathWithin(path, root string) bool { return profile.PathWithin(path, root) }

func canonicalRoot(path string) (string, error) { return profile.CanonicalRoot(path) }

func guaranteesFromBits(bits uint64) Guarantees { return profile.GuaranteesFromBits(bits) }

// mustTarget parses a normalized egress target or fails the test. It used to
// live in proxy_test.go, which moved to pkg/network with the proxy itself.
func mustTarget(t *testing.T, raw string) NetworkTarget {
	t.Helper()
	target, err := ParseNetworkTarget(raw)
	if err != nil {
		t.Fatalf("ParseNetworkTarget(%q): %v", raw, err)
	}
	return target
}
