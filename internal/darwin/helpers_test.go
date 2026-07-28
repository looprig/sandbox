package darwin

import (
	"testing"

	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/internal/testsupport"
	"github.com/looprig/sandbox/pkg/profile"
)

// Shims onto the shared fixtures, so the call sites in this suite read exactly
// as they did when the Seatbelt backend lived in the flat root package.

func mustProfile(t *testing.T, config profile.ProfileConfig) *profile.Profile {
	t.Helper()
	return testsupport.MustProfile(t, config)
}

const (
	fixtureScopedRuntime  = testsupport.FixtureScopedRuntime
	fixtureHostRead       = testsupport.FixtureHostRead
	fixtureWorkspaceWrite = testsupport.FixtureWorkspaceWrite
	fixtureBroadNetwork   = testsupport.FixtureBroadNetwork
	fixtureDirect         = testsupport.FixtureDirect
)

type (
	backendFixtureShape  = testsupport.FixtureShape
	backendFixtureOption = testsupport.FixtureOption
)

func backendFixturePolicy(shape backendFixtureShape, workspace string, opts ...backendFixtureOption) policy.Effective {
	return testsupport.FixturePolicy(shape, workspace, opts...)
}

func fixtureWithDenyRead(path string) backendFixtureOption {
	return testsupport.FixtureWithDenyRead(path)
}

func fixtureWithoutSecretDenials() backendFixtureOption {
	return testsupport.FixtureWithoutSecretDenials()
}

func fixtureWithNet(net policy.NetPolicy) backendFixtureOption {
	return testsupport.FixtureWithNet(net)
}
