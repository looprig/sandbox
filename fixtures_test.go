package sandbox

import (
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/internal/testsupport"
)

// Fixture shims. The fixture bodies moved to internal/testsupport when the
// module was split into packages; these keep every existing call site in this
// package's tests spelled the way it always was.

const (
	fixtureSharedTmpRoot  = testsupport.FixtureSharedTmpRoot
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

func fixtureSecretDenials() []policy.FSEntry { return testsupport.FixtureSecretDenials() }
func fixtureWithWritable(path string) backendFixtureOption {
	return testsupport.FixtureWithWritable(path)
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
func fixtureWithEnv(env policy.EnvPolicy) backendFixtureOption {
	return testsupport.FixtureWithEnv(env)
}
func fixtureWithLimits(l policy.Limits) backendFixtureOption { return testsupport.FixtureWithLimits(l) }
func fixtureWithAckUnconfined() backendFixtureOption         { return testsupport.FixtureWithAckUnconfined() }
