//lint:file-ignore U1000 Several shims below are referenced only from
// //go:build linux test files. staticcheck runs per-GOOS, so on darwin it
// cannot see those call sites and reports them as dead; the linux vet in
// `make vet` is what actually proves they are all live.

package exec

import (
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/internal/testsupport"
)

// Fixture shims. The fixture bodies moved to internal/testsupport when the
// module was split into packages; these keep every existing call site in this
// package's tests spelled the way it always was. Only the shims this package
// actually uses are declared — staticcheck rejects the rest as dead code.

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

func fixtureWithDenyRead(path string) backendFixtureOption {
	return testsupport.FixtureWithDenyRead(path)
}

func fixtureWithoutSecretDenials() backendFixtureOption {
	return testsupport.FixtureWithoutSecretDenials()
}

func fixtureWithNet(net policy.NetPolicy) backendFixtureOption {
	return testsupport.FixtureWithNet(net)
}

func fixtureSecretDenials() []policy.FSEntry {
	return testsupport.FixtureSecretDenials()
}

func fixtureWithWritable(path string) backendFixtureOption {
	return testsupport.FixtureWithWritable(path)
}

func fixtureWithEnv(env policy.EnvPolicy) backendFixtureOption {
	return testsupport.FixtureWithEnv(env)
}

func fixtureWithLimits(limits policy.Limits) backendFixtureOption {
	return testsupport.FixtureWithLimits(limits)
}

func fixtureWithAckUnconfined() backendFixtureOption {
	return testsupport.FixtureWithAckUnconfined()
}

func containsStr(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
