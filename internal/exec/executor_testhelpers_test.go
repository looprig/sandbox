package exec

import (
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/platform"
	"os/exec"
	"time"

	"github.com/looprig/sandbox/internal/policy"
)

func newExecutorForEffectivePolicy(p policy.Effective, configs ...executorConfig) (*Executor, error) {
	return newExecutorFromEffective(nil, p, mergeExecutorConfigs(configs...))
}

func newTestExecutor(profile *Profile, configs ...executorConfig) (*Executor, error) {
	return newExecutor(profile, mergeExecutorConfigs(configs...))
}

func withBackend(value enforce.Backend) executorConfig { return executorConfig{backend: value} }

func withClock(value func() time.Time) executorConfig { return executorConfig{clock: value} }

func mergeExecutorConfigs(configs ...executorConfig) executorConfig {
	var merged executorConfig
	for _, config := range configs {
		if config.grantTTL != 0 {
			merged.grantTTL = config.grantTTL
		}
		if config.clock != nil {
			merged.clock = config.clock
		}
		if config.backend != nil {
			merged.backend = config.backend
		}
		if config.platform != (platform.Options{}) {
			merged.platform = config.platform
		}
		if config.lifecycle != nil {
			merged.lifecycle = config.lifecycle
		}
	}
	return merged
}

func withExecutorSetConfig(configs ...executorConfig) ExecutorSetOption {
	return func(config *executorSetConfig) {
		config.executor = mergeExecutorConfigs(config.executor, mergeExecutorConfigs(configs...))
	}
}

type testPassthroughBackend struct{}

func newTestPassthroughBackend() *testPassthroughBackend { return &testPassthroughBackend{} }

func (*testPassthroughBackend) Compile(p policy.Effective) (enforce.Spec, CompileReport, uint8, uint64, error) {
	bits := uint64(0)
	if !p.Env.Inherit {
		bits = GuaranteeEnvScrub
	}
	return enforce.Spec{Wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd) error, func()) {
		return argv, nil, nil
	}}, CompileReport{}, LevelNone, bits, nil
}
