package sandbox

import (
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

func withBackend(value backend) executorConfig { return executorConfig{backend: value} }

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

func (*testPassthroughBackend) compile(p policy.Effective) (spawnSpec, CompileReport, uint8, uint64, error) {
	bits := uint64(0)
	if !p.Env.Inherit {
		bits = GuaranteeEnvScrub
	}
	return spawnSpec{wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd) error, func()) {
		return argv, nil, nil
	}}, CompileReport{}, LevelNone, bits, nil
}

func containsStr(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
