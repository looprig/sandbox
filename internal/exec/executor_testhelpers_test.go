package exec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/platform"
	"github.com/looprig/sandbox/internal/policy"
)

const portableEchoMarker = "--sandbox-portable-echo"

func TestPortableArgvEchoHelper(t *testing.T) {
	for index, arg := range os.Args {
		if arg == portableEchoMarker {
			fmt.Print(strings.Join(os.Args[index+1:], " "))
			return
		}
	}
}

func portableEchoArgv(t *testing.T, values ...string) []string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	argv := []string{executable, "-test.run=^TestPortableArgvEchoHelper$", "--", portableEchoMarker}
	return append(argv, values...)
}

func TestPortableShellFixtures(t *testing.T) {
	workspace := t.TempDir()
	executor, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, workspace))
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(workspace, "portable-marker")
	command := portableWriteCommand(marker, "started")
	output, code, err := executor.RunCommand(context.Background(), workspace, command)
	if err != nil || code != 0 {
		t.Fatalf("portable write: workspace=%q command=%q code=%d err=%v output=%q", workspace, command, code, err, output)
	}
	if data, err := os.ReadFile(marker); err != nil || !strings.Contains(string(data), "started") {
		t.Fatalf("portable marker: data=%q err=%v", data, err)
	}
}

func portableEnvironmentCommand() string {
	if runtime.GOOS == "windows" {
		return "set"
	}
	return "env"
}

func portableSuccessCommand() string {
	if runtime.GOOS == "windows" {
		return "exit /b 0"
	}
	return "true"
}

func portableFailureCommand() string {
	if runtime.GOOS == "windows" {
		return "exit /b 1"
	}
	return "false"
}

func portableShellQuote(value string) string {
	if runtime.GOOS == "windows" {
		return `"` + strings.ReplaceAll(value, "%", "%%") + `"`
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

func portableWriteCommand(path, value string) string {
	if runtime.GOOS == "windows" {
		// Every Windows marker fixture is created in cmd.Dir. Keeping the shell
		// operand relative avoids cmd.exe's non-CommandLineToArgvW quote grammar;
		// the absolute path is still used by the parent for verification.
		return "> " + filepath.Base(path) + " echo " + value
	}
	return "printf %s " + portableShellQuote(value) + " > " + portableShellQuote(path)
}

func portableSleepCommand(seconds int) string {
	if runtime.GOOS == "windows" {
		ping := filepath.Join(os.Getenv("SystemRoot"), "System32", "ping.exe")
		return ping + " -n " + strconv.Itoa(seconds+1) + " 127.0.0.1 >nul"
	}
	return "sleep " + strconv.Itoa(seconds)
}

func portableWriteSleepWriteCommand(started, completed string, seconds int) string {
	separator := "; "
	if runtime.GOOS == "windows" {
		separator = " & "
	}
	return portableWriteCommand(started, "started") + separator + portableSleepCommand(seconds) + separator + portableWriteCommand(completed, "completed")
}

func portableProxyExposureCommand(path string) string {
	if runtime.GOOS == "windows" {
		return "> " + filepath.Base(path) + " echo %HTTP_PROXY% & " + portableSleepCommand(1) + " & exit /b 7"
	}
	return "printf '%s' \"$HTTP_PROXY\" > " + portableShellQuote(path) + "; sleep 1; exit 7"
}

func parsedEnvironment(output []byte) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		if name, value, ok := strings.Cut(line, "="); ok {
			result[strings.ToUpper(name)] = value
		}
	}
	return result
}

func newExecutorForEffectivePolicy(p policy.Effective, configs ...executorConfig) (*Executor, error) {
	config := mergeExecutorConfigs(configs...)
	// Direct construction is a unit-test seam and owns no stable scratch root.
	// Production Windows construction always enters through ExecutorSet, which
	// supplies that root before selecting the restricted backend.
	if runtime.GOOS == "windows" && config.backend == nil && config.platform.WindowsRestrictedRuntime == nil {
		config.backend = newTestPassthroughBackend()
	}
	return newExecutorFromEffective(nil, p, config)
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
		if config.quarantine != nil {
			merged.quarantine = config.quarantine
		}
		if config.processTree != nil {
			merged.processTree = config.processTree
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
