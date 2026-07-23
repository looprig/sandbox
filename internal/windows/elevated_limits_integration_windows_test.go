//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
	win "golang.org/x/sys/windows"
)

const (
	elevatedLimitsGate       = "SANDBOX_WINDOWS_ELEVATED_TEST"
	elevatedLimitsMaxPIDs    = 4
	elevatedLimitsMaxMemory  = int64(384 << 20)
	elevatedLimitsMaxCPUPct  = 50
	elevatedLimitsHelperMode = "resource-limits"
)

type elevatedLimitsProbeResult struct {
	InJob              bool   `json:"in_job"`
	LimitFlags         uint32 `json:"limit_flags"`
	ActiveProcessLimit uint32 `json:"active_process_limit"`
	JobMemoryLimit     uint64 `json:"job_memory_limit"`
	CPUControlFlags    uint32 `json:"cpu_control_flags"`
	CPURate            uint32 `json:"cpu_rate"`
}

func TestElevatedConfiguredResourceLimitsAcceptance(t *testing.T) {
	if os.Getenv(elevatedLimitsGate) != "1" {
		t.Skip(elevatedLimitsGate + "=1 is required")
	}
	if !win.GetCurrentProcessToken().IsElevated() {
		t.Fatal("elevated resource-limit acceptance requires an elevated worker token")
	}
	setup := elevatedLimitsSetupConfig(t)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := Setup(ctx, setup); err != nil {
		t.Fatalf("setup elevated Windows sandbox for resource limits: %v", err)
	}

	workspace := t.TempDir()
	prof, err := profile.NewProfile(profile.ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: profile.Allow, WorkspaceWrite: profile.Allow,
		HostRead: profile.Deny, HostWrite: profile.Deny,
		Network: profile.Deny, Command: profile.Allow,
	})
	if err != nil {
		t.Fatal(err)
	}
	effective, err := policy.Compile(prof)
	if err != nil {
		t.Fatal(err)
	}
	effective.Limits = policy.Limits{
		MaxPIDs: elevatedLimitsMaxPIDs, MaxMemBytes: elevatedLimitsMaxMemory,
		MaxCPUPct: elevatedLimitsMaxCPUPct,
	}
	spec, _, _, bits, err := newElevatedBackend(Config{
		Mode: Elevated, StateRoot: setup.StateRoot,
	}).Compile(effective)
	if err != nil {
		t.Fatalf("compile elevated resource-limit policy: %v", err)
	}
	defer func() {
		if err := spec.Release(); err != nil {
			t.Errorf("release elevated resource-limit specification: %v", err)
		}
	}()
	if bits&profile.GuaranteeResourceLimits == 0 {
		t.Fatal("configured elevated backend did not claim GuaranteeResourceLimits")
	}

	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(workspace, "elevated-limits-probe.exe")
	copyElevatedLimitsHelper(t, source, helper)
	resultPath := filepath.Join(workspace, "elevated-limits-result.json")
	var stdout, stderr bytes.Buffer
	code, err := spec.Launch(enforce.LaunchRequest{
		Context: context.Background(),
		Dir:     workspace,
		Argv: []string{
			helper, "-test.run=^TestElevatedConfiguredResourceLimitsPayload$",
			"--", elevatedLimitsHelperMode, resultPath,
		},
		Env: os.Environ(), Stdin: bytes.NewReader(nil), Stdout: &stdout, Stderr: &stderr,
	})
	if err != nil || code != 0 {
		t.Fatalf("launch elevated resource-limit probe = code %d err %v stdout=%q stderr=%q",
			code, err, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatalf("read elevated resource-limit evidence: %v", err)
	}
	var observed elevatedLimitsProbeResult
	if err := json.Unmarshal(data, &observed); err != nil {
		t.Fatalf("decode elevated resource-limit evidence: %v", err)
	}
	wantFlags := uint32(win.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
		win.JOB_OBJECT_LIMIT_ACTIVE_PROCESS | win.JOB_OBJECT_LIMIT_JOB_MEMORY)
	wantCPUFlags := uint32(jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap)
	if !observed.InJob ||
		observed.LimitFlags&wantFlags != wantFlags ||
		observed.ActiveProcessLimit != elevatedLimitsMaxPIDs ||
		observed.JobMemoryLimit != uint64(elevatedLimitsMaxMemory) ||
		observed.CPUControlFlags != wantCPUFlags ||
		observed.CPURate != elevatedLimitsMaxCPUPct*100 {
		t.Fatalf("elevated resource-limit evidence = %+v, want pids=%d memory=%d cpu=%d%%",
			observed, elevatedLimitsMaxPIDs, elevatedLimitsMaxMemory, elevatedLimitsMaxCPUPct)
	}
	t.Log("ELEVATED_RESOURCE_LIMITS_ACCEPTANCE_PASS")
}

func TestElevatedConfiguredResourceLimitsPayload(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || len(os.Args) != separator+3 ||
		os.Args[separator+1] != elevatedLimitsHelperMode {
		return
	}
	var inJob uint32
	ok, _, callErr := win.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(
		uintptr(win.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inJob)))
	if ok == 0 {
		t.Fatalf("query Job membership: %v", callErr)
	}
	result := elevatedLimitsProbeResult{InJob: inJob != 0}
	if result.InJob {
		var limits win.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		if err := win.QueryInformationJobObject(0, win.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), nil); err != nil {
			t.Fatalf("query Job resource limits: %v", err)
		}
		result.LimitFlags = limits.BasicLimitInformation.LimitFlags
		result.ActiveProcessLimit = limits.BasicLimitInformation.ActiveProcessLimit
		result.JobMemoryLimit = uint64(limits.JobMemoryLimit)
		var cpu jobObjectCPURateControlInformation
		if err := win.QueryInformationJobObject(0, win.JobObjectCpuRateControlInformation,
			uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu)), nil); err != nil {
			t.Fatalf("query Job CPU limit: %v", err)
		}
		result.CPUControlFlags = cpu.ControlFlags
		result.CPURate = cpu.CPURate
	}
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Args[separator+2], data, 0o600); err != nil {
		t.Fatalf("write Job resource-limit evidence: %v", err)
	}
}

func elevatedLimitsSetupConfig(t *testing.T) SetupConfig {
	t.Helper()
	required := func(name string) string {
		value := strings.TrimSpace(os.Getenv(name))
		if value == "" {
			t.Fatalf("%s is required", name)
		}
		return value
	}
	var ports []uint16
	for _, item := range strings.Split(required("SANDBOX_WINDOWS_PROXY_PORTS"), ",") {
		value, err := strconv.ParseUint(strings.TrimSpace(item), 10, 16)
		if err != nil || value == 0 {
			t.Fatalf("invalid SANDBOX_WINDOWS_PROXY_PORTS item %q", item)
		}
		ports = append(ports, uint16(value))
	}
	config := SetupConfig{
		InstallationID:      required("SANDBOX_WINDOWS_INSTALLATION_ID"),
		StateRoot:           required("SANDBOX_WINDOWS_STATE_ROOT"),
		HostBinary:          required("SANDBOX_WINDOWS_HOST_BINARY"),
		RuntimeEvidencePath: required("SANDBOX_WINDOWS_RUNTIME_EVIDENCE"),
		ProxyPorts:          ports,
	}
	for name, path := range map[string]string{
		"SANDBOX_WINDOWS_STATE_ROOT":       config.StateRoot,
		"SANDBOX_WINDOWS_HOST_BINARY":      config.HostBinary,
		"SANDBOX_WINDOWS_RUNTIME_EVIDENCE": config.RuntimeEvidencePath,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			t.Fatalf("%s must be canonical and absolute", name)
		}
	}
	return config
}

func copyElevatedLimitsHelper(t *testing.T, source, destination string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		t.Fatal(err)
	}
}
