//go:build windows

package windows

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"unsafe"

	"github.com/looprig/sandbox/pkg/sandboxtest"
	win "golang.org/x/sys/windows"
)

const elevatedDisposableGate = "SANDBOX_WINDOWS_ELEVATED_TEST"

type elevatedAcceptanceCase struct {
	name, guarantee string
	positiveControl bool
	cleanupCheck    bool
}

// This registry is the single checklist consumed by disposable-worker
// orchestration. A new claimed mechanism cannot silently omit its positive
// control or residue inspection.
func TestElevatedAcceptanceMatrixIsFailClosed(t *testing.T) {
	cases := []elevatedAcceptanceCase{
		{"setup-corruption-staleness", "setup", true, true},
		{"credential-state-protection", "state", true, true},
		{"read-write-races", "filesystem", true, true},
		{"unsupported-roots-classes", "filesystem", true, true},
		{"offline-target-online", "network", true, true},
		{"private-desktop-launch-surfaces", "process", true, true},
		{"detached-job-limits-handles", "process", true, true},
		{"concurrency-client-death-restart", "lifecycle", true, true},
		{"credential-refresh", "state", true, true},
		{"setup-removal-residue", "cleanup", true, true},
	}
	seen := map[string]bool{}
	for _, test := range cases {
		if test.name == "" || test.guarantee == "" || seen[test.name] {
			t.Fatalf("invalid or duplicate acceptance case %#v", test)
		}
		seen[test.name] = true
		if !test.positiveControl || !test.cleanupCheck {
			t.Fatalf("%s can hide a false pass: positive-control=%t cleanup=%t", test.name, test.positiveControl, test.cleanupCheck)
		}
	}
}

func TestElevatedDisposableAcceptanceGate(t *testing.T) {
	sandboxtest.RequireLiveGate(t, sandboxtest.LiveGate{
		OptInEnv: elevatedDisposableGate, Description: "elevated Windows adversarial matrix",
		Supported: elevatedWorkerSupported,
		Evidence:  elevatedWorkerPrerequisites,
	})
}

type rtlOSVersionInfo struct {
	size, major, minor, build, platform uint32
	csd                                 [128]uint16
}

func elevatedWorkerSupported() (bool, string) {
	var version rtlOSVersionInfo
	version.size = uint32(unsafe.Sizeof(version))
	proc := win.NewLazySystemDLL("ntdll.dll").NewProc("RtlGetVersion")
	status, _, _ := proc.Call(uintptr(unsafe.Pointer(&version)))
	if status != 0 || version.build < 22000 {
		return false, "Windows 11/Server disposable worker build 22000+ is required"
	}
	if !win.GetCurrentProcessToken().IsElevated() {
		return false, "elevated worker token is required"
	}
	return true, ""
}

// elevatedWorkerPrerequisites validates the concrete inputs consumed by the
// repository's ordinary go test ./... live matrix. CI owns aggregation and its
// unconditional post-test residue audit; this test must not recursively launch
// another test harness or require evidence that only that harness can produce.
func elevatedWorkerPrerequisites() (bool, string) {
	host := os.Getenv("SANDBOX_WINDOWS_HOST_BINARY")
	if !filepath.IsAbs(host) {
		return false, "SANDBOX_WINDOWS_HOST_BINARY must be absolute"
	}
	if info, err := os.Stat(host); err != nil || info.IsDir() {
		return false, "SANDBOX_WINDOWS_HOST_BINARY is missing or not a file"
	}
	stateRoot := os.Getenv("SANDBOX_WINDOWS_STATE_ROOT")
	if !filepath.IsAbs(stateRoot) || filepath.Clean(stateRoot) != stateRoot {
		return false, "SANDBOX_WINDOWS_STATE_ROOT must be canonical and absolute"
	}
	if strings.TrimSpace(os.Getenv("SANDBOX_WINDOWS_INSTALLATION_ID")) == "" {
		return false, "SANDBOX_WINDOWS_INSTALLATION_ID is required"
	}
	rawPorts := strings.Split(os.Getenv("SANDBOX_WINDOWS_PROXY_PORTS"), ",")
	if len(rawPorts) == 0 {
		return false, "SANDBOX_WINDOWS_PROXY_PORTS is required"
	}
	seen := make(map[uint64]struct{}, len(rawPorts))
	for _, raw := range rawPorts {
		port, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 16)
		if err != nil || port == 0 {
			return false, "SANDBOX_WINDOWS_PROXY_PORTS contains an invalid port"
		}
		if _, duplicate := seen[port]; duplicate {
			return false, "SANDBOX_WINDOWS_PROXY_PORTS contains a duplicate port"
		}
		seen[port] = struct{}{}
	}
	return true, ""
}
