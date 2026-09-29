//go:build linux

package linux

import (
	"errors"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// TestSeccompAuditArchMatchesGOARCH pins the filter's arch guard to the
// architecture the binary runs as. A guard naming another architecture kills
// every syscall the target makes: before per-arch bindings the filter
// hard-coded AUDIT_ARCH_X86_64, so every confined spawn on arm64 died of
// SIGSYS. An architecture with no binding must report Seccomp absent (so no
// rung that needs it is selected) and refuse to install.
func TestSeccompAuditArchMatchesGOARCH(t *testing.T) {
	want := map[string]uint32{
		"amd64": unix.AUDIT_ARCH_X86_64,
		"arm64": unix.AUDIT_ARCH_AARCH64,
	}
	arch, supported := want[runtime.GOARCH]
	if got := SeccompAuditArch(); got != arch {
		t.Fatalf("SeccompAuditArch() on %s = %#x, want %#x", runtime.GOARCH, got, arch)
	}
	if seccompArchSupported != supported {
		t.Fatalf("seccompArchSupported on %s = %v, want %v", runtime.GOARCH, seccompArchSupported, supported)
	}
	if seccompGuardX32 != (runtime.GOARCH == "amd64") {
		t.Fatalf("seccompGuardX32 on %s = %v, want it only on amd64", runtime.GOARCH, seccompGuardX32)
	}
	filter := BuildSeccompFilter()
	if filter[1].K != arch {
		t.Fatalf("arch guard compares %#x, want %#x", filter[1].K, arch)
	}
	if !supported {
		if ProbeSeccompFilter() {
			t.Fatal("ProbeSeccompFilter() = true on an architecture with no filter binding")
		}
		if err := installSeccompFilter(); !errors.Is(err, errUnsupportedSeccompArch) {
			t.Fatalf("installSeccompFilter() = %v, want errUnsupportedSeccompArch", err)
		}
	}
}
