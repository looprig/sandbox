//go:build linux && amd64

package linux

import "golang.org/x/sys/unix"

// The Seccomp filter's architecture binding for x86_64 (see seccomp.go). The
// syscall numbers the filter compares come from golang.org/x/sys/unix, whose
// SYS_* constants are generated per GOARCH, so only these two values are
// architecture-specific.
const (
	// seccompArchSupported: the filter is built for this architecture.
	seccompArchSupported = true
	// seccompAuditArch is the seccomp_data.arch value of a native syscall. Any
	// other value (i386 via int 0x80) is killed by the arch guard.
	seccompAuditArch = unix.AUDIT_ARCH_X86_64
	// seccompGuardX32: x32 shares AUDIT_ARCH_X86_64 but ORs
	// __X32_SYSCALL_BIT into its syscall numbers, so it needs its own guard.
	seccompGuardX32 = true
)
