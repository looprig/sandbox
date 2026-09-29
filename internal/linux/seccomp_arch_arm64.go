//go:build linux && arm64

package linux

import "golang.org/x/sys/unix"

// The Seccomp filter's architecture binding for AArch64 (see seccomp.go and
// seccomp_arch_amd64.go). A 32-bit (AArch32) task reports AUDIT_ARCH_ARM and is
// killed by the arch guard. AArch64 has no x32-style ABI sharing its arch value,
// so no second guard is needed.
const (
	seccompArchSupported = true
	seccompAuditArch     = unix.AUDIT_ARCH_AARCH64
	seccompGuardX32      = false
)
