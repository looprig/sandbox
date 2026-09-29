//go:build linux && !amd64 && !arm64

package linux

// No Seccomp filter is built for this architecture. ProbeSeccompFilter reports
// the capability absent, so SelectRung chooses no enforcing rung and executor
// construction fails closed with enforce.ErrUnavailable, rather than every
// spawn being killed by an arch guard written for another architecture.
// installSeccompFilter refuses as well, in case a caller pins a backend.
const (
	seccompArchSupported = false
	seccompAuditArch     = 0
	seccompGuardX32      = false
)
