// Package windows owns the configuration and setup vocabulary for the Windows
// sandbox backends. Its public data types remain available on every platform.
package windows

import (
	"errors"

	"github.com/looprig/sandbox/internal/safetext"
)

// SandboxMode selects the Windows confinement tier.
type SandboxMode uint8

const (
	Auto SandboxMode = iota
	RestrictedToken
	Elevated
)

// Config contains the Windows backend settings attached to an executor set.
type Config struct {
	Mode      SandboxMode
	StateRoot string
}

// SetupConfig identifies one elevated Windows sandbox installation.
type SetupConfig struct {
	InstallationID string
	StateRoot      string
	HostBinary     string
	// RuntimeEvidencePath names the reviewed Task 5 evidence artifact to
	// import into the protected installation. Setup never treats an
	// environment variable or a boolean flag as runtime approval.
	RuntimeEvidencePath string
	ProxyPorts          []uint16
}

// WindowsSetupProblemCode identifies one stable setup inspection problem.
type WindowsSetupProblemCode uint16

const (
	SetupProblemUnknown WindowsSetupProblemCode = iota
	SetupProblemManifestMissing
	SetupProblemOwnerMismatch
	SetupProblemHostBinaryStale
	SetupProblemServiceUnavailable
	SetupProblemAccountMissing
	SetupProblemCredentialUnavailable
	SetupProblemFirewallOverridden
	SetupProblemFirewallRuleChanged
	SetupProblemPortInUse
	SetupProblemRuntimeBaselineGap
	SetupProblemLeaseRecoveryPending
	SetupProblemProtocolMismatch
	// SetupProblemProxyPortsStale: the requested proxy-port set differs from
	// the one the installation's manifest (and therefore its firewall rules)
	// pins (design §12: a changed proxy-port set makes setup stale). The
	// installed rules are not "changed" (FirewallRuleChanged) and no port is
	// necessarily "in use" (PortInUse); a refresh is what is owed. Appended
	// last so every existing code keeps its value.
	SetupProblemProxyPortsStale
)

// SetupProblem describes one problem found while inspecting setup state.
// Detail is diagnostic text, not a stable API.
type SetupProblem struct {
	Code     WindowsSetupProblemCode
	Resource string
	Path     string
	Port     uint16
	PID      uint32
	Detail   string
}

func (problem SetupProblem) validate() error {
	if problem.Detail != "" && !safetext.Valid(problem.Detail) {
		return errors.New("sandbox: invalid Windows setup problem detail")
	}
	return nil
}

// SetupStatus reports the inspected state of one Windows installation.
type SetupStatus struct {
	Ready          bool
	Version        uint32
	InstallationID string
	OwnerSID       string
	OfflineAccount string
	OnlineAccount  string
	ProxyPorts     []uint16
	Problems       []SetupProblem
}
