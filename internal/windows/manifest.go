package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

const setupManifestVersion uint32 = 1

type setupState string

const (
	setupStateStaging         setupState = "staging"
	setupStateReady           setupState = "ready"
	setupStateRecoveryPending setupState = "recovery-pending"
)

// setupManifest is the only authority for locating the installed host. Source
// paths are deliberately not persisted, so runtime cannot execute them.
type setupManifest struct {
	Version        uint32     `json:"version"`
	State          setupState `json:"state"`
	InstallationID string     `json:"installation_id"`
	OwnerSID       string     `json:"owner_sid"`
	HostPath       string     `json:"host_path"`
	HostSHA256     string     `json:"host_sha256"`
	ProxyPorts     []uint16   `json:"proxy_ports"`
	Protocol       uint16     `json:"protocol"`
}

func (manifest setupManifest) validate() error {
	if manifest.Version != setupManifestVersion || manifest.InstallationID == "" ||
		manifest.OwnerSID == "" || manifest.HostPath == "" || manifest.Protocol == 0 {
		return errors.New("sandbox: incomplete Windows setup manifest")
	}
	if manifest.State != setupStateStaging && manifest.State != setupStateReady && manifest.State != setupStateRecoveryPending {
		return errors.New("sandbox: invalid Windows setup manifest state")
	}
	digest, err := hex.DecodeString(manifest.HostSHA256)
	if err != nil || len(digest) != sha256.Size {
		return errors.New("sandbox: invalid Windows host digest")
	}
	if err := validateProxyPorts(manifest.ProxyPorts); err != nil {
		return err
	}
	return nil
}

func encodeSetupManifest(manifest setupManifest) ([]byte, error) {
	if err := manifest.validate(); err != nil {
		return nil, err
	}
	manifest.ProxyPorts = append([]uint16(nil), manifest.ProxyPorts...)
	slices.Sort(manifest.ProxyPorts)
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encode Windows setup manifest: %w", err)
	}
	return append(data, '\n'), nil
}

func decodeSetupManifest(data []byte) (setupManifest, error) {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var manifest setupManifest
	if err := decoder.Decode(&manifest); err != nil {
		return setupManifest{}, fmt.Errorf("decode Windows setup manifest: %w", err)
	}
	if err := manifest.validate(); err != nil {
		return setupManifest{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return setupManifest{}, errors.New("sandbox: trailing Windows setup manifest data")
	}
	return manifest, nil
}

type setupInspection struct {
	Manifest             *setupManifest
	ManifestErr          error
	Requested            SetupConfig
	OwnerSID             string
	HostSHA256           string
	ServiceReady         bool
	AccountsReady        bool
	CredentialsReady     bool
	FirewallEffective    bool
	FirewallUnchanged    bool
	PortPID              map[uint16]uint32
	RuntimeBaselineReady bool
	LeaseRecovery        bool
	Protocol             uint16
}

func statusFromInspection(facts setupInspection) SetupStatus {
	status := SetupStatus{InstallationID: facts.Requested.InstallationID, ProxyPorts: append([]uint16(nil), facts.Requested.ProxyPorts...)}
	add := func(code WindowsSetupProblemCode, resource, path, detail string, port uint16, pid uint32) {
		problem := SetupProblem{Code: code, Resource: resource, Path: path, Port: port, PID: pid, Detail: detail}
		if problem.validate() == nil {
			status.Problems = append(status.Problems, problem)
		}
	}
	if facts.Manifest == nil || facts.ManifestErr != nil {
		add(SetupProblemManifestMissing, "manifest", "", "setup manifest is absent or invalid", 0, 0)
		return status
	}
	m := facts.Manifest
	status.Version, status.OwnerSID = m.Version, m.OwnerSID
	if m.State == setupStateRecoveryPending {
		add(SetupProblemLeaseRecoveryPending, "setup", "", "setup recovery is pending", 0, 0)
	}
	if m.State != setupStateReady {
		add(SetupProblemManifestMissing, "manifest", "", "setup has not reached ready state", 0, 0)
	}
	if m.InstallationID != facts.Requested.InstallationID || m.OwnerSID != facts.OwnerSID {
		add(SetupProblemOwnerMismatch, "owner", "", "installation identity or owner does not match", 0, 0)
	}
	if !strings.EqualFold(m.HostSHA256, facts.HostSHA256) {
		add(SetupProblemHostBinaryStale, "sandbox-host", m.HostPath, "installed host hash does not match", 0, 0)
	}
	if !facts.ServiceReady {
		add(SetupProblemServiceUnavailable, "service", "", "service is unavailable", 0, 0)
	}
	if !facts.AccountsReady {
		add(SetupProblemAccountMissing, "accounts", "", "sandbox account is missing", 0, 0)
	}
	if !facts.CredentialsReady {
		add(SetupProblemCredentialUnavailable, "credentials", "", "credential state is unavailable", 0, 0)
	}
	if !facts.FirewallEffective {
		add(SetupProblemFirewallOverridden, "firewall", "", "firewall policy is overridden", 0, 0)
	} else if !facts.FirewallUnchanged {
		add(SetupProblemFirewallRuleChanged, "firewall", "", "firewall rules have changed", 0, 0)
	}
	for port, pid := range facts.PortPID {
		add(SetupProblemPortInUse, "proxy-port", "", "proxy port is already owned", port, pid)
	}
	if !facts.RuntimeBaselineReady {
		add(SetupProblemRuntimeBaselineGap, "runtime-baseline", "", "runtime baseline is incomplete", 0, 0)
	}
	if facts.Protocol != m.Protocol {
		add(SetupProblemProtocolMismatch, "protocol", "", "broker protocol version does not match", 0, 0)
	}
	status.Ready = len(status.Problems) == 0
	return status
}

func validateProxyPorts(ports []uint16) error {
	if len(ports) == 0 || len(ports) > 32 {
		return errors.New("sandbox: proxy ports must be a small non-empty set")
	}
	seen := make(map[uint16]struct{}, len(ports))
	for _, port := range ports {
		if port == 0 {
			return errors.New("sandbox: proxy port must be non-zero")
		}
		if _, ok := seen[port]; ok {
			return errors.New("sandbox: duplicate proxy port")
		}
		seen[port] = struct{}{}
	}
	return nil
}
