package windows

import (
	"crypto/sha256"
	"strings"
	"testing"
)

func validSetupManifest() setupManifest {
	return setupManifest{Version: 1, State: setupStateReady, InstallationID: "install", OwnerSID: "S-1-5-21-1", HostPath: `C:\ProgramData\Looprig\slots\generation\sandbox-host.exe`, HostSHA256: strings.Repeat("ab", sha256.Size), ProxyPorts: []uint16{9002, 9001}, Protocol: 1}
}

func healthyInspection() setupInspection {
	m := validSetupManifest()
	return setupInspection{Manifest: &m, Requested: SetupConfig{InstallationID: "install", ProxyPorts: []uint16{9001, 9002}}, OwnerSID: m.OwnerSID, HostSHA256: m.HostSHA256, ServiceReady: true, AccountsReady: true, CredentialsReady: true, FirewallEffective: true, FirewallUnchanged: true, RuntimeBaselineReady: true, Protocol: m.Protocol}
}

func TestSetupManifestRoundTripIsCanonical(t *testing.T) {
	m := validSetupManifest()
	data, err := encodeSetupManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeSetupManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.ProxyPorts[0] != 9001 || got.State != setupStateReady {
		t.Fatalf("unexpected manifest: %+v", got)
	}
	if strings.Contains(string(data), "source") {
		t.Fatal("source path must not be persisted")
	}
}

func TestSetupManifestRejectsUnknownAndInvalidData(t *testing.T) {
	valid, err := encodeSetupManifest(validSetupManifest())
	if err != nil {
		t.Fatal(err)
	}
	for _, data := range []string{`{"version":1,"unknown":true}`, `{"version":1}`, `{} {}`, string(valid) + `{}`} {
		if _, err := decodeSetupManifest([]byte(data)); err == nil {
			t.Fatalf("accepted %q", data)
		}
	}
}

func TestSetupStatusStatesAndTypedProblems(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*setupInspection)
		code   WindowsSetupProblemCode
	}{
		{"absent", func(f *setupInspection) { f.Manifest = nil }, SetupProblemManifestMissing},
		{"staging", func(f *setupInspection) { f.Manifest.State = setupStateStaging }, SetupProblemManifestMissing},
		{"recovery", func(f *setupInspection) { f.Manifest.State = setupStateRecoveryPending }, SetupProblemLeaseRecoveryPending},
		{"broker lease quarantine", func(f *setupInspection) { f.LeaseRecovery = true }, SetupProblemLeaseRecoveryPending},
		{"owner", func(f *setupInspection) { f.OwnerSID = "S-1-5-21-2" }, SetupProblemOwnerMismatch},
		{"hash", func(f *setupInspection) { f.HostSHA256 = strings.Repeat("cd", 32) }, SetupProblemHostBinaryStale},
		{"service", func(f *setupInspection) { f.ServiceReady = false }, SetupProblemServiceUnavailable},
		{"account", func(f *setupInspection) { f.AccountsReady = false }, SetupProblemAccountMissing},
		{"credential", func(f *setupInspection) { f.CredentialsReady = false }, SetupProblemCredentialUnavailable},
		{"firewall override", func(f *setupInspection) { f.FirewallEffective = false }, SetupProblemFirewallOverridden},
		{"firewall change", func(f *setupInspection) { f.FirewallUnchanged = false }, SetupProblemFirewallRuleChanged},
		{"port", func(f *setupInspection) { f.PortPID = map[uint16]uint32{9001: 42} }, SetupProblemPortInUse},
		{"runtime", func(f *setupInspection) { f.RuntimeBaselineReady = false }, SetupProblemRuntimeBaselineGap},
		{"protocol", func(f *setupInspection) { f.Protocol = 2 }, SetupProblemProtocolMismatch},
		// Review L8 / design §12: a changed proxy-port set is stale setup.
		{"proxy ports added", func(f *setupInspection) { f.Requested.ProxyPorts = []uint16{9001, 9002, 9003} }, SetupProblemProxyPortsStale},
		{"proxy ports replaced", func(f *setupInspection) { f.Requested.ProxyPorts = []uint16{9001, 9004} }, SetupProblemProxyPortsStale},
		{"proxy ports removed", func(f *setupInspection) { f.Requested.ProxyPorts = []uint16{9002} }, SetupProblemProxyPortsStale},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := healthyInspection()
			test.mutate(&f)
			s := statusFromInspection(f)
			if s.Ready {
				t.Fatal("reported ready")
			}
			found := false
			for _, p := range s.Problems {
				if p.Code == test.code {
					found = true
				}
				if strings.Contains(p.Detail, "test-secret") {
					t.Fatal("secret leaked")
				}
			}
			if !found {
				t.Fatalf("missing code %v: %+v", test.code, s.Problems)
			}
		})
	}
	if !statusFromInspection(healthyInspection()).Ready {
		t.Fatal("healthy setup not ready")
	}
}

// TestSetupProblemCodesAreStable pins every existing problem code's value;
// the stale proxy-port code was appended, never inserted.
func TestSetupProblemCodesAreStable(t *testing.T) {
	for want, code := range []WindowsSetupProblemCode{
		SetupProblemUnknown, SetupProblemManifestMissing, SetupProblemOwnerMismatch, SetupProblemHostBinaryStale,
		SetupProblemServiceUnavailable, SetupProblemAccountMissing, SetupProblemCredentialUnavailable,
		SetupProblemFirewallOverridden, SetupProblemFirewallRuleChanged, SetupProblemPortInUse,
		SetupProblemRuntimeBaselineGap, SetupProblemLeaseRecoveryPending, SetupProblemProtocolMismatch,
		SetupProblemProxyPortsStale,
	} {
		if int(code) != want {
			t.Fatalf("problem code %d has value %d", want, code)
		}
	}
}

// TestSetupStatusAcceptsTheSamePortSetInAnyOrder: the comparison is a set
// comparison; ordering never makes an installation stale.
func TestSetupStatusAcceptsTheSamePortSetInAnyOrder(t *testing.T) {
	f := healthyInspection()
	f.Requested.ProxyPorts = []uint16{9002, 9001}
	if status := statusFromInspection(f); !status.Ready {
		t.Fatalf("reordered port set reported stale: %+v", status.Problems)
	}
}

// TestForeignProxyPortOwnersIgnoresTheInspectingProcess pins L8: a pinned
// port held by the inspecting host's own reserved listener is not a squatter,
// while any other process (or an unknown owner) still is.
func TestForeignProxyPortOwnersIgnoresTheInspectingProcess(t *testing.T) {
	foreign := foreignProxyPortOwners(map[uint16]uint32{9001: 100, 9002: 200, 9003: 100}, 100)
	if len(foreign) != 1 || foreign[9002] != 200 {
		t.Fatalf("foreign owners = %v, want only 9002 -> 200", foreign)
	}
	if got := foreignProxyPortOwners(map[uint16]uint32{9001: 100}, 100); len(got) != 0 {
		t.Fatalf("own listener reported foreign: %v", got)
	}
	if got := foreignProxyPortOwners(map[uint16]uint32{9001: 0}, 0); len(got) != 1 {
		t.Fatalf("unknown self PID must not hide an owner: %v", got)
	}
}
