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
