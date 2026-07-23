//go:build windows

package windows

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadBrokerRuntimeConfigDerivesOnlyFromInstalledExecutable(t *testing.T) {
	programData := t.TempDir()
	root := filepath.Join(programData, "Looprig")
	executable := filepath.Join(root, "slots", "generation", "sandbox-host.exe")
	if err := os.MkdirAll(filepath.Dir(executable), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(executable, []byte("host"), 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := hashFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	manifest := setupManifest{Version: setupManifestVersion, State: setupStateReady, InstallationID: "install", OwnerSID: "S-1-5-21-1", HostPath: executable, HostSHA256: digest, ProxyPorts: []uint16{9001}, Protocol: brokerProtocolVersion}
	data, err := encodeSetupManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, readyManifestName), data, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := loadBrokerRuntimeConfigWithVerifier(executable, programData, allowBrokerPaths{})
	if err != nil {
		t.Fatal(err)
	}
	if config.InstallationID != "install" || config.OwnerSID != manifest.OwnerSID || config.Protocol != brokerProtocolVersion || config.OfflineAccount == "" || config.OnlineAccount == "" || config.PipeName == "" || config.JournalPath == "" {
		t.Fatalf("incomplete broker config: %#v", config)
	}
	if _, err := loadBrokerRuntimeConfigWithVerifier(filepath.Join(root, "attacker.exe"), programData, allowBrokerPaths{}); err == nil {
		t.Fatal("accepted executable outside installed generation")
	}
}

type allowBrokerPaths struct{}

func (allowBrokerPaths) Verify(string, string) error { return nil }

type fakeHostInstaller struct {
	fail       string
	calls      []string
	rolledBack bool
	manifest   []byte
	staging    []byte
}

func (f *fakeHostInstaller) PersistStaging(_ validatedSetup, _ stagedHost, data []byte) error {
	f.staging = append([]byte(nil), data...)
	return f.hit("persist-staging")
}

func (f *fakeHostInstaller) hit(name string) error {
	f.calls = append(f.calls, name)
	if f.fail == name {
		return errors.New("injected " + name)
	}
	return nil
}
func (f *fakeHostInstaller) Prepare(validatedSetup) error { return f.hit("prepare") }
func (f *fakeHostInstaller) Stage(validatedSetup) (stagedHost, error) {
	staged := stagedHost{stagingDir: "stage", finalDir: "final", finalHost: `C:\protected\sandbox-host.exe`, digest: strings.Repeat("ab", 32)}
	if err := f.hit("stage"); err != nil {
		return staged, err
	}
	return staged, nil
}
func (f *fakeHostInstaller) SelfTest(context.Context, stagedHost) error { return f.hit("self-test") }
func (f *fakeHostInstaller) Activate(_ validatedSetup, _ stagedHost, data []byte) error {
	f.manifest = append([]byte(nil), data...)
	return f.hit("activate")
}
func (f *fakeHostInstaller) Rollback(stagedHost) error { f.rolledBack = true; return nil }

func TestHostInstallPublishesReadyOnlyAfterSelfTest(t *testing.T) {
	f := &fakeHostInstaller{}
	s := validatedSetup{config: SetupConfig{InstallationID: "install", ProxyPorts: []uint16{9001}}, ownerSID: "S-1-5-21-1"}
	if err := installHost(context.Background(), s, f); err != nil {
		t.Fatal(err)
	}
	m, err := decodeSetupManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if m.State != setupStateReady || m.HostPath != `C:\protected\sandbox-host.exe` {
		t.Fatalf("unexpected manifest: %+v", m)
	}
	staging, err := decodeSetupManifest(f.staging)
	if err != nil || staging.State != setupStateStaging {
		t.Fatalf("staging manifest was not persisted before readiness: %+v, %v", staging, err)
	}
	if f.rolledBack {
		t.Fatal("successful install rolled back")
	}
}

func TestHostInstallRollsBackEveryPostStageFailure(t *testing.T) {
	for _, step := range []string{"stage", "persist-staging", "self-test", "activate"} {
		t.Run(step, func(t *testing.T) {
			f := &fakeHostInstaller{fail: step}
			err := installHost(context.Background(), validatedSetup{config: SetupConfig{InstallationID: "i", ProxyPorts: []uint16{1}}, ownerSID: "S"}, f)
			if err == nil {
				t.Fatal("expected failure")
			}
			if !f.rolledBack {
				t.Fatal("missing rollback")
			}
			if step == "self-test" && len(f.manifest) != 0 {
				t.Fatal("ready manifest published before self-test")
			}
		})
	}
}

func TestPendingSetupDependenciesNeverReportReady(t *testing.T) {
	readiness, err := (pendingSetupDependencyInspector{}).Inspect(context.Background(), validatedSetup{}, setupManifest{})
	if err != nil {
		t.Fatal(err)
	}
	facts := healthyInspection()
	facts.ServiceReady = readiness.service
	facts.AccountsReady = readiness.accounts
	facts.CredentialsReady = readiness.credentials
	facts.FirewallEffective = readiness.firewallEffective
	facts.FirewallUnchanged = readiness.firewallUnchanged
	facts.RuntimeBaselineReady = readiness.runtimeBaseline
	status := statusFromInspection(facts)
	if status.Ready || len(status.Problems) == 0 {
		t.Fatalf("pending dependencies reported ready: %+v", status)
	}
}

func TestInitializeSetupIdentitiesUsesOnlyOwnedStagingGeneration(t *testing.T) {
	setup := validatedSetup{config: SetupConfig{InstallationID: "install"}, stateRoot: `C:\ProgramData\Looprig`}
	manifest := setupManifest{State: setupStateStaging, InstallationID: "install", HostPath: `C:\ProgramData\Looprig\slots\one\sandbox-host.exe`}
	desired, err := desiredBrokerState("install", manifest.HostPath)
	if err != nil {
		t.Fatal(err)
	}
	initializer := &fakeServiceInitializer{health: brokerIdentityHealth{InstallationID: "install", OfflineAccount: desired.OfflineAccount, OfflineSID: "S-1-5-21-1", OnlineAccount: desired.OnlineAccount, OnlineSID: "S-1-5-21-2", CredentialsProtected: true}}
	if _, err := initializeSetupIdentities(context.Background(), setup, manifest, initializer); err != nil {
		t.Fatal(err)
	}
	manifest.State = setupStateReady
	if _, err := initializeSetupIdentities(context.Background(), setup, manifest, initializer); err == nil {
		t.Fatal("ready generation was accepted for identity initialization")
	}
	manifest.State, manifest.InstallationID = setupStateStaging, "foreign"
	if _, err := initializeSetupIdentities(context.Background(), setup, manifest, initializer); err == nil {
		t.Fatal("foreign generation was accepted for identity initialization")
	}
}

func TestInstalledHostPathMustBeExactProtectedSlot(t *testing.T) {
	root := `C:\ProgramData\Looprig`
	tests := []struct {
		path string
		ok   bool
	}{
		{`C:\ProgramData\Looprig\slots\generation\sandbox-host.exe`, true},
		{`C:\attacker\sandbox-host.exe`, false},
		{`C:\ProgramData\Looprig\caller.exe`, false},
		{`C:\ProgramData\Looprig\slots\..\source.exe`, false},
		{`C:\ProgramData\Looprig\slots\generation\nested\sandbox-host.exe`, false},
	}
	for _, test := range tests {
		err := validateInstalledHostPath(root, test.path)
		if (err == nil) != test.ok {
			t.Errorf("validateInstalledHostPath(%q) error = %v, want ok %v", test.path, err, test.ok)
		}
	}
}

func TestHostInstallNeverPersistsCallerSourcePath(t *testing.T) {
	f := &fakeHostInstaller{}
	s := validatedSetup{config: SetupConfig{InstallationID: "i", HostBinary: `C:\attacker\mutable.exe`, ProxyPorts: []uint16{1}}, sourceHost: `C:\attacker\mutable.exe`, ownerSID: "S"}
	if err := installHost(context.Background(), s, f); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(f.manifest), "attacker") || strings.Contains(string(f.manifest), "mutable.exe") {
		t.Fatal("source path persisted")
	}
}
