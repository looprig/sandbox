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

func TestLoadBrokerRuntimeConfigUsesProtectedGenerationManifestBeforeReady(t *testing.T) {
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
	manifest := setupManifest{Version: setupManifestVersion, State: setupStateStaging, InstallationID: "install", OwnerSID: "S-1-5-21-1", HostPath: executable, HostSHA256: digest, ProxyPorts: []uint16{9001}, Protocol: brokerProtocolVersion}
	data, err := encodeSetupManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	generationManifest := filepath.Join(filepath.Dir(executable), "manifest.json")
	if err := os.WriteFile(generationManifest, data, 0600); err != nil {
		t.Fatal(err)
	}
	config, err := loadBrokerRuntimeConfigWithVerifier(executable, programData, allowBrokerPaths{})
	if err != nil {
		t.Fatal(err)
	}
	if config.ManifestState != setupStateStaging || config.GenerationManifestPath != generationManifest ||
		config.HostPath != executable || len(config.ProxyPorts) != 1 || config.ProxyPorts[0] != 9001 {
		t.Fatalf("incomplete staging config: %#v", config)
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

type initializingHostInstaller struct{ fakeHostInstaller }

func (f *initializingHostInstaller) Initialize(_ context.Context, _ validatedSetup, _ stagedHost, manifest setupManifest) (setupManifest, error) {
	manifest.OfflineSID = "S-1-5-21-1"
	manifest.OnlineSID = "S-1-5-21-2"
	manifest.ServiceIdentity = "service-identity"
	return manifest, f.hit("initialize")
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
func (f *fakeHostInstaller) Promote(validatedSetup, stagedHost) error   { return f.hit("promote") }
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

func TestHostInstallPublishesIdentityPinsOnlyAfterDependencyInitialization(t *testing.T) {
	f := &initializingHostInstaller{}
	setup := validatedSetup{config: SetupConfig{InstallationID: "install", ProxyPorts: []uint16{9001}}, ownerSID: "S-1-5-21-owner"}
	if err := installHost(context.Background(), setup, f); err != nil {
		t.Fatal(err)
	}
	manifest, err := decodeSetupManifest(f.manifest)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.State != setupStateReady || manifest.OfflineSID == "" || manifest.OnlineSID == "" || manifest.ServiceIdentity == "" {
		t.Fatalf("ready manifest lacks initialized identity pins: %#v", manifest)
	}
	initialize := -1
	activate := -1
	for index, call := range f.calls {
		switch call {
		case "initialize":
			initialize = index
		case "activate":
			activate = index
		}
	}
	if initialize < 0 || activate <= initialize {
		t.Fatalf("ready activation preceded dependency initialization: %v", f.calls)
	}
}

func TestInitializedGenerationManifestRejectsChangedProtectedIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "manifest.json")
	original := setupManifest{Version: setupManifestVersion, State: setupStateStaging, InstallationID: "install", OwnerSID: "S-1-5-21-owner", HostPath: `C:\root\slots\one\sandbox-host.exe`, HostSHA256: strings.Repeat("ab", 32), ProxyPorts: []uint16{9001}, Protocol: brokerProtocolVersion}
	enriched := original
	enriched.OfflineSID, enriched.OnlineSID, enriched.ServiceIdentity = "S-1-5-21-1", "S-1-5-21-2", "service"
	write := func(manifest setupManifest) {
		data, err := encodeSetupManifest(manifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write(enriched)
	if _, err := readInitializedGenerationManifest(path, original, "service"); err != nil {
		t.Fatal(err)
	}
	enriched.HostSHA256 = strings.Repeat("cd", 32)
	write(enriched)
	if _, err := readInitializedGenerationManifest(path, original, "service"); err == nil {
		t.Fatal("changed protected generation identity was accepted")
	}
}

func TestHostInstallRollsBackEveryPostStageFailure(t *testing.T) {
	for _, step := range []string{"stage", "persist-staging", "self-test", "promote", "initialize", "activate"} {
		t.Run(step, func(t *testing.T) {
			var f hostInstallMechanisms
			base := &fakeHostInstaller{fail: step}
			f = base
			if step == "initialize" {
				f = &initializingHostInstaller{fakeHostInstaller: *base}
			}
			err := installHost(context.Background(), validatedSetup{config: SetupConfig{InstallationID: "i", ProxyPorts: []uint16{1}}, ownerSID: "S"}, f)
			if err == nil {
				t.Fatal("expected failure")
			}
			rolledBack := base.rolledBack
			if initializing, ok := f.(*initializingHostInstaller); ok {
				rolledBack = initializing.rolledBack
				if len(initializing.manifest) != 0 {
					t.Fatal("ready manifest published after failed dependency initialization")
				}
			}
			if !rolledBack {
				t.Fatal("missing rollback")
			}
			if step == "self-test" && len(base.manifest) != 0 {
				t.Fatal("ready manifest published before self-test")
			}
		})
	}
}

func TestInitializedDependenciesRequireExplicitRuntimeEvidence(t *testing.T) {
	setup := validatedSetup{config: SetupConfig{InstallationID: "install"}}
	manifest := setupManifest{InstallationID: "install"}
	inspector := staticSetupInspector{readiness: setupDependencyReadiness{
		service: true, accounts: true, credentials: true,
		firewallEffective: true, firewallUnchanged: true,
		runtimeBaseline: false,
	}}
	ready, err := initializedDependenciesReady(context.Background(), setup, manifest, inspector)
	if err != nil {
		t.Fatal(err)
	}
	if ready {
		t.Fatal("machine dependencies were treated as ready without approved runtime evidence")
	}
	inspector.readiness.runtimeBaseline = true
	ready, err = initializedDependenciesReady(context.Background(), setup, manifest, inspector)
	if err != nil || !ready {
		t.Fatalf("explicitly approved dependencies = %v, %v", ready, err)
	}
}

func TestHostRefreshCarriesOnlyManifestPinnedIdentity(t *testing.T) {
	previous := setupManifest{
		Version: setupManifestVersion, State: setupStateReady,
		InstallationID: "install", OwnerSID: "S-1-5-21-owner",
		HostPath:   `C:\protected\slots\old\sandbox-host.exe`,
		HostSHA256: strings.Repeat("cd", 32), ProxyPorts: []uint16{9001},
		Protocol:   brokerProtocolVersion,
		OfflineSID: "S-1-5-21-101", OnlineSID: "S-1-5-21-102",
		ServiceIdentity: "old-service",
	}
	setup := validatedSetup{
		config:   SetupConfig{InstallationID: "install", ProxyPorts: []uint16{9001}},
		ownerSID: previous.OwnerSID, prior: &previous,
	}
	f := &fakeHostInstaller{}
	if err := installHost(context.Background(), setup, f); err != nil {
		t.Fatal(err)
	}
	staging, err := decodeSetupManifest(f.staging)
	if err != nil {
		t.Fatal(err)
	}
	if staging.OfflineSID != previous.OfflineSID || staging.OnlineSID != previous.OnlineSID {
		t.Fatalf("refresh lost manifest-pinned account identity: %#v", staging)
	}
	if staging.ServiceIdentity == "" || staging.ServiceIdentity == previous.ServiceIdentity {
		t.Fatalf("refresh did not pin the new generation service identity: %#v", staging)
	}
}

func TestRefreshServiceRequiresPriorOwnedIdentity(t *testing.T) {
	desired, err := desiredBrokerState("install", `C:\protected\slots\new\sandbox-host.exe`)
	if err != nil {
		t.Fatal(err)
	}
	oldSpec := desired.Service
	oldSpec.BinaryPath = `C:\protected\slots\old\sandbox-host.exe`
	oldIdentity := serviceSpecIdentity(oldSpec)
	prior := setupManifest{ServiceIdentity: oldIdentity}

	foreign := &fakeSCMFacade{record: brokerServiceRecord{Spec: oldSpec, Identity: "foreign"}}
	if _, _, err := reconcileSetupService(foreign, desired.Service, &prior); !errors.Is(err, errServiceOwnershipMismatch) {
		t.Fatalf("foreign service refresh error = %v, want ownership mismatch", err)
	}

	owned := &fakeSCMFacade{record: brokerServiceRecord{Spec: oldSpec, Identity: oldIdentity, Running: true}}
	created, previous, err := reconcileSetupService(owned, desired.Service, &prior)
	if err != nil {
		t.Fatal(err)
	}
	if created || previous == nil || previous.Identity != oldIdentity ||
		owned.stopped != desired.Service.Name || owned.applied != desired.Service {
		t.Fatalf("owned refresh did not preserve rollback state: created=%v previous=%#v facade=%#v", created, previous, owned)
	}
}

func TestUnavailableRuntimeEvidenceNeverReportsApproved(t *testing.T) {
	approved, err := (unavailableApprovedRuntimeEvidence{}).Approved(context.Background(), validatedSetup{}, setupManifest{})
	if err != nil {
		t.Fatal(err)
	}
	if approved {
		t.Fatal("missing supported-worker runtime evidence was approved")
	}
}

func TestInstalledSetupInspectorRequiresManifestPinnedOwnedObjects(t *testing.T) {
	names, err := deriveInstallationPrincipalNames("install")
	if err != nil {
		t.Fatal(err)
	}
	host := `C:\ProgramData\Looprig\slots\one\sandbox-host.exe`
	desired, err := desiredBrokerState("install", host)
	if err != nil {
		t.Fatal(err)
	}
	manifest := setupManifest{InstallationID: "install", HostPath: host, OfflineSID: "S-1-5-21-1", OnlineSID: "S-1-5-21-2", ServiceIdentity: serviceSpecIdentity(desired.Service)}
	accounts := &mappedSetupAccounts{records: map[string]sandboxAccountRecord{
		names.Offline: {Name: names.Offline, SID: manifest.OfflineSID, Owned: true, Policy: requiredSandboxAccountPolicy()},
		names.Online:  {Name: names.Online, SID: manifest.OnlineSID, Owned: true, Policy: requiredSandboxAccountPolicy()},
	}}
	service := &fakeServiceAPI{record: brokerServiceRecord{Spec: desired.Service, Identity: manifest.ServiceIdentity, Owned: true, Running: true}}
	credentials := &fakeCredentialStore{protection: credentialProtection{SystemRead: true, AdministratorsRead: true}}
	got, err := (installedSetupDependencyInspector{accounts: accounts, services: service, credentials: credentials, evidence: staticRuntimeEvidence(true)}).
		Inspect(context.Background(), validatedSetup{}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !got.accounts || !got.credentials || !got.service || !got.runtimeBaseline {
		t.Fatalf("healthy pinned installation reported %#v", got)
	}
	manifest.OfflineSID = ""
	got, err = (installedSetupDependencyInspector{accounts: accounts, services: service, credentials: credentials, evidence: staticRuntimeEvidence(true)}).
		Inspect(context.Background(), validatedSetup{}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got.accounts {
		t.Fatal("deterministic account name was treated as ownership without a manifest SID pin")
	}
}

func TestRemoveInstalledSetupRefusesUnpinnedIdentity(t *testing.T) {
	manifest := setupManifest{InstallationID: "install", OwnerSID: "S-1-5-21-owner", HostPath: `C:\ProgramData\Looprig\slots\one\sandbox-host.exe`, ProxyPorts: []uint16{9001}}
	setup := validatedSetup{config: SetupConfig{InstallationID: "install"}, stateRoot: `C:\ProgramData\Looprig`, ownerSID: manifest.OwnerSID}
	err := removeInstalledSetup(context.Background(), setup, manifest, setupRemovalMechanisms{
		accounts: &mappedSetupAccounts{}, services: &fakeServiceAPI{}, credentials: &fakeCredentialStore{},
		firewall: &fakeFirewallPolicy{effective: true}, removeDir: func(string) error { return nil },
		validateArtifacts: func(validatedSetup, setupManifest) error { return nil },
	})
	if err == nil {
		t.Fatal("removal adopted deterministic names without manifest-pinned identities")
	}
}

func TestValidateOwnedSetupArtifactsAcceptsCompleteOwnedTreeAndRejectsForeignResidue(t *testing.T) {
	root := t.TempDir()
	generation := strings.Repeat("a1", 16)
	host := filepath.Join(root, "slots", generation, "sandbox-host.exe")
	manifest := setupManifest{
		Version: setupManifestVersion, State: setupStateReady,
		InstallationID: "remove-owned", OwnerSID: "S-1-5-21-owner",
		OfflineSID: "S-1-5-21-1", OnlineSID: "S-1-5-21-2",
		ServiceIdentity: "service", HostPath: host, HostSHA256: strings.Repeat("ab", 32),
		ProxyPorts: []uint16{41001}, Protocol: brokerProtocolVersion,
	}
	generationManifest := manifest
	generationManifest.State = setupStateStaging
	data, err := encodeSetupManifest(generationManifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, directory := range []string{
		filepath.Dir(host),
		filepath.Join(root, "credentials"),
		filepath.Join(root, ".staging-"+strings.Repeat("b2", 16)),
	} {
		if err := os.MkdirAll(directory, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, contents := range map[string][]byte{
		filepath.Join(root, readyManifestName):          data,
		filepath.Join(root, runtimeEvidenceName):        {},
		filepath.Join(root, runtimeEvidenceName+".tmp"): {},
		filepath.Join(root, "broker-leases.journal"):    {},
		host: []byte("host"),
		filepath.Join(filepath.Dir(host), "manifest.json"):                               data,
		filepath.Join(root, "credentials", "offline.dpapi"):                              []byte("cipher"),
		filepath.Join(root, "credentials", "online.dpapi.tmp-"+strings.Repeat("c3", 16)): []byte("temp"),
		filepath.Join(root, ".staging-"+strings.Repeat("b2", 16), "sandbox-host.exe"):    []byte("stage"),
	} {
		if err := os.WriteFile(path, contents, 0600); err != nil {
			t.Fatal(err)
		}
	}
	setup := validatedSetup{
		config:    SetupConfig{InstallationID: manifest.InstallationID},
		stateRoot: root, ownerSID: manifest.OwnerSID,
	}
	if err := validateOwnedSetupArtifacts(setup, manifest); err != nil {
		t.Fatalf("owned artifact tree rejected: %v", err)
	}
	foreign := filepath.Join(root, "do-not-delete.txt")
	if err := os.WriteFile(foreign, []byte("foreign"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateOwnedSetupArtifacts(setup, manifest); err == nil {
		t.Fatal("foreign state-root artifact was accepted for recursive removal")
	}
}

func TestRemoveInstalledSetupDeletesWholeInventoriedRootAfterDependencies(t *testing.T) {
	root := t.TempDir()
	host := filepath.Join(root, "slots", strings.Repeat("d4", 16), "sandbox-host.exe")
	manifest := setupManifest{
		InstallationID: "remove-all", OwnerSID: "S-1-5-21-owner", HostPath: host,
		OfflineSID: "S-1-5-21-1", OnlineSID: "S-1-5-21-2",
		ServiceIdentity: "owned-service", ProxyPorts: []uint16{41001},
	}
	names, err := deriveInstallationPrincipalNames(manifest.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	accounts := &mappedSetupAccounts{records: map[string]sandboxAccountRecord{
		names.Offline: {Name: names.Offline, SID: manifest.OfflineSID, Owned: true},
		names.Online:  {Name: names.Online, SID: manifest.OnlineSID, Owned: true},
	}}
	service := &fakeServiceAPI{record: brokerServiceRecord{
		Spec:     brokerServiceSpecModel{Name: names.Service},
		Identity: manifest.ServiceIdentity, Owned: true,
	}}
	credentials := &fakeCredentialStore{}
	var removed string
	err = removeInstalledSetup(context.Background(), validatedSetup{
		config:    SetupConfig{InstallationID: manifest.InstallationID},
		stateRoot: root, ownerSID: manifest.OwnerSID,
	}, manifest, setupRemovalMechanisms{
		accounts: accounts, services: service, credentials: credentials,
		firewall:          &fakeFirewallPolicy{effective: true},
		validateArtifacts: func(validatedSetup, setupManifest) error { return nil },
		removeDir: func(path string) error {
			if len(accounts.records) != 0 || service.deleted == "" || !credentials.removed {
				return errors.New("artifact deletion preceded dependency removal")
			}
			removed = path
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if removed != root {
		t.Fatalf("removed root = %q, want %q", removed, root)
	}
}

type staticRuntimeEvidence bool

func (approved staticRuntimeEvidence) Approved(context.Context, validatedSetup, setupManifest) (bool, error) {
	return bool(approved), nil
}

type mappedSetupAccounts struct {
	records map[string]sandboxAccountRecord
}

func (a *mappedSetupAccounts) Lookup(name string) (sandboxAccountRecord, error) {
	record, ok := a.records[name]
	if !ok {
		return sandboxAccountRecord{}, errAccountNotFound
	}
	return record, nil
}
func (*mappedSetupAccounts) Create(sandboxAccountRecord, []byte) (sandboxAccountRecord, error) {
	return sandboxAccountRecord{}, errors.New("unexpected create")
}
func (*mappedSetupAccounts) ApplyPolicy(sandboxAccountRecord) error {
	return errors.New("unexpected policy update")
}
func (*mappedSetupAccounts) SetPassword(string, []byte) error {
	return errors.New("unexpected password update")
}
func (a *mappedSetupAccounts) Delete(name string) error {
	delete(a.records, name)
	return nil
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

type rejectBrokerPaths struct{ err error }

func (verifier rejectBrokerPaths) Verify(string, string) error { return verifier.err }

func TestRefreshRevalidatesReadyManifestProtectionAndHostHash(t *testing.T) {
	root := t.TempDir()
	host := filepath.Join(root, "slots", "generation", "sandbox-host.exe")
	if err := os.MkdirAll(filepath.Dir(host), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(host, []byte("trusted host"), 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := hashFile(host)
	if err != nil {
		t.Fatal(err)
	}
	manifest := setupManifest{
		Version: setupManifestVersion, State: setupStateReady, InstallationID: "refresh",
		OwnerSID: "S-1-5-21-1", HostPath: host, HostSHA256: digest,
		OfflineSID: "S-1-5-21-1-1001", OnlineSID: "S-1-5-21-1-1002",
		ServiceIdentity: "owned-service", Protocol: brokerProtocolVersion, ProxyPorts: []uint16{41001},
	}
	data, err := encodeSetupManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, readyManifestName), data, 0600); err != nil {
		t.Fatal(err)
	}
	setup := validatedSetup{config: SetupConfig{InstallationID: "refresh"}, stateRoot: root, ownerSID: manifest.OwnerSID}
	if prior, err := loadOwnedReadyManifestWithVerifier(setup, allowBrokerPaths{}, hashFile); err != nil || prior == nil {
		t.Fatalf("valid refresh manifest = %#v, %v", prior, err)
	}
	if _, err := loadOwnedReadyManifestWithVerifier(setup, rejectBrokerPaths{errors.New("unprotected")}, hashFile); !errors.Is(err, ErrSetupStale) {
		t.Fatalf("unprotected refresh error = %v", err)
	}
	wrongHash := func(string) (string, error) { return strings.Repeat("0", 64), nil }
	if _, err := loadOwnedReadyManifestWithVerifier(setup, allowBrokerPaths{}, wrongHash); !errors.Is(err, ErrSetupStale) {
		t.Fatalf("modified host refresh error = %v", err)
	}
}

func TestRefreshRollbackRestoresPriorFirewallBeforeService(t *testing.T) {
	prior := setupManifest{
		InstallationID: "refresh", OfflineSID: "S-1-5-21-1-1001",
		ProxyPorts: []uint16{41001},
	}
	oldDesired, err := desiredBrokerState(prior.InstallationID, `C:\ProgramData\Looprig\slots\old\sandbox-host.exe`)
	if err != nil {
		t.Fatal(err)
	}
	previous := brokerServiceRecord{Spec: oldDesired.Service, Identity: serviceSpecIdentity(oldDesired.Service), Owned: true}
	newRules, err := offlineFirewallRules(prior.InstallationID, prior.OfflineSID, []uint16{42001})
	if err != nil {
		t.Fatal(err)
	}
	policy := &fakeFirewallPolicy{effective: true, rules: ruleMap(newRules)}
	scm := &fakeSCMFacade{}
	if err := restoreSetupServiceAndFirewall(scm, policy, previous, prior); err != nil {
		t.Fatal(err)
	}
	want, err := offlineFirewallRules(prior.InstallationID, prior.OfflineSID, prior.ProxyPorts)
	if err != nil {
		t.Fatal(err)
	}
	if effective, unchanged, err := inspectOfflineFirewall(policy, want); err != nil || !effective || !unchanged {
		t.Fatalf("restored firewall = effective %t unchanged %t err %v", effective, unchanged, err)
	}
	if scm.stopped != previous.Spec.Name || scm.applied != previous.Spec {
		t.Fatalf("service rollback = stopped %q applied %#v", scm.stopped, scm.applied)
	}

	failing := &fakeFirewallPolicy{effective: true, rules: ruleMap(newRules), failPut: 1}
	scm = &fakeSCMFacade{}
	if err := restoreSetupServiceAndFirewall(scm, failing, previous, prior); err == nil {
		t.Fatal("firewall restore failure was hidden")
	}
	if scm.stopped != previous.Spec.Name || scm.applied.Name != "" {
		t.Fatalf("old service restarted before firewall restoration: stopped %q applied %#v", scm.stopped, scm.applied)
	}
}
