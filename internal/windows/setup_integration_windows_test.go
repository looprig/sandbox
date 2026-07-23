//go:build windows

package windows

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"testing"
)

type removalAccountAPI struct {
	records map[string]sandboxAccountRecord
	deleted []string
}

func (api *removalAccountAPI) Lookup(name string) (sandboxAccountRecord, error) {
	record, ok := api.records[name]
	if !ok {
		return sandboxAccountRecord{}, errAccountNotFound
	}
	return record, nil
}
func (*removalAccountAPI) Create(sandboxAccountRecord, []byte) (sandboxAccountRecord, error) {
	panic("unexpected create")
}
func (*removalAccountAPI) ApplyPolicy(sandboxAccountRecord) error { panic("unexpected apply") }
func (*removalAccountAPI) SetPassword(string, []byte) error       { panic("unexpected password") }
func (api *removalAccountAPI) Delete(name string) error {
	api.deleted = append(api.deleted, name)
	delete(api.records, name)
	return nil
}

type removalServiceAPI struct {
	record           brokerServiceRecord
	stopped, deleted bool
}

func (api *removalServiceAPI) Lookup(string) (brokerServiceRecord, error) { return api.record, nil }
func (*removalServiceAPI) Create(brokerServiceSpecModel) (brokerServiceRecord, error) {
	panic("unexpected create")
}
func (*removalServiceAPI) Apply(brokerServiceSpecModel) error { panic("unexpected apply") }
func (api *removalServiceAPI) Stop(string) error              { api.stopped = true; return nil }
func (api *removalServiceAPI) Delete(string) error            { api.deleted = true; return nil }

type removalCredentialStore struct{ removed []string }

func (*removalCredentialStore) WriteProtected(string, []byte) error { panic("unexpected write") }
func (*removalCredentialStore) InspectProtection(string) (credentialProtection, error) {
	panic("unexpected inspect")
}
func (*removalCredentialStore) ReadProtected(string) ([]byte, error) { panic("unexpected read") }
func (store *removalCredentialStore) RemoveProtected(name string) error {
	store.removed = append(store.removed, name)
	return nil
}

type removalFirewallPolicy struct {
	rules   map[string]offlineFirewallRule
	readErr error
}

func (*removalFirewallPolicy) LocalRulesEffective() (bool, error) { return true, nil }
func (policy *removalFirewallPolicy) Get(name string) (offlineFirewallRule, bool, error) {
	if policy.readErr != nil {
		return offlineFirewallRule{}, false, policy.readErr
	}
	rule, ok := policy.rules[name]
	return rule, ok, nil
}
func (*removalFirewallPolicy) Put(offlineFirewallRule) error { panic("unexpected put") }
func (policy *removalFirewallPolicy) Remove(name string) error {
	delete(policy.rules, name)
	return nil
}

func setupRemovalFixture(t *testing.T) (validatedSetup, setupManifest, *removalAccountAPI, *removalServiceAPI, *removalCredentialStore, *removalFirewallPolicy) {
	t.Helper()
	stateRoot := filepath.Join(`C:\ProgramData`, "Looprig", "acceptance")
	manifest := setupManifest{
		InstallationID: "acceptance", OwnerSID: "S-1-5-21-1-2-3-1000",
		HostPath:   filepath.Join(stateRoot, "slots", "generation", "sandbox-host.exe"),
		OfflineSID: "S-1-5-21-1-2-3-1001", OnlineSID: "S-1-5-21-1-2-3-1002",
		ServiceIdentity: "service-identity", ProxyPorts: []uint16{41001},
	}
	names, err := deriveInstallationPrincipalNames(manifest.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	accounts := &removalAccountAPI{records: map[string]sandboxAccountRecord{
		names.Offline: {Name: names.Offline, SID: manifest.OfflineSID, Owned: true},
		names.Online:  {Name: names.Online, SID: manifest.OnlineSID, Owned: true},
	}}
	service := &removalServiceAPI{record: brokerServiceRecord{
		Spec: brokerServiceSpecModel{Name: names.Service}, Identity: manifest.ServiceIdentity, Owned: true,
	}}
	credentials := &removalCredentialStore{}
	rules, err := offlineFirewallRules(manifest.InstallationID, manifest.OfflineSID, manifest.ProxyPorts)
	if err != nil {
		t.Fatal(err)
	}
	firewall := &removalFirewallPolicy{rules: ruleMap(rules)}
	setup := validatedSetup{config: SetupConfig{InstallationID: manifest.InstallationID}, stateRoot: stateRoot, ownerSID: manifest.OwnerSID}
	return setup, manifest, accounts, service, credentials, firewall
}

func TestSetupIntegrationPartialCleanupRetainsRecoveryAuthority(t *testing.T) {
	setup, manifest, accounts, service, credentials, firewall := setupRemovalFixture(t)
	firewall.readErr = errors.New("injected firewall inventory failure")
	var removed []string
	err := removeInstalledSetup(context.Background(), setup, manifest, setupRemovalMechanisms{
		accounts: accounts, services: service, credentials: credentials, firewall: firewall,
		validateArtifacts: func(validatedSetup, setupManifest) error { return nil },
		removeDir:         func(path string) error { removed = append(removed, path); return nil },
	})
	if err == nil {
		t.Fatal("partial cleanup failure was hidden")
	}
	if len(removed) != 0 {
		t.Fatalf("manifest/generation removed before dependency cleanup succeeded: %v", removed)
	}
	if !service.deleted || len(accounts.deleted) != 2 || !slices.Equal(credentials.removed, []string{"offline", "online"}) {
		t.Fatalf("independent cleanup did not continue: service=%t accounts=%v credentials=%v", service.deleted, accounts.deleted, credentials.removed)
	}
}

func TestSetupIntegrationSuccessfulRemovalOrdersResidueLast(t *testing.T) {
	setup, manifest, accounts, service, credentials, firewall := setupRemovalFixture(t)
	var removed []string
	if err := removeInstalledSetup(context.Background(), setup, manifest, setupRemovalMechanisms{
		accounts: accounts, services: service, credentials: credentials, firewall: firewall,
		validateArtifacts: func(validatedSetup, setupManifest) error { return nil },
		removeDir:         func(path string) error { removed = append(removed, path); return nil },
	}); err != nil {
		t.Fatal(err)
	}
	want := []string{setup.stateRoot}
	if !slices.Equal(removed, want) || len(firewall.rules) != 0 {
		t.Fatalf("removal order/residue = %v rules=%d, want %v/0", removed, len(firewall.rules), want)
	}
}
