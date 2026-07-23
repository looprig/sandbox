//go:build windows

package windows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestEnsureBrokerServiceUsesFailClosedConfiguration(t *testing.T) {
	api := &fakeServiceAPI{lookupErr: errServiceNotFound}
	spec := brokerServiceSpec("lsb-svc-0123456789ab", `C:\ProgramData\Looprig\sandbox-host.exe`)
	if _, err := ensureBrokerService(api, spec); err != nil {
		t.Fatal(err)
	}
	if len(api.created) != 1 {
		t.Fatalf("create calls = %d", len(api.created))
	}
	got := api.created[0]
	if got.Account != localSystemAccount || got.Start != serviceStartAutomatic || got.SIDType != serviceSIDRestricted || !got.FailureActions.Restart || got.FailureActions.ResetPeriodSeconds == 0 {
		t.Fatalf("unsafe service configuration: %#v", got)
	}
}

func TestEnsureBrokerServiceRejectsForeignExistingService(t *testing.T) {
	spec := brokerServiceSpec("lsb-svc-0123456789ab", `C:\ProgramData\Looprig\sandbox-host.exe`)
	api := &fakeServiceAPI{record: brokerServiceRecord{Spec: spec, Owned: false}}
	if _, err := ensureBrokerService(api, spec); !errors.Is(err, errServiceOwnershipMismatch) {
		t.Fatalf("got %v, want ownership mismatch", err)
	}
	if len(api.updated) != 0 {
		t.Fatal("foreign service was modified")
	}
}

func TestRemoveBrokerServiceRequiresExactManifestIdentity(t *testing.T) {
	spec := brokerServiceSpec("lsb-svc-0123456789ab", `C:\ProgramData\Looprig\sandbox-host.exe`)
	api := &fakeServiceAPI{record: brokerServiceRecord{Spec: spec, Owned: true, Identity: "service-id"}}
	if err := removeBrokerService(api, spec.Name, "other-id"); !errors.Is(err, errServiceOwnershipMismatch) {
		t.Fatalf("got %v, want ownership mismatch", err)
	}
	if api.stopped || api.deleted != "" {
		t.Fatal("service changed without ownership proof")
	}
	if err := removeBrokerService(api, spec.Name, "service-id"); err != nil {
		t.Fatal(err)
	}
	if !api.stopped || api.deleted != spec.Name {
		t.Fatalf("removal incomplete: %#v", api)
	}
}

func TestInitializeBrokerIdentitiesSendsNoCredentialAndRequiresExactHealth(t *testing.T) {
	desired, err := desiredBrokerState("installation-alpha", `C:\ProgramData\Looprig\slots\one\sandbox-host.exe`)
	if err != nil {
		t.Fatal(err)
	}
	initializer := &fakeServiceInitializer{health: brokerIdentityHealth{
		InstallationID:       desired.InstallationID,
		OfflineAccount:       desired.OfflineAccount,
		OfflineSID:           "S-1-5-21-10",
		OnlineAccount:        desired.OnlineAccount,
		OnlineSID:            "S-1-5-21-11",
		CredentialsProtected: true,
	}}
	health, err := initializeBrokerIdentities(context.Background(), initializer, desired)
	if err != nil {
		t.Fatal(err)
	}
	if health.OfflineSID == health.OnlineSID || initializer.desired != desired {
		t.Fatalf("incorrect initialization: health=%#v desired=%#v", health, initializer.desired)
	}
	initializer.health.CredentialsProtected = false
	if _, err := initializeBrokerIdentities(context.Background(), initializer, desired); err == nil {
		t.Fatal("unprotected credentials were accepted as healthy")
	}
}

func TestSCMServiceAdapterRequiresManifestFingerprintAndReadBack(t *testing.T) {
	spec := brokerServiceSpec("lsb-svc-0123456789ab", `C:\ProgramData\Looprig\sandbox-host.exe`)
	identity := serviceSpecIdentity(spec)
	facade := &fakeSCMFacade{record: brokerServiceRecord{Spec: spec, Identity: identity}}
	api := scmServiceAPI{scm: facade, ownedIdentity: identity}
	record, err := api.Create(spec)
	if err != nil || !record.Owned || facade.created != spec {
		t.Fatalf("create failed: record=%#v err=%v", record, err)
	}
	facade.record.Identity = "different"
	if _, err := api.Create(spec); err == nil {
		t.Fatal("SCM read-back mismatch was accepted")
	}
	foreign := brokerServiceSpec("foreign", spec.BinaryPath)
	if _, err := api.Create(foreign); !errors.Is(err, errServiceOwnershipMismatch) {
		t.Fatalf("foreign spec got %v", err)
	}
}

func TestProvisionBrokerIdentityStateCreatesAndRefreshesInsideService(t *testing.T) {
	desired, err := desiredBrokerState("installation-alpha", `C:\ProgramData\Looprig\slots\one\sandbox-host.exe`)
	if err != nil {
		t.Fatal(err)
	}
	accounts := &fakeRuntimeAccounts{records: map[string]sandboxAccountRecord{}}
	store := &fakeCredentialStore{protection: credentialProtection{SystemRead: true, AdministratorsRead: true}}
	runtime := brokerIdentityRuntime{accounts: accounts, protector: freshCredentialProtector{}, store: store, random: bytes.NewReader(bytes.Repeat([]byte{17}, 256))}
	health, err := provisionBrokerIdentityState(runtime, desired, false)
	if err != nil {
		t.Fatal(err)
	}
	if !health.CredentialsProtected || health.OfflineSID == "" || health.OnlineSID == "" || health.OfflineSID == health.OnlineSID {
		t.Fatalf("unhealthy provision result: %#v", health)
	}
	if accounts.passwordUpdates != 0 {
		t.Fatal("initial creation unexpectedly used refresh path")
	}
	runtime.random = bytes.NewReader(bytes.Repeat([]byte{19}, 256))
	if _, err := provisionBrokerIdentityState(runtime, desired, true); err != nil {
		t.Fatal(err)
	}
	if accounts.passwordUpdates != 2 {
		t.Fatalf("refresh password updates = %d", accounts.passwordUpdates)
	}
}

func TestProtectedBrokerCredentialSourceReturnsCallerOwnedPassword(t *testing.T) {
	store := &fakeCredentialStore{data: []byte("cipher"), protection: credentialProtection{SystemRead: true, AdministratorsRead: true}}
	source := protectedBrokerCredentialSource{config: brokerRuntimeConfig{OfflineAccount: "offline-account"}, store: store, unprotector: &fakeUnprotector{}}
	account, password, err := source.LoadCredential(brokerAccountOffline)
	if err != nil {
		t.Fatal(err)
	}
	if account != "offline-account" || string(password) != "password" {
		t.Fatalf("credential = %q %q", account, password)
	}
	zeroBytes(password)
	if !allZero(password) {
		t.Fatal("credential source returned immutable password")
	}
	if _, _, err := source.LoadCredential(brokerAccountUnspecified); err == nil {
		t.Fatal("accepted unspecified account")
	}
}

type fakeServiceInitializer struct {
	desired brokerDesiredState
	health  brokerIdentityHealth
}

type fakeSCMFacade struct {
	record  brokerServiceRecord
	created brokerServiceSpecModel
	applied brokerServiceSpecModel
	stopped string
	deleted string
}

type freshCredentialProtector struct{}

func (freshCredentialProtector) Protect(plaintext []byte) ([]byte, error) {
	return append([]byte("cipher-"), plaintext...), nil
}

type fakeRuntimeAccounts struct {
	records         map[string]sandboxAccountRecord
	passwordUpdates int
	nextSID         int
}

func (f *fakeRuntimeAccounts) Lookup(name string) (sandboxAccountRecord, error) {
	record, ok := f.records[name]
	if !ok {
		return sandboxAccountRecord{}, errAccountNotFound
	}
	return record, nil
}
func (f *fakeRuntimeAccounts) Create(record sandboxAccountRecord, _ []byte) (sandboxAccountRecord, error) {
	f.nextSID++
	record.SID = fmt.Sprintf("S-1-5-21-%d", f.nextSID)
	record.Owned = true
	f.records[record.Name] = record
	return record, nil
}
func (f *fakeRuntimeAccounts) ApplyPolicy(record sandboxAccountRecord) error {
	f.records[record.Name] = record
	return nil
}
func (f *fakeRuntimeAccounts) SetPassword(string, []byte) error { f.passwordUpdates++; return nil }
func (f *fakeRuntimeAccounts) Delete(name string) error         { delete(f.records, name); return nil }

func (f *fakeSCMFacade) Lookup(brokerServiceSpecModel) (brokerServiceRecord, error) {
	return f.record, nil
}
func (f *fakeSCMFacade) Create(spec brokerServiceSpecModel) error { f.created = spec; return nil }
func (f *fakeSCMFacade) Apply(spec brokerServiceSpecModel) error  { f.applied = spec; return nil }
func (f *fakeSCMFacade) Start(string) error                       { return nil }
func (f *fakeSCMFacade) Stop(name string) error                   { f.stopped = name; return nil }
func (f *fakeSCMFacade) Delete(name string) error                 { f.deleted = name; return nil }

func (f *fakeServiceInitializer) EnsureService(context.Context, brokerServiceSpecModel) error {
	return nil
}
func (f *fakeServiceInitializer) Initialize(_ context.Context, desired brokerDesiredState) (brokerIdentityHealth, error) {
	f.desired = desired
	return f.health, nil
}

type fakeServiceAPI struct {
	record    brokerServiceRecord
	lookupErr error
	created   []brokerServiceSpecModel
	updated   []brokerServiceSpecModel
	stopped   bool
	deleted   string
}

func (f *fakeServiceAPI) Lookup(string) (brokerServiceRecord, error) {
	if f.lookupErr != nil {
		return brokerServiceRecord{}, f.lookupErr
	}
	return f.record, nil
}
func (f *fakeServiceAPI) Create(spec brokerServiceSpecModel) (brokerServiceRecord, error) {
	f.created = append(f.created, spec)
	return brokerServiceRecord{Spec: spec, Owned: true, Identity: "created-id"}, nil
}
func (f *fakeServiceAPI) Apply(spec brokerServiceSpecModel) error {
	f.updated = append(f.updated, spec)
	return nil
}
func (f *fakeServiceAPI) Stop(string) error        { f.stopped = true; return nil }
func (f *fakeServiceAPI) Delete(name string) error { f.deleted = name; return nil }
