//go:build windows

package windows

import (
	"context"
	"errors"
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

type fakeServiceInitializer struct {
	desired brokerDesiredState
	health  brokerIdentityHealth
}

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
