//go:build windows

package windows

import (
	"bytes"
	"errors"
	"testing"
)

func TestNewAccountPasswordUsesMutableBoundedAlphabet(t *testing.T) {
	password, err := newAccountPassword(bytes.NewReader(bytes.Repeat([]byte{17}, 64)), 32)
	if err != nil {
		t.Fatal(err)
	}
	if len(password) != 32 {
		t.Fatalf("password length = %d", len(password))
	}
	for _, value := range password {
		if !bytes.ContainsRune([]byte(accountPasswordAlphabet), rune(value)) {
			t.Fatalf("unexpected password byte %q", value)
		}
	}
	zeroBytes(password)
	if !allZero(password) {
		t.Fatal("generated password is not wipeable")
	}
}

func TestInstallationPrincipalNamesAreDeterministicAndBounded(t *testing.T) {
	first, err := deriveInstallationPrincipalNames("customer/install:alpha")
	if err != nil {
		t.Fatal(err)
	}
	second, err := deriveInstallationPrincipalNames("customer/install:alpha")
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("names changed: %#v != %#v", first, second)
	}
	if first.Offline == first.Online || first.Offline == first.Service || first.Online == first.Service {
		t.Fatalf("principal names collided: %#v", first)
	}
	if len(first.Offline) > windowsLocalAccountNameLimit || len(first.Online) > windowsLocalAccountNameLimit {
		t.Fatalf("account name exceeds Windows limit: %#v", first)
	}
	other, err := deriveInstallationPrincipalNames("customer/install:beta")
	if err != nil {
		t.Fatal(err)
	}
	if first == other {
		t.Fatal("different installation identities derived identical names")
	}
}

func TestReconcileSandboxAccountCreatesLeastPrivilegeAccount(t *testing.T) {
	api := &fakeAccountAPI{lookupErr: errAccountNotFound}
	password := []byte("temporary-secret")
	result, err := reconcileSandboxAccount(api, "lsb-o-0123456789ab", password, false)
	if err != nil {
		t.Fatal(err)
	}
	if !allZero(password) {
		t.Fatal("credential buffer was not zeroed")
	}
	if result.SID == "" || len(api.created) != 1 {
		t.Fatalf("account was not created: result=%#v calls=%#v", result, api.created)
	}
	want := sandboxAccountPolicy{PasswordNeverExpires: true, HiddenFromUI: true, Groups: []string{windowsUsersGroup}, Rights: []string{serviceLogonRight}, DenyRights: []string{interactiveLogonRight, remoteInteractiveLogonRight, networkLogonRight}}
	if !result.Policy.equal(want) {
		t.Fatalf("wrong policy: got %#v want %#v", result.Policy, want)
	}
}

func TestReconcileSandboxAccountRejectsUnexpectedOwner(t *testing.T) {
	api := &fakeAccountAPI{record: sandboxAccountRecord{Name: "lsb-o-0123456789ab", SID: "S-1-5-21-1", Owned: false}}
	password := []byte("temporary-secret")
	_, err := reconcileSandboxAccount(api, api.record.Name, password, true)
	if !errors.Is(err, errAccountOwnershipMismatch) {
		t.Fatalf("got %v, want ownership mismatch", err)
	}
	if len(api.updated) != 0 || len(api.created) != 0 {
		t.Fatal("unexpected account was modified")
	}
	if !allZero(password) {
		t.Fatal("credential buffer was not zeroed on failure")
	}
}

func TestReconcileSandboxAccountPreservesValidIdentityWithoutRotation(t *testing.T) {
	policy := requiredSandboxAccountPolicy()
	api := &fakeAccountAPI{record: sandboxAccountRecord{Name: "lsb-o-0123456789ab", SID: "S-1-5-21-1", Owned: true, Policy: policy}}
	password := []byte("unused-secret")
	result, err := reconcileSandboxAccount(api, api.record.Name, password, false)
	if err != nil {
		t.Fatal(err)
	}
	if result.SID != api.record.SID || len(api.updated) != 0 || len(api.passwords) != 0 {
		t.Fatalf("idempotent setup changed account: result=%#v api=%#v", result, api)
	}
	if !allZero(password) {
		t.Fatal("unused credential buffer was not zeroed")
	}
}

func TestRemoveSandboxAccountRequiresManifestIdentity(t *testing.T) {
	api := &fakeAccountAPI{record: sandboxAccountRecord{Name: "lsb-o-0123456789ab", SID: "S-1-5-21-2", Owned: true}}
	if err := removeSandboxAccount(api, api.record.Name, "S-1-5-21-other"); !errors.Is(err, errAccountOwnershipMismatch) {
		t.Fatalf("got %v, want ownership mismatch", err)
	}
	if api.deleted != "" {
		t.Fatal("account deleted without exact SID ownership proof")
	}
	if err := removeSandboxAccount(api, api.record.Name, api.record.SID); err != nil {
		t.Fatal(err)
	}
	if api.deleted != api.record.Name {
		t.Fatalf("deleted %q", api.deleted)
	}
}

type fakeAccountAPI struct {
	record    sandboxAccountRecord
	lookupErr error
	created   []sandboxAccountRecord
	updated   []sandboxAccountRecord
	passwords []string
	deleted   string
}

func (f *fakeAccountAPI) Lookup(name string) (sandboxAccountRecord, error) {
	if f.lookupErr != nil {
		return sandboxAccountRecord{}, f.lookupErr
	}
	return f.record, nil
}
func (f *fakeAccountAPI) Create(record sandboxAccountRecord, password []byte) (sandboxAccountRecord, error) {
	record.SID = "S-1-5-21-created"
	record.Owned = true
	f.created = append(f.created, record)
	return record, nil
}
func (f *fakeAccountAPI) ApplyPolicy(record sandboxAccountRecord) error {
	f.updated = append(f.updated, record)
	return nil
}
func (f *fakeAccountAPI) SetPassword(name string, password []byte) error {
	f.passwords = append(f.passwords, name)
	return nil
}
func (f *fakeAccountAPI) Delete(name string) error { f.deleted = name; return nil }

func allZero(data []byte) bool {
	for _, value := range data {
		if value != 0 {
			return false
		}
	}
	return true
}
