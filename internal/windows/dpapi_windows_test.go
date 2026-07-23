//go:build windows

package windows

import (
	"errors"
	"testing"
)

func TestSealCredentialZerosWorkingCopyAndRequiresProtectedStore(t *testing.T) {
	protector := &fakeCredentialProtector{ciphertext: []byte("ciphertext")}
	store := &fakeCredentialStore{protection: credentialProtection{SystemRead: true, AdministratorsRead: true}}
	plaintext := []byte("secret")
	if err := sealCredential(protector, store, "offline", plaintext); err != nil {
		t.Fatal(err)
	}
	if !allZero(plaintext) || !allZero(protector.seen) {
		t.Fatal("plaintext credential remained in a caller or protector buffer")
	}
	if store.name != "offline" || string(store.data) != "ciphertext" || !store.systemOnly {
		t.Fatalf("unexpected persisted credential: %#v", store)
	}
}

func TestSealCredentialZerosBuffersOnFailure(t *testing.T) {
	protector := &fakeCredentialProtector{ciphertext: []byte("ciphertext")}
	store := &fakeCredentialStore{err: errors.New("write failed")}
	plaintext := []byte("secret")
	if err := sealCredential(protector, store, "offline", plaintext); err == nil {
		t.Fatal("expected failure")
	}
	if !allZero(plaintext) || !allZero(protector.seen) || !allZero(protector.ciphertext) {
		t.Fatal("credential material remained after failure")
	}
}

func TestSealCredentialRejectsBroadOrInheritedCiphertextACL(t *testing.T) {
	for _, protection := range []credentialProtection{
		{SystemRead: true, AdministratorsRead: true, OtherRead: true},
		{SystemRead: true, AdministratorsRead: true, Inherited: true},
		{SystemRead: true},
	} {
		protector := &fakeCredentialProtector{ciphertext: []byte("ciphertext")}
		store := &fakeCredentialStore{protection: protection}
		if err := sealCredential(protector, store, "offline", []byte("secret")); err == nil {
			t.Fatalf("accepted protection %#v", protection)
		}
		if !store.removed {
			t.Fatal("unsafe ciphertext was not removed")
		}
	}
}

type fakeCredentialProtector struct {
	seen       []byte
	ciphertext []byte
}

func (f *fakeCredentialProtector) Protect(plaintext []byte) ([]byte, error) {
	f.seen = plaintext
	return f.ciphertext, nil
}

type fakeCredentialStore struct {
	name       string
	data       []byte
	systemOnly bool
	protection credentialProtection
	err        error
	removed    bool
}

func (f *fakeCredentialStore) InspectProtection(string) (credentialProtection, error) {
	return f.protection, nil
}
func (f *fakeCredentialStore) RemoveProtected(string) error { f.removed = true; return nil }

func (f *fakeCredentialStore) WriteProtected(name string, ciphertext []byte) error {
	f.name, f.data, f.systemOnly = name, append([]byte(nil), ciphertext...), true
	return f.err
}
