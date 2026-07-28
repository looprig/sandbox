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

func TestAtomicCredentialStoreRejectsNamesAndDelegatesExactPath(t *testing.T) {
	files := &fakeCredentialFileOps{protection: credentialProtection{SystemRead: true, AdministratorsRead: true}}
	store := atomicCredentialStore{root: `C:\ProgramData\Looprig\state`, files: files}
	if err := store.WriteProtected("offline", []byte("cipher")); err != nil {
		t.Fatal(err)
	}
	if files.path != `C:\ProgramData\Looprig\state\offline.dpapi` {
		t.Fatalf("path = %q", files.path)
	}
	for _, name := range []string{"", `..\foreign`, `C:escape`, `nested/name`} {
		if err := store.WriteProtected(name, []byte("cipher")); err == nil {
			t.Fatalf("accepted credential name %q", name)
		}
	}
}

func TestOpenCredentialZerosCiphertextAndReturnsMutablePassword(t *testing.T) {
	store := &fakeCredentialStore{data: []byte("cipher"), protection: credentialProtection{SystemRead: true, AdministratorsRead: true}}
	unprotector := &fakeUnprotector{}
	password, err := openCredential(store, unprotector, "offline")
	if err != nil {
		t.Fatal(err)
	}
	if string(password) != "password" || !allZero(unprotector.seen) || !allZero(store.data) {
		t.Fatalf("credential buffers not handled safely: password=%q seen=%v ciphertext=%v", password, unprotector.seen, store.data)
	}
	zeroBytes(password)
	if !allZero(password) {
		t.Fatal("returned password is not mutable")
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

type fakeCredentialFileOps struct {
	path       string
	data       []byte
	protection credentialProtection
}

func (f *fakeCredentialFileOps) AtomicWrite(path string, data []byte) error {
	f.path = path
	f.data = append([]byte(nil), data...)
	return nil
}
func (f *fakeCredentialFileOps) Inspect(path string) (credentialProtection, error) {
	f.path = path
	return f.protection, nil
}
func (f *fakeCredentialFileOps) Read(path string) ([]byte, error) {
	f.path = path
	return append([]byte(nil), f.data...), nil
}
func (f *fakeCredentialFileOps) Remove(path string) error { f.path = path; return nil }

func (f *fakeCredentialStore) InspectProtection(string) (credentialProtection, error) {
	return f.protection, nil
}
func (f *fakeCredentialStore) ReadProtected(string) ([]byte, error) { return f.data, nil }
func (f *fakeCredentialStore) RemoveProtected(string) error         { f.removed = true; return nil }

type fakeUnprotector struct{ seen []byte }

func (f *fakeUnprotector) Unprotect(ciphertext []byte) ([]byte, error) {
	f.seen = ciphertext
	return []byte("password"), nil
}

func (f *fakeCredentialStore) WriteProtected(name string, ciphertext []byte) error {
	f.name, f.data, f.systemOnly = name, append([]byte(nil), ciphertext...), true
	return f.err
}
