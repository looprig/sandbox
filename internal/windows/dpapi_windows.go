//go:build windows

package windows

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	win "golang.org/x/sys/windows"
)

type credentialProtector interface {
	Protect(plaintext []byte) ([]byte, error)
}

type protectedCredentialStore interface {
	// WriteProtected must atomically persist ciphertext in a protected object.
	WriteProtected(name string, ciphertext []byte) error
	InspectProtection(name string) (credentialProtection, error)
	RemoveProtected(name string) error
}

type credentialProtection struct {
	SystemRead         bool
	AdministratorsRead bool
	OtherRead          bool
	Inherited          bool
}

func (protection credentialProtection) valid() bool {
	return protection.SystemRead && protection.AdministratorsRead && !protection.OtherRead && !protection.Inherited
}

func sealCredential(protector credentialProtector, store protectedCredentialStore, name string, plaintext []byte) error {
	defer zeroBytes(plaintext)
	if name == "" || len(plaintext) == 0 {
		return errors.New("sandbox: incomplete Windows credential record")
	}
	working := append([]byte(nil), plaintext...)
	defer zeroBytes(working)
	ciphertext, err := protector.Protect(working)
	if err != nil {
		return err
	}
	defer zeroBytes(ciphertext)
	if len(ciphertext) == 0 {
		return errors.New("sandbox: DPAPI returned empty ciphertext")
	}
	if err := store.WriteProtected(name, ciphertext); err != nil {
		return err
	}
	protection, err := store.InspectProtection(name)
	if err != nil {
		return errors.Join(err, store.RemoveProtected(name))
	}
	if !protection.valid() {
		return errors.Join(fmt.Errorf("sandbox: Windows credential ciphertext ACL is not protected"), store.RemoveProtected(name))
	}
	return nil
}

// systemDPAPI uses user-scope DPAPI. It is valid only in the LocalSystem broker
// process; callers are responsible for verifying that process identity first.
type systemDPAPI struct{}

func (systemDPAPI) Protect(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.New("sandbox: empty DPAPI plaintext")
	}
	user, err := win.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	if !user.User.Sid.IsWellKnown(win.WinLocalSystemSid) {
		return nil, errors.New("sandbox: LocalSystem is required for broker credential protection")
	}
	in := win.DataBlob{Size: uint32(len(plaintext)), Data: &plaintext[0]}
	var out win.DataBlob
	if err := win.CryptProtectData(&in, nil, nil, 0, nil, win.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer win.LocalFree(win.Handle(unsafe.Pointer(out.Data)))
	if out.Size == 0 || out.Data == nil {
		return nil, errors.New("sandbox: DPAPI returned empty ciphertext")
	}
	ciphertext := append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...)
	runtime.KeepAlive(plaintext)
	return ciphertext, nil
}
