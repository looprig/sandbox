//go:build windows

package windows

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	win "golang.org/x/sys/windows"
)

type credentialProtector interface {
	Protect(plaintext []byte) ([]byte, error)
}

type credentialFileOps interface {
	AtomicWrite(path string, ciphertext []byte) error
	Inspect(path string) (credentialProtection, error)
	Read(path string) ([]byte, error)
	Remove(path string) error
}

type atomicCredentialStore struct {
	root  string
	files credentialFileOps
}

func (store atomicCredentialStore) path(name string) (string, error) {
	if name == "" || filepath.Base(name) != name || strings.ContainsAny(name, `/\\:`) {
		return "", errors.New("sandbox: invalid Windows credential record name")
	}
	return filepath.Join(store.root, name+".dpapi"), nil
}
func (store atomicCredentialStore) WriteProtected(name string, ciphertext []byte) error {
	path, err := store.path(name)
	if err != nil {
		return err
	}
	return store.files.AtomicWrite(path, ciphertext)
}
func (store atomicCredentialStore) InspectProtection(name string) (credentialProtection, error) {
	path, err := store.path(name)
	if err != nil {
		return credentialProtection{}, err
	}
	return store.files.Inspect(path)
}
func (store atomicCredentialStore) ReadProtected(name string) ([]byte, error) {
	path, err := store.path(name)
	if err != nil {
		return nil, err
	}
	return store.files.Read(path)
}
func (store atomicCredentialStore) RemoveProtected(name string) error {
	path, err := store.path(name)
	if err != nil {
		return err
	}
	return store.files.Remove(path)
}

type realCredentialFileOps struct{}

const credentialFileAllAccess uint32 = 0x001f01ff

func (realCredentialFileOps) AtomicWrite(path string, ciphertext []byte) (err error) {
	if len(ciphertext) == 0 {
		return errors.New("sandbox: empty Windows credential ciphertext")
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if attributes, attributeErr := win.GetFileAttributes(win.StringToUTF16Ptr(filepath.Dir(path))); attributeErr != nil || attributes&win.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.Join(errors.New("sandbox: credential directory is unavailable or reparse-backed"), attributeErr)
	}
	if err = protectCredentialDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}
	temporary := path + ".tmp-" + hex.EncodeToString(nonce[:])
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(temporary)
		}
	}()
	_, writeErr := file.Write(ciphertext)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if err = protectCredentialFile(temporary); err != nil {
		return err
	}
	if err = win.MoveFileEx(win.StringToUTF16Ptr(temporary), win.StringToUTF16Ptr(path), win.MOVEFILE_REPLACE_EXISTING|win.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	return nil
}

func protectCredentialDirectory(path string) error {
	sd, err := win.SecurityDescriptorFromString("O:SYG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, err := win.CreateWellKnownSid(win.WinLocalSystemSid)
	if err != nil {
		return err
	}
	return win.SetNamedSecurityInfo(path, win.SE_FILE_OBJECT, win.OWNER_SECURITY_INFORMATION|win.DACL_SECURITY_INFORMATION|win.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
}
func (realCredentialFileOps) Inspect(path string) (credentialProtection, error) {
	return inspectCredentialFileProtection(path)
}
func (realCredentialFileOps) Read(path string) ([]byte, error) { return os.ReadFile(path) }
func (realCredentialFileOps) Remove(path string) error {
	err := os.Remove(path)
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

func protectCredentialFile(path string) error {
	sd, err := win.SecurityDescriptorFromString("O:SYG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, err := win.CreateWellKnownSid(win.WinLocalSystemSid)
	if err != nil {
		return err
	}
	return win.SetNamedSecurityInfo(path, win.SE_FILE_OBJECT, win.OWNER_SECURITY_INFORMATION|win.DACL_SECURITY_INFORMATION|win.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
}

func inspectCredentialFileProtection(path string) (credentialProtection, error) {
	sd, err := win.GetNamedSecurityInfo(path, win.SE_FILE_OBJECT, win.OWNER_SECURITY_INFORMATION|win.DACL_SECURITY_INFORMATION)
	if err != nil {
		return credentialProtection{}, err
	}
	if sd == nil {
		return credentialProtection{}, errors.New("sandbox: credential security descriptor is missing")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return credentialProtection{}, err
	}
	result := credentialProtection{SystemRead: owner != nil && owner.IsWellKnown(win.WinLocalSystemSid)}
	control, _, err := sd.Control()
	if err != nil {
		return credentialProtection{}, err
	}
	result.Inherited = control&win.SE_DACL_PROTECTED == 0
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return credentialProtection{}, errors.New("sandbox: credential DACL is missing")
	}
	if dacl.AceCount != 2 {
		result.OtherRead = true
	}
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *win.ACCESS_ALLOWED_ACE
		if err := win.GetAce(dacl, index, &ace); err != nil {
			return credentialProtection{}, err
		}
		if ace.Header.AceType != win.ACCESS_ALLOWED_ACE_TYPE || uint32(ace.Mask)&credentialFileAllAccess != credentialFileAllAccess {
			result.OtherRead = true
			continue
		}
		sid := (*win.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.IsWellKnown(win.WinLocalSystemSid):
			result.SystemRead = true
		case sid.IsWellKnown(win.WinBuiltinAdministratorsSid):
			result.AdministratorsRead = true
		default:
			result.OtherRead = true
		}
	}
	return result, nil
}

type protectedCredentialStore interface {
	// WriteProtected must atomically persist ciphertext in a protected object.
	WriteProtected(name string, ciphertext []byte) error
	InspectProtection(name string) (credentialProtection, error)
	ReadProtected(name string) ([]byte, error)
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

func (systemDPAPI) Unprotect(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.New("sandbox: empty DPAPI ciphertext")
	}
	user, err := win.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return nil, err
	}
	if !user.User.Sid.IsWellKnown(win.WinLocalSystemSid) {
		return nil, errors.New("sandbox: LocalSystem is required for broker credential decryption")
	}
	working := append([]byte(nil), ciphertext...)
	defer zeroBytes(working)
	in := win.DataBlob{Size: uint32(len(working)), Data: &working[0]}
	var out win.DataBlob
	if err := win.CryptUnprotectData(&in, nil, nil, 0, nil, win.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, err
	}
	defer win.LocalFree(win.Handle(unsafe.Pointer(out.Data)))
	if out.Size == 0 || out.Data == nil {
		return nil, errors.New("sandbox: DPAPI returned empty plaintext")
	}
	plaintext := append([]byte(nil), unsafe.Slice(out.Data, int(out.Size))...)
	runtime.KeepAlive(working)
	return plaintext, nil
}

type credentialUnprotector interface{ Unprotect([]byte) ([]byte, error) }

// openCredential returns a mutable password buffer owned by the caller. The
// caller must call zeroBytes immediately after LogonUser completes.
func openCredential(store protectedCredentialStore, unprotector credentialUnprotector, name string) ([]byte, error) {
	protection, err := store.InspectProtection(name)
	if err != nil {
		return nil, err
	}
	if !protection.valid() {
		return nil, errors.New("sandbox: Windows credential ciphertext ACL is not protected")
	}
	ciphertext, err := store.ReadProtected(name)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(ciphertext)
	working := append([]byte(nil), ciphertext...)
	defer zeroBytes(working)
	plaintext, err := unprotector.Unprotect(working)
	if err != nil {
		return nil, err
	}
	if len(plaintext) == 0 {
		return nil, errors.New("sandbox: DPAPI returned empty plaintext")
	}
	return plaintext, nil
}
