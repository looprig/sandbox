//go:build windows

package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	win "golang.org/x/sys/windows"
)

type namedMutexAPI interface {
	CreateOwned(name, sddl string) (handle win.Handle, alreadyExists bool, err error)
	Release(win.Handle) error
	Close(win.Handle) error
}

type protectedInstallationLocker struct {
	ownerSID string
	mutexes  namedMutexAPI
}

func (l protectedInstallationLocker) Acquire(installationID string) (installationLock, error) {
	if strings.TrimSpace(installationID) == "" || l.mutexes == nil {
		return nil, errors.New("sandbox: invalid Windows installation lock configuration")
	}
	if _, err := win.StringToSid(l.ownerSID); err != nil {
		return nil, fmt.Errorf("sandbox: invalid Windows installation owner SID: %w", err)
	}
	digest := sha256.Sum256([]byte(installationID))
	name := `Global\LooprigSandbox-` + hex.EncodeToString(digest[:12]) + "-host"
	sddl := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;" + l.ownerSID + ")"
	handle, exists, err := l.mutexes.CreateOwned(name, sddl)
	if err != nil {
		return nil, fmt.Errorf("create protected Windows installation mutex: %w", err)
	}
	if exists {
		return nil, errors.Join(errInstallationAlreadyActive, l.mutexes.Close(handle))
	}
	return installationLockFunc(func() error {
		return errors.Join(l.mutexes.Release(handle), l.mutexes.Close(handle))
	}), nil
}

type win32NamedMutexAPI struct{}

func (win32NamedMutexAPI) CreateOwned(name, sddl string) (win.Handle, bool, error) {
	descriptor, err := win.SecurityDescriptorFromString(sddl)
	if err != nil {
		return 0, false, err
	}
	namePtr, err := win.UTF16PtrFromString(name)
	if err != nil {
		return 0, false, err
	}
	attributes := &win.SecurityAttributes{
		Length: uint32(unsafe.Sizeof(win.SecurityAttributes{})), SecurityDescriptor: descriptor,
	}
	handle, createErr := win.CreateMutex(attributes, true, namePtr)
	if errors.Is(createErr, win.ERROR_ALREADY_EXISTS) {
		return handle, true, nil
	}
	return handle, false, createErr
}

func (win32NamedMutexAPI) Release(handle win.Handle) error { return win.ReleaseMutex(handle) }
func (win32NamedMutexAPI) Close(handle win.Handle) error   { return win.CloseHandle(handle) }
