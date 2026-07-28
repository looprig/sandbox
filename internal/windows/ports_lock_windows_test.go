//go:build windows

package windows

import (
	"errors"
	"strings"
	"testing"

	win "golang.org/x/sys/windows"
)

func TestProtectedInstallationLockerUsesDeterministicProtectedIdentity(t *testing.T) {
	api := &fakeNamedMutexAPI{handle: 17}
	locker := protectedInstallationLocker{ownerSID: "S-1-5-21-1-2-3-1001", mutexes: api}
	lock, err := locker.Acquire("installation")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(api.name, `Global\LooprigSandbox-`) || !strings.HasSuffix(api.name, "-host") {
		t.Fatalf("mutex name = %q", api.name)
	}
	if api.sddl != "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-21-1-2-3-1001)" {
		t.Fatalf("mutex SDDL = %q", api.sddl)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if !api.released || !api.closed {
		t.Fatal("owned mutex was not released and closed")
	}
}

func TestProtectedInstallationLockerRejectsExistingMutex(t *testing.T) {
	api := &fakeNamedMutexAPI{handle: 17, exists: true}
	_, err := (protectedInstallationLocker{ownerSID: "S-1-5-21-1-2-3-1001", mutexes: api}).Acquire("installation")
	if !errors.Is(err, errInstallationAlreadyActive) || !api.closed || api.released {
		t.Fatalf("existing mutex result = %v, closed=%v released=%v", err, api.closed, api.released)
	}
}

type fakeNamedMutexAPI struct {
	handle           win.Handle
	exists, released bool
	closed           bool
	name, sddl       string
}

func (a *fakeNamedMutexAPI) CreateOwned(name, sddl string) (win.Handle, bool, error) {
	a.name, a.sddl = name, sddl
	return a.handle, a.exists, nil
}
func (a *fakeNamedMutexAPI) Release(win.Handle) error { a.released = true; return nil }
func (a *fakeNamedMutexAPI) Close(win.Handle) error   { a.closed = true; return nil }
