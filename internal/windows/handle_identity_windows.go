//go:build windows

package windows

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	winapi "golang.org/x/sys/windows"
)

const (
	systemExtendedHandleInformation = 64
	statusInfoLengthMismatch        = 0xc0000004
)

var ntQuerySystemInformation = winapi.NewLazySystemDLL("ntdll.dll").NewProc("NtQuerySystemInformation")

type systemHandleEntry struct {
	Object                uintptr
	UniqueProcessID       uintptr
	HandleValue           uintptr
	GrantedAccess         uint32
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       uint16
	HandleAttributes      uint32
	Reserved              uint32
}

// HandleObjectIdentity is a process-local handle value bound to its underlying
// kernel object and authority. Its fields stay private so callers can use the
// identity only to request and verify a specific candidate handle.
type HandleObjectIdentity struct {
	value  uintptr
	object uintptr
}

// CaptureHandleObjectIdentity captures a handle's kernel-object identity and
// granted authority from the current process.
func CaptureHandleObjectIdentity(handle winapi.Handle) (HandleObjectIdentity, error) {
	if invalidExplicitHandle(handle) {
		return HandleObjectIdentity{}, errors.New("sandbox: capture handle identity: invalid or pseudo handle")
	}
	object, err := currentProcessHandleObject(handle)
	if err != nil {
		return HandleObjectIdentity{}, fmt.Errorf("sandbox: capture handle identity object: %w", err)
	}
	return HandleObjectIdentity{value: uintptr(handle), object: object}, nil
}

// Value returns the process-local handle value to ask a child probe to inspect.
func (identity HandleObjectIdentity) Value() uintptr { return identity.value }

// CompareCandidate distinguishes inheritance of the captured kernel object
// from reuse of its process-local handle value. A zero object identity for the
// candidate is inconclusive and must not be treated as proof of exclusion.
func (identity HandleObjectIdentity) CompareCandidate(value, object uintptr) (sameObject, conclusive bool) {
	if identity.value == 0 || identity.object == 0 || value != identity.value {
		return false, value != identity.value
	}
	if object == 0 {
		return false, false
	}
	return object == identity.object, true
}

func currentProcessHandleObject(handle winapi.Handle) (uintptr, error) {
	buffer := make([]byte, 64<<10)
	for {
		var needed uint32
		status, _, _ := ntQuerySystemInformation.Call(
			systemExtendedHandleInformation,
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			uintptr(unsafe.Pointer(&needed)),
		)
		if uint32(status) == statusInfoLengthMismatch {
			buffer = make([]byte, int(needed)+(64<<10))
			continue
		}
		if status != 0 {
			return 0, fmt.Errorf("NtQuerySystemInformation: NTSTATUS %#x", uint32(status))
		}
		break
	}

	count := *(*uintptr)(unsafe.Pointer(&buffer[0]))
	headerSize := 2 * unsafe.Sizeof(uintptr(0))
	entrySize := unsafe.Sizeof(systemHandleEntry{})
	pid := uintptr(os.Getpid())
	for i := uintptr(0); i < count; i++ {
		offset := headerSize + i*entrySize
		if offset+entrySize > uintptr(len(buffer)) {
			return 0, errors.New("truncated system handle table")
		}
		entry := *(*systemHandleEntry)(unsafe.Pointer(&buffer[offset]))
		if entry.UniqueProcessID == pid && entry.HandleValue == uintptr(handle) {
			if entry.Object == 0 {
				return 0, errors.New("system handle table returned an empty object identity")
			}
			return entry.Object, nil
		}
	}
	return 0, fmt.Errorf("handle %#x absent from system handle table", uintptr(handle))
}
