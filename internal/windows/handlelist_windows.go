//go:build windows

package windows

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"

	winapi "golang.org/x/sys/windows"
)

const objectBasicInformation = 0

var ntQueryObject = winapi.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryObject")

type objectBasicInfo struct {
	Attributes    uint32
	GrantedAccess uint32
	HandleCount   uint32
	PointerCount  uint32
	Reserved      [10]uint32
}

// ExplicitHandle describes a kernel handle deliberately shared with a child.
// Access is the exact access mask requested for the inheritable duplicate. The
// source handle is never made inheritable.
type ExplicitHandle struct {
	Handle winapi.Handle
	Access uint32
}

// ConfigureExplicitHandleList makes cmd use Go's Windows STARTUPINFOEX handle
// list path. Go 1.26's syscall.StartProcess duplicates the three ProcAttr.Files
// handles as inheritable child-side handles, appends AdditionalInheritedHandles,
// publishes exactly that slice through PROC_THREAD_ATTRIBUTE_HANDLE_LIST, and
// passes bInheritHandles=TRUE only when the resulting list is non-empty.
//
// Additional handles are accepted only through the declared slice. Each source is
// duplicated with the requested access and the inheritance bit required by the
// Windows attribute-list API. The returned cleanup must be called after Start
// has returned (calling it after Wait is also safe).
func ConfigureExplicitHandleList(cmd *exec.Cmd, declared []ExplicitHandle) (cleanup func(), err error) {
	if cmd == nil {
		return nil, errors.New("sandbox: configure Windows handle list: nil command")
	}
	if len(cmd.ExtraFiles) != 0 {
		return nil, errors.New("sandbox: configure Windows handle list: ExtraFiles are not supported")
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	if cmd.SysProcAttr.NoInheritHandles {
		return nil, errors.New("sandbox: configure Windows handle list: handle inheritance was disabled")
	}
	if len(cmd.SysProcAttr.AdditionalInheritedHandles) != 0 {
		return nil, errors.New("sandbox: configure Windows handle list: ambient inherited handles are forbidden")
	}
	if err := validateStandardHandles(cmd); err != nil {
		return nil, err
	}

	seen := make(map[winapi.Handle]struct{}, len(declared))
	duplicates := make([]winapi.Handle, 0, len(declared))
	closeDuplicates := func() {
		for _, handle := range duplicates {
			_ = winapi.CloseHandle(handle)
		}
		duplicates = nil
		cmd.SysProcAttr.AdditionalInheritedHandles = nil
	}
	defer func() {
		if err != nil {
			closeDuplicates()
		}
	}()

	process := winapi.CurrentProcess()
	for i, item := range declared {
		if invalidExplicitHandle(item.Handle) {
			return nil, fmt.Errorf("sandbox: configure Windows handle list: handle %d is null, invalid, or pseudo", i)
		}
		if item.Access == 0 {
			return nil, fmt.Errorf("sandbox: configure Windows handle list: handle %d has an empty access mask", i)
		}
		if _, ok := seen[item.Handle]; ok {
			return nil, fmt.Errorf("sandbox: configure Windows handle list: duplicate source handle at index %d", i)
		}
		seen[item.Handle] = struct{}{}
		granted, accessErr := handleGrantedAccess(item.Handle)
		if accessErr != nil {
			return nil, fmt.Errorf("sandbox: configure Windows handle list: inspect handle %d access: %w", i, accessErr)
		}
		if wider := item.Access &^ granted; wider != 0 {
			return nil, fmt.Errorf("sandbox: configure Windows handle list: handle %d requests wider access %#x (granted %#x)", i, wider, granted)
		}

		var duplicate winapi.Handle
		if duplicateErr := winapi.DuplicateHandle(
			process,
			item.Handle,
			process,
			&duplicate,
			item.Access,
			true,
			0,
		); duplicateErr != nil {
			return nil, fmt.Errorf("sandbox: configure Windows handle list: duplicate handle %d: %w", i, duplicateErr)
		}
		duplicates = append(duplicates, duplicate)
	}

	cmd.SysProcAttr.AdditionalInheritedHandles = make([]syscall.Handle, len(duplicates))
	for i, handle := range duplicates {
		cmd.SysProcAttr.AdditionalInheritedHandles[i] = syscall.Handle(handle)
	}
	return closeDuplicates, nil
}

func validateStandardHandles(cmd *exec.Cmd) error {
	// os/exec creates directional anonymous pipes for non-*os.File streams and
	// opens NUL read-only for a nil stdin. A supplied *os.File bypasses that
	// construction and is inherited directly, so inspect it before Start and
	// reject any access beyond the standard stream's directional minimum.
	streams := []struct {
		name     string
		value    any
		allowed  uint32
		required uint32
	}{
		{name: "stdin", value: cmd.Stdin, allowed: winapi.FILE_GENERIC_READ, required: winapi.FILE_READ_DATA},
		{name: "stdout", value: cmd.Stdout, allowed: winapi.FILE_GENERIC_WRITE, required: winapi.FILE_WRITE_DATA},
		{name: "stderr", value: cmd.Stderr, allowed: winapi.FILE_GENERIC_WRITE, required: winapi.FILE_WRITE_DATA},
	}
	for _, stream := range streams {
		file, ok := stream.value.(*os.File)
		if !ok || file == nil {
			continue
		}
		handle := winapi.Handle(file.Fd())
		if invalidExplicitHandle(handle) {
			return fmt.Errorf("sandbox: configure Windows handle list: %s has an invalid or pseudo handle", stream.name)
		}
		granted, err := handleGrantedAccess(handle)
		if err != nil {
			return fmt.Errorf("sandbox: configure Windows handle list: inspect %s access: %w", stream.name, err)
		}
		if granted&stream.required == 0 || granted&^stream.allowed != 0 {
			return fmt.Errorf("sandbox: configure Windows handle list: %s access %#x exceeds directional mask %#x", stream.name, granted, stream.allowed)
		}
	}
	return nil
}

func handleGrantedAccess(handle winapi.Handle) (uint32, error) {
	var info objectBasicInfo
	var needed uint32
	status, _, _ := ntQueryObject.Call(
		uintptr(handle),
		objectBasicInformation,
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		uintptr(unsafe.Pointer(&needed)),
	)
	if status != 0 {
		return 0, fmt.Errorf("NtQueryObject: NTSTATUS %#x", uint32(status))
	}
	return info.GrantedAccess, nil
}

func invalidExplicitHandle(handle winapi.Handle) bool {
	value := uintptr(handle)
	// Windows pseudo handles are small negative values (for example -1 for the
	// current process and -2 for the current thread). The uintptr expression is
	// correct on both 32-bit and 64-bit Windows.
	return value == 0 || value >= ^uintptr(0)-15
}
