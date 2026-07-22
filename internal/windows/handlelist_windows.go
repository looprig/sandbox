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

const (
	objectTypeInformation = 2
	standardInputAccess   = winapi.FILE_READ_DATA | winapi.SYNCHRONIZE
	standardOutputAccess  = winapi.FILE_WRITE_DATA | winapi.SYNCHRONIZE
)

var ntQueryObject = winapi.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryObject")

type objectBasicInfo struct {
	Attributes    uint32
	GrantedAccess uint32
	HandleCount   uint32
	PointerCount  uint32
	Reserved      [10]uint32
}

type objectTypeUnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
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
	standardCleanup, err := narrowStandardHandles(cmd)
	if err != nil {
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
		standardCleanup()
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

func narrowStandardHandles(cmd *exec.Cmd) (func(), error) {
	// os/exec creates directional anonymous pipes for non-*os.File streams and
	// opens NUL read-only for a nil stdin. A supplied *os.File bypasses that
	// construction and is inherited directly, so classify its kernel object and
	// replace it with an executor-owned least-access duplicate before Start.
	streams := []struct {
		name   string
		value  any
		access uint32
	}{
		{name: "stdin", value: cmd.Stdin, access: standardInputAccess},
		{name: "stdout", value: cmd.Stdout, access: standardOutputAccess},
		{name: "stderr", value: cmd.Stderr, access: standardOutputAccess},
	}
	type replacement struct {
		name string
		file *os.File
	}
	replacements := make([]replacement, 0, len(streams))
	closeReplacements := func() {
		for _, replacement := range replacements {
			_ = replacement.file.Close()
		}
		replacements = nil
	}
	for _, stream := range streams {
		file, ok := stream.value.(*os.File)
		if !ok || file == nil {
			continue
		}
		handle := winapi.Handle(file.Fd())
		if err := validateStandardHandleObject(stream.name, handle); err != nil {
			closeReplacements()
			return nil, err
		}
		granted, err := handleGrantedAccess(handle)
		if err != nil {
			closeReplacements()
			return nil, fmt.Errorf("sandbox: configure Windows handle list: inspect %s access: %w", stream.name, err)
		}
		if missing := stream.access &^ granted; missing != 0 {
			closeReplacements()
			return nil, fmt.Errorf("sandbox: configure Windows handle list: %s lacks required access %#x (granted %#x)", stream.name, missing, granted)
		}
		var duplicate winapi.Handle
		// Keep the parent-side wrapper non-inheritable. syscall.StartProcess
		// creates its own inheritable ProcAttr.Files duplicate immediately before
		// publishing that transient handle through HANDLE_LIST.
		if err := winapi.DuplicateHandle(winapi.CurrentProcess(), handle, winapi.CurrentProcess(), &duplicate, stream.access, false, 0); err != nil {
			closeReplacements()
			return nil, fmt.Errorf("sandbox: configure Windows handle list: narrow %s: %w", stream.name, err)
		}
		owned := os.NewFile(uintptr(duplicate), "sandbox-"+stream.name)
		if owned == nil {
			_ = winapi.CloseHandle(duplicate)
			closeReplacements()
			return nil, fmt.Errorf("sandbox: configure Windows handle list: wrap narrow %s", stream.name)
		}
		replacements = append(replacements, replacement{name: stream.name, file: owned})
	}
	for _, replacement := range replacements {
		switch replacement.name {
		case "stdin":
			cmd.Stdin = replacement.file
		case "stdout":
			cmd.Stdout = replacement.file
		case "stderr":
			cmd.Stderr = replacement.file
		}
	}
	return closeReplacements, nil
}

func validateStandardHandleObject(name string, handle winapi.Handle) error {
	if invalidExplicitHandle(handle) {
		return fmt.Errorf("sandbox: configure Windows handle list: %s has an invalid or pseudo handle", name)
	}
	typeName, err := handleObjectType(handle)
	if err != nil {
		return fmt.Errorf("sandbox: configure Windows handle list: inspect %s object type: %w", name, err)
	}
	if typeName != "File" {
		return fmt.Errorf("sandbox: configure Windows handle list: %s object type %q is not stream-capable File", name, typeName)
	}
	fileType, err := winapi.GetFileType(handle)
	if err != nil {
		return fmt.Errorf("sandbox: configure Windows handle list: inspect %s file type: %w", name, err)
	}
	switch fileType &^ winapi.FILE_TYPE_REMOTE {
	case winapi.FILE_TYPE_PIPE:
		return nil
	case winapi.FILE_TYPE_DISK:
		var info winapi.ByHandleFileInformation
		if err := winapi.GetFileInformationByHandle(handle, &info); err != nil {
			return fmt.Errorf("sandbox: configure Windows handle list: inspect %s disk object: %w", name, err)
		}
		if info.FileAttributes&winapi.FILE_ATTRIBUTE_DIRECTORY != 0 {
			return fmt.Errorf("sandbox: configure Windows handle list: %s directory handles are not supported", name)
		}
		return nil
	case winapi.FILE_TYPE_CHAR:
		var mode uint32
		if err := winapi.GetConsoleMode(handle, &mode); err == nil {
			return fmt.Errorf("sandbox: configure Windows handle list: %s console handles are not supported by least-access launch", name)
		}
		return fmt.Errorf("sandbox: configure Windows handle list: %s character devices are not supported", name)
	default:
		return fmt.Errorf("sandbox: configure Windows handle list: %s file type %#x is not supported", name, fileType)
	}
}

func handleObjectType(handle winapi.Handle) (string, error) {
	buffer := make([]byte, 4<<10)
	var needed uint32
	status, _, _ := ntQueryObject.Call(
		uintptr(handle),
		objectTypeInformation,
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&needed)),
	)
	if status != 0 {
		return "", fmt.Errorf("NtQueryObject: NTSTATUS %#x", uint32(status))
	}
	name := (*objectTypeUnicodeString)(unsafe.Pointer(&buffer[0]))
	if name.Buffer == nil || name.Length == 0 {
		return "", errors.New("NtQueryObject returned an empty object type")
	}
	return winapi.UTF16ToString(unsafe.Slice(name.Buffer, int(name.Length/2))), nil
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
