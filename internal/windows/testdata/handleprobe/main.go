//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	systemExtendedHandleInformation = 64
	objectTypeInformation           = 2
	statusInfoLengthMismatch        = 0xc0000004
)

var (
	ntdll                    = windows.NewLazySystemDLL("ntdll.dll")
	ntQuerySystemInformation = ntdll.NewProc("NtQuerySystemInformation")
	ntQueryObject            = ntdll.NewProc("NtQueryObject")
)

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

type unicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type reportedHandle struct {
	Value  uintptr `json:"value"`
	Type   string  `json:"type"`
	Access uint32  `json:"access"`
}

type report struct {
	Stdin   string           `json:"stdin"`
	Handles []reportedHandle `json:"handles"`
}

func main() {
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(err)
	}
	handles, err := enumerateHandles()
	if err != nil {
		fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(report{Stdin: string(stdin), Handles: handles}); err != nil {
		fatal(err)
	}
	if _, err := fmt.Fprintln(os.Stderr, "stderr-ok"); err != nil {
		fatal(err)
	}
}

func enumerateHandles() ([]reportedHandle, error) {
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
			size := int(needed) + 64<<10
			buffer = make([]byte, size)
			continue
		}
		if status != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation: NTSTATUS %#x", uint32(status))
		}
		break
	}

	count := *(*uintptr)(unsafe.Pointer(&buffer[0]))
	headerSize := 2 * unsafe.Sizeof(uintptr(0))
	entrySize := unsafe.Sizeof(systemHandleEntry{})
	pid := uintptr(os.Getpid())
	result := make([]reportedHandle, 0, 32)
	for i := uintptr(0); i < count; i++ {
		offset := headerSize + i*entrySize
		if offset+entrySize > uintptr(len(buffer)) {
			return nil, fmt.Errorf("truncated system handle table")
		}
		entry := *(*systemHandleEntry)(unsafe.Pointer(&buffer[offset]))
		if entry.UniqueProcessID != pid {
			continue
		}
		result = append(result, reportedHandle{
			Value:  entry.HandleValue,
			Type:   objectType(windows.Handle(entry.HandleValue)),
			Access: entry.GrantedAccess,
		})
	}
	return result, nil
}

func objectType(handle windows.Handle) string {
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
		return fmt.Sprintf("<NTSTATUS %#x>", uint32(status))
	}
	name := (*unicodeString)(unsafe.Pointer(&buffer[0]))
	if name.Buffer == nil || name.Length == 0 {
		return ""
	}
	return windows.UTF16PtrToString(name.Buffer)
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}
