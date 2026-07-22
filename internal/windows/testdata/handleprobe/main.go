//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"unsafe"

	winlaunch "github.com/looprig/sandbox/internal/windows"
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
	Object uintptr `json:"object,omitempty"`
}

type report struct {
	Stdin    string             `json:"stdin"`
	Standard map[string]uintptr `json:"standard"`
	Handles  []reportedHandle   `json:"handles"`
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "runner" {
		runRunner()
		return
	}
	requestedObjects, err := requestedObjectHandles(os.Args[1:])
	if err != nil {
		fatal(err)
	}
	runTarget(requestedObjects)
}

func requestedObjectHandles(args []string) (map[uintptr]struct{}, error) {
	if len(args) == 0 || args[0] == "target" {
		return nil, nil
	}
	if args[0] != "objects" {
		return nil, fmt.Errorf("unknown mode %q", args[0])
	}
	requested := make(map[uintptr]struct{}, len(args)-1)
	for _, value := range args[1:] {
		handle, err := strconv.ParseUint(value, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("parse requested handle %q: %w", value, err)
		}
		requested[uintptr(handle)] = struct{}{}
	}
	return requested, nil
}

func runTarget(requestedObjects map[uintptr]struct{}) {
	stdin, err := io.ReadAll(os.Stdin)
	if err != nil {
		fatal(err)
	}
	handles, err := enumerateHandles(requestedObjects)
	if err != nil {
		fatal(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(report{
		Stdin: string(stdin),
		Standard: map[string]uintptr{
			"stdin":  os.Stdin.Fd(),
			"stdout": os.Stdout.Fd(),
			"stderr": os.Stderr.Fd(),
		},
		Handles: handles,
	}); err != nil {
		fatal(err)
	}
	if _, err := fmt.Fprintln(os.Stderr, "stderr-ok"); err != nil {
		fatal(err)
	}
}

func runRunner() {
	if len(os.Args) != 3 {
		fatal(fmt.Errorf("runner requires request handle"))
	}
	value, err := strconv.ParseUint(os.Args[2], 16, 64)
	if err != nil {
		fatal(fmt.Errorf("parse request handle: %w", err))
	}
	requestHandle := windows.Handle(uintptr(value))
	request := os.NewFile(uintptr(requestHandle), "sealed-request")
	if request == nil {
		fatal(fmt.Errorf("open inherited request handle"))
	}
	defer request.Close()
	marker := []byte{0}
	if _, err := io.ReadFull(request, marker); err != nil || marker[0] != 0x7f {
		fatal(fmt.Errorf("read inherited request marker: value=%#x err=%v", marker[0], err))
	}
	if err := windows.SetHandleInformation(requestHandle, windows.HANDLE_FLAG_INHERIT, 0); err != nil {
		fatal(fmt.Errorf("clear request inheritance: %w", err))
	}

	// Ask the target to report kernel-object identity only for the runner's
	// request-handle value. If Windows reuses that numeric value after the
	// request is excluded, the parent can distinguish the unrelated object.
	cmd := exec.Command(os.Args[0], "objects", os.Args[2])
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cleanup, err := winlaunch.ConfigureExplicitHandleList(cmd, nil)
	if err != nil {
		fatal(err)
	}
	defer cleanup()
	if err := cmd.Run(); err != nil {
		fatal(fmt.Errorf("run target: %w", err))
	}
}

func enumerateHandles(requestedObjects map[uintptr]struct{}) ([]reportedHandle, error) {
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
		reported := reportedHandle{
			Value:  entry.HandleValue,
			Type:   objectType(windows.Handle(entry.HandleValue)),
			Access: entry.GrantedAccess,
		}
		if _, requested := requestedObjects[entry.HandleValue]; requested {
			reported.Object = entry.Object
		}
		result = append(result, reported)
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
