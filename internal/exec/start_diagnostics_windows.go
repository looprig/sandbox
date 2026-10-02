//go:build windows

package exec

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// This file makes a failed Windows launch diagnosable from a CI log alone.
// The first Windows CI run's only evidence for a restricted-tier launch
// failure was `fork/exec <test binary>: Access is denied.` — enough to know
// CreateProcessAsUser returned ERROR_ACCESS_DENIED, not enough to know
// whether the TOKEN handle lacked an access right, the image's DACL refused
// the launch identity, or something else did. describeWindowsStartFailure
// wraps every launch error (the plain cmd.Start path and the raw ConPTY
// CreateProcess path) with: the API, the image and working directory, the
// GetLastError value, the launch token's granted access and the rights
// CreateProcessAsUser requires of it, and — for ERROR_ACCESS_DENIED only —
// the image's owner/DACL plus an open of the image performed while
// impersonating the launch token. Each piece is best effort: a diagnostic
// step that itself fails says so in the text and never replaces err, which
// stays reachable through errors.Is/As.

// createProcessAsUserTokenAccess is what CreateProcessAsUser documents its
// hToken must grant: TOKEN_QUERY, TOKEN_DUPLICATE and TOKEN_ASSIGN_PRIMARY.
const createProcessAsUserTokenAccess = windows.TOKEN_QUERY | windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY

func describeWindowsStartFailure(cmd *exec.Cmd, image string, err error) error {
	if err == nil {
		return nil
	}
	var token syscall.Token
	if cmd != nil && cmd.SysProcAttr != nil {
		token = cmd.SysProcAttr.Token
	}
	api := "CreateProcess"
	if token != 0 {
		api = "CreateProcessAsUser"
	}
	dir := ""
	if cmd != nil {
		dir = cmd.Dir
	}
	parts := []string{fmt.Sprintf("%s image %q dir %q", api, image, dir)}
	var errno syscall.Errno
	if errors.As(err, &errno) {
		parts = append(parts, fmt.Sprintf("GetLastError %d (%#x)", uint32(errno), uint32(errno)))
	}
	if token != 0 {
		parts = append(parts, describeLaunchToken(windows.Token(token)))
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) && image != "" {
		parts = append(parts, describeImageSecurity(image))
		if token != 0 {
			parts = append(parts, probeImageOpenAsToken(image, windows.Token(token)))
		}
	}
	return fmt.Errorf("sandbox: start process (%s): %w", strings.Join(parts, "; "), err)
}

var ntQueryObjectForDiagnostics = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtQueryObject")

// objectBasicInformationForDiagnostics mirrors OBJECT_BASIC_INFORMATION.
type objectBasicInformationForDiagnostics struct {
	Attributes    uint32
	GrantedAccess uint32
	HandleCount   uint32
	PointerCount  uint32
	Reserved      [10]uint32
}

// handleGrantedAccessForDiagnostics reads a handle's granted access mask
// (NtQueryObject, ObjectBasicInformation).
func handleGrantedAccessForDiagnostics(handle windows.Handle) (uint32, error) {
	var info objectBasicInformationForDiagnostics
	var needed uint32
	status, _, _ := ntQueryObjectForDiagnostics.Call(
		uintptr(handle),
		0, // ObjectBasicInformation
		uintptr(unsafe.Pointer(&info)),
		unsafe.Sizeof(info),
		uintptr(unsafe.Pointer(&needed)),
	)
	if status != 0 {
		return 0, fmt.Errorf("NtQueryObject: NTSTATUS %#x", uint32(status))
	}
	return info.GrantedAccess, nil
}

func describeLaunchToken(token windows.Token) string {
	granted, err := handleGrantedAccessForDiagnostics(windows.Handle(token))
	if err != nil {
		return fmt.Sprintf("launch token access unknown (%v)", err)
	}
	text := fmt.Sprintf("launch token handle access %#x", granted)
	if missing := uint32(createProcessAsUserTokenAccess) &^ granted; missing != 0 {
		text += fmt.Sprintf(" MISSING %#x of the %#x CreateProcessAsUser requires", missing, uint32(createProcessAsUserTokenAccess))
	}
	if restricted, restrictedErr := token.IsRestricted(); restrictedErr == nil {
		text += fmt.Sprintf(", restricted=%v", restricted)
	}
	return text
}

// describeImageSecurity reports the image's owner and DACL as SDDL, which is
// what decides whether a launch identity that is not an administrator (the
// restricted tier disables Administrators to deny-only) may read and execute
// it.
func describeImageSecurity(image string) string {
	sd, err := windows.GetNamedSecurityInfo(image, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Sprintf("image security unreadable (%v)", err)
	}
	return "image security " + sd.String()
}

// probeImageOpenAsToken opens image for GENERIC_READ|GENERIC_EXECUTE while
// impersonating an impersonation duplicate of the launch token — the same
// identity the kernel checks when it maps the image for the new process —
// so the log says whether the image's DACL alone refuses that identity. The
// impersonation runs on a locked OS thread; if RevertToSelf fails the thread
// is deliberately left locked so the runtime retires it with the goroutine
// instead of reusing a thread that still carries the launch token.
func probeImageOpenAsToken(image string, token windows.Token) string {
	path, err := windows.UTF16PtrFromString(image)
	if err != nil {
		return fmt.Sprintf("image open probe skipped (%v)", err)
	}
	var impersonation windows.Token
	if err := windows.DuplicateTokenEx(token, windows.TOKEN_IMPERSONATE|windows.TOKEN_QUERY, nil,
		windows.SecurityImpersonation, windows.TokenImpersonation, &impersonation); err != nil {
		return fmt.Sprintf("image open probe skipped: duplicate launch token for impersonation: %v", err)
	}
	defer impersonation.Close()
	result := make(chan string, 1)
	go func() {
		runtime.LockOSThread()
		if err := windows.SetThreadToken(nil, impersonation); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Sprintf("image open probe skipped: impersonate launch token: %v", err)
			return
		}
		handle, openErr := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_EXECUTE,
			windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, 0, 0)
		if openErr == nil {
			_ = windows.CloseHandle(handle)
		}
		if err := windows.RevertToSelf(); err != nil {
			result <- fmt.Sprintf("image open as launch token: %v (RevertToSelf failed: %v; thread retired)", openErr, err)
			return
		}
		runtime.UnlockOSThread()
		if openErr != nil {
			result <- fmt.Sprintf("image open as launch token REFUSED: %v", openErr)
			return
		}
		result <- "image open as launch token succeeded"
	}()
	return <-result
}

// windowsExitStatusName names the NTSTATUS values a Windows child reports as
// its exit code when it dies before its own code runs (loader and DLL
// initialisation failures, mostly) or is killed by the system. A console
// client that cannot attach to its console fails kernelbase's initialisation
// with STATUS_DLL_INIT_FAILED, which is why the ConPTY tests decode it. An
// exit code outside the NTSTATUS error range, or one not listed, returns "".
func windowsExitStatusName(code int) string {
	switch uint32(code) {
	case 0xC0000005:
		return "STATUS_ACCESS_VIOLATION"
	case 0xC0000022:
		return "STATUS_ACCESS_DENIED"
	case 0xC0000135:
		return "STATUS_DLL_NOT_FOUND"
	case 0xC0000139:
		return "STATUS_ENTRYPOINT_NOT_FOUND"
	case 0xC000013A:
		return "STATUS_CONTROL_C_EXIT"
	case 0xC0000142:
		// Two causes this package has met, distinguishable by launch shape:
		// a ConPTY client handed a malformed pseudo-console attribute (fixed
		// in attachPseudoConsoleAttribute), and a restricted-token child whose
		// WRITE_RESTRICTED restricting list lacks the session logon SID, so
		// user32/console-host initialisation cannot open WinSta0\Default for
		// write-class rights (fixed by tokenLogonSID, internal/windows).
		return "STATUS_DLL_INIT_FAILED (a DLL initialisation routine failed; for a console client, usually the console connection; " +
			"under a restricted token, usually the window station/desktop (WinSta0\\Default) refusing the restricting SIDs' write check — is the session logon SID among them?)"
	case 0xC0000409:
		return "STATUS_STACK_BUFFER_OVERRUN"
	case 0xC000041D:
		return "STATUS_FATAL_USER_CALLBACK_EXCEPTION"
	case 0xC0000417:
		return "STATUS_INVALID_CRUNTIME_PARAMETER"
	}
	if uint32(code)&0xC0000000 == 0xC0000000 {
		return "unlisted NTSTATUS error"
	}
	return ""
}

// describeExitCode renders a child exit code with its NTSTATUS name, when it
// has one, for test failure messages and launch diagnostics.
func describeExitCode(code int) string {
	if name := windowsExitStatusName(code); name != "" {
		return fmt.Sprintf("%d (%#x %s)", code, uint32(code), name)
	}
	return fmt.Sprintf("%d", code)
}
