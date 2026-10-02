//go:build windows

package windows

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	xwindows "golang.org/x/sys/windows"
)

// TestRestrictedTokenChildInitializationMatrix decides, from one CI log, why
// a restricted-tier child dies with STATUS_DLL_INIT_FAILED (0xC0000142) —
// the second Windows CI run's facade and policy-enforcement failures — and
// proves the production shape no longer does.
//
// It launches `cmd.exe /d /c exit 0` once per variant across the three axes
// that separate the candidate causes, each exactly as the restricted tier
// launches (CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP, resumed only after
// any Job assignment):
//
//   - token: this process's own; restricted WITHOUT the logon SID (the shape
//     the second CI run launched with); restricted through
//     CreateRestrictedToken (production: executor plus logon SID);
//   - console: CREATE_NO_WINDOW (a private console, so Windows starts a
//     console host for the child under the child's token) or
//     DETACHED_PROCESS (no console at all, so no console host);
//   - Job: none, or a sandboxed Job (UI restrictions), as internal/exec's
//     restricted tier uses.
//
// Reading the result: if only the logon-less CREATE_NO_WINDOW variants die
// 0xC0000142 the window-station/desktop theory (tokenLogonSID) is confirmed;
// if DETACHED_PROCESS survives where CREATE_NO_WINDOW dies, the casualty is
// the console host rather than the child's own user32; if the host-token
// variant in a sandboxed Job dies too, the Job's UI restrictions are a
// cause independent of the token. Only the production variants are
// required to succeed; every outcome is logged either way.
func TestRestrictedTokenChildInitializationMatrix(t *testing.T) {
	var source xwindows.Token
	if err := xwindows.OpenProcessToken(xwindows.CurrentProcess(), xwindows.TOKEN_DUPLICATE|xwindows.TOKEN_QUERY|xwindows.TOKEN_ASSIGN_PRIMARY, &source); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer source.Close()
	if restricted, err := source.IsRestricted(); err != nil || restricted {
		t.Fatalf("token prerequisite unavailable: current process token restricted=%v err=%v", restricted, err)
	}
	executor, err := ExecutorSID("spawn-matrix-installation", "spawn-matrix-executor")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("launch context: %s", describeSpawnContext(source))

	production, err := CreateRestrictedToken(source, []SID{executor})
	if err != nil {
		t.Fatalf("CreateRestrictedToken (production shape): %v", err)
	}
	defer production.Close()
	withoutLogon, err := restrictedTokenWithoutLogonSID(source, executor)
	if err != nil {
		t.Fatalf("issue logon-less restricted token: %v", err)
	}
	defer withoutLogon.Close()

	cmdExe := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	type variant struct {
		name     string
		token    xwindows.Token
		console  uint32
		job      bool
		required bool
	}
	variants := []variant{
		{"host token, CREATE_NO_WINDOW, sandboxed Job", 0, xwindows.CREATE_NO_WINDOW, true, false},
		{"restricted without logon SID, CREATE_NO_WINDOW, sandboxed Job", withoutLogon, xwindows.CREATE_NO_WINDOW, true, false},
		{"restricted without logon SID, DETACHED_PROCESS, sandboxed Job", withoutLogon, xwindows.DETACHED_PROCESS, true, false},
		{"restricted without logon SID, CREATE_NO_WINDOW, no Job", withoutLogon, xwindows.CREATE_NO_WINDOW, false, false},
		{"production (logon SID), CREATE_NO_WINDOW, sandboxed Job", production, xwindows.CREATE_NO_WINDOW, true, true},
		{"production (logon SID), DETACHED_PROCESS, sandboxed Job", production, xwindows.DETACHED_PROCESS, true, false},
		{"production (logon SID), CREATE_NO_WINDOW, no Job", production, xwindows.CREATE_NO_WINDOW, false, false},
	}
	var lines []string
	failedRequired := false
	for _, v := range variants {
		outcome, ok := runMatrixChild(cmdExe, []string{"/d", "/c", "exit 0"}, v.token, v.console, v.job)
		line := fmt.Sprintf("%s: %s", v.name, outcome)
		t.Log(line)
		lines = append(lines, line)
		if v.required && !ok {
			failedRequired = true
		}
	}
	if failedRequired {
		t.Fatalf("a production-shape restricted child did not exit 0; full matrix:\n  %s", strings.Join(lines, "\n  "))
	}
}

// restrictedTokenWithoutLogonSID is the restricted tier's token as the second
// Windows CI run issued it — dangerous groups deny-only, privileges removed,
// WRITE_RESTRICTED, and ONLY the executor as restricting SID — built through
// the same issueRestrictedToken call production uses, test-only, so the
// matrix can show what the logon SID changes.
func restrictedTokenWithoutLogonSID(source xwindows.Token, executor SID) (xwindows.Token, error) {
	executorSID, err := xwindows.StringToSid(executor.String())
	if err != nil {
		return 0, err
	}
	groups, err := source.GetTokenGroups()
	if err != nil {
		return 0, err
	}
	dangerous, err := dangerousGroupSIDs()
	if err != nil {
		return 0, err
	}
	var disabled []xwindows.SIDAndAttributes
	for _, sid := range dangerous {
		if groupIsEnabledForAllow(groups.AllGroups(), sid) {
			disabled = append(disabled, xwindows.SIDAndAttributes{Sid: sid})
		}
	}
	return issueRestrictedToken(win32RestrictedTokenCreator{}, source, tokenRestrictionWriteOnly, disabled, []xwindows.SIDAndAttributes{{Sid: executorSID}})
}

var matrixNtResumeProcess = xwindows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

// runMatrixChild launches path suspended with token (0: this process's own)
// and the console flag, optionally assigns it to a fresh sandboxed Job,
// resumes it, and reports its decoded exit (ok only for exit 0).
func runMatrixChild(path string, args []string, token xwindows.Token, console uint32, sandboxedJob bool) (string, bool) {
	cmd := exec.Command(path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:         syscall.Token(token),
		CreationFlags: xwindows.CREATE_SUSPENDED | xwindows.CREATE_NEW_PROCESS_GROUP | console,
	}
	var job *Job
	if sandboxedJob {
		var err error
		if job, err = NewJob(JobOptions{Sandboxed: true}); err != nil {
			return "Job setup failed: " + err.Error(), false
		}
		defer job.Close()
	}
	if err := cmd.Start(); err != nil {
		return "start failed: " + err.Error(), false
	}
	var setupErr error
	if err := cmd.Process.WithHandle(func(handle uintptr) {
		if job != nil {
			if err := job.Assign(xwindows.Handle(handle)); err != nil {
				setupErr = fmt.Errorf("assign to Job: %w", err)
				return
			}
		}
		if status, _, _ := matrixNtResumeProcess.Call(handle); status != 0 {
			setupErr = fmt.Errorf("NtResumeProcess: NTSTATUS %#x", uint32(status))
		}
	}); err != nil && setupErr == nil {
		setupErr = err
	}
	if setupErr != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return "launch setup failed: " + setupErr.Error(), false
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return "did not exit within 20s (killed)", false
	}
	code := uint32(cmd.ProcessState.ExitCode())
	if code == 0 {
		return "exit 0", true
	}
	name := ""
	switch code {
	case 0xC0000142:
		name = " STATUS_DLL_INIT_FAILED"
	case 0xC0000022:
		name = " STATUS_ACCESS_DENIED"
	case 0xC000013A:
		name = " STATUS_CONTROL_C_EXIT"
	}
	return fmt.Sprintf("exit %#x%s", code, name), false
}

var (
	matrixGetUserObjectInformationW = user32.NewProc("GetUserObjectInformationW")
	matrixGetThreadDesktop          = user32.NewProc("GetThreadDesktop")
)

// describeSpawnContext names what the logon-SID theory depends on: the
// session, this process's window station and desktop (WinSta0\Default for
// an interactive session; Service-0x0-…$ for a service), and the source
// token's logon SID.
func describeSpawnContext(source xwindows.Token) string {
	var parts []string
	var session uint32
	if err := xwindows.ProcessIdToSessionId(xwindows.GetCurrentProcessId(), &session); err != nil {
		parts = append(parts, "session: "+err.Error())
	} else {
		parts = append(parts, fmt.Sprintf("session %d", session))
	}
	station, _, _ := getProcessWindowStation.Call()
	parts = append(parts, "window station "+userObjectName(station))
	desktop, _, _ := matrixGetThreadDesktop.Call(uintptr(xwindows.GetCurrentThreadId()))
	parts = append(parts, "desktop "+userObjectName(desktop))
	if groups, err := source.GetTokenGroups(); err != nil {
		parts = append(parts, "token groups: "+err.Error())
	} else if logon, err := tokenLogonSID(groups.AllGroups()); err != nil {
		parts = append(parts, "logon SID: "+err.Error())
	} else {
		parts = append(parts, "logon SID "+logon.String())
	}
	return strings.Join(parts, ", ")
}

// userObjectName is GetUserObjectInformationW(handle, UOI_NAME).
func userObjectName(handle uintptr) string {
	if handle == 0 {
		return "<none>"
	}
	const uoiName = 2
	buffer := make([]uint16, 256)
	var needed uint32
	ok, _, err := matrixGetUserObjectInformationW.Call(handle, uoiName, uintptr(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)*2), uintptr(unsafe.Pointer(&needed)))
	if ok == 0 {
		return "<" + err.Error() + ">"
	}
	return xwindows.UTF16ToString(buffer)
}
