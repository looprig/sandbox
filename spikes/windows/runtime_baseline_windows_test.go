//go:build windows

package windows_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	disableMaxPrivilege = 0x1
	luaToken            = 0x4
	runtimeTimeout      = 20 * time.Second
)

var (
	createRestrictedToken = windows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")
	ntResumeProcess       = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")
)

type runtimeCase struct {
	name          string
	path          string
	args          []string
	creationFlags uint32
	required      bool
}

type runtimeResult struct {
	Name            string   `json:"name"`
	Path            string   `json:"path"`
	Arguments       []string `json:"arguments"`
	RequestedAccess string   `json:"requested_access"`
	ObjectIdentity  string   `json:"object_identity"`
	Owner           string   `json:"owner"`
	DACL            string   `json:"dacl"`
	Status          string   `json:"status"`
	ExitCode        int      `json:"exit_code,omitempty"`
	Error           string   `json:"error,omitempty"`
	Output          string   `json:"output,omitempty"`
}

type limitedBuffer struct {
	mu        sync.Mutex
	data      []byte
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	const limit = 64 << 10
	remaining := limit - len(b.data)
	if remaining > 0 {
		if len(p) < remaining {
			remaining = len(p)
		}
		b.data = append(b.data, p[:remaining]...)
	}
	if remaining < len(p) {
		b.truncated = true
	}
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	result := string(b.data)
	if b.truncated {
		result += "\n[output truncated at 65536 bytes]"
	}
	return result
}

func TestRestrictedRuntimeBaseline(t *testing.T) {
	if testing.Short() {
		t.Fatal("restricted runtime baseline is a live gate; -short is not a passing result")
	}

	probe, aclDelta := buildRuntimeProbe(t)
	t.Logf("platform=%s", platformInventory(t))
	t.Logf("fixture_acl_delta=%s", aclDelta)

	token := newExactRestrictedToken(t)
	defer token.Close()
	t.Logf("exact_token=%s", tokenInventory(t, token))

	results := runRuntimeMatrix(t, token, probe)
	encoded, err := json.Marshal(results)
	if err != nil {
		t.Fatalf("encode runtime matrix: %v", err)
	}
	t.Logf("runtime_matrix=%s", encoded)

	var failures []string
	for _, result := range results {
		if result.Status == "FAIL" {
			failures = append(failures, result.Name)
		}
	}
	if len(failures) != 0 {
		t.Fatalf("exact Restricted Code token runtime failures: %s; inspect runtime_matrix diagnostics above", strings.Join(failures, ", "))
	}
}

func buildRuntimeProbe(t *testing.T) (string, string) {
	t.Helper()
	installRoot := filepath.Join(t.TempDir(), "installed-runner")
	if err := os.Mkdir(installRoot, 0o755); err != nil {
		t.Fatalf("create runner fixture directory: %v", err)
	}
	before := securityInventory(installRoot)
	grantRestrictedCodeReadExecute(t, installRoot)
	after := securityInventory(installRoot)

	probe := filepath.Join(installRoot, "runtimeprobe.exe")
	cmd := exec.Command("go", "build", "-trimpath", "-o", probe, "./spikes/windows/testdata/runtimeprobe")
	cmd.Dir = repositoryRoot(t)
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build installed-runner-shaped runtime probe: %v\n%s", err, output)
	}
	return probe, fmt.Sprintf("object=%q before={%s} after={%s}; only this test-owned fixture was changed", installRoot, before, after)
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not locate runtime baseline source")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(sourceFile), "..", ".."))
}

func grantRestrictedCodeReadExecute(t *testing.T, path string) {
	t.Helper()
	restrictedCode, err := windows.StringToSid("S-1-5-12")
	if err != nil {
		t.Fatalf("parse Restricted Code SID: %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read fixture DACL: %v", err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatalf("extract fixture DACL: %v", err)
	}
	entry := windows.EXPLICIT_ACCESS{
		AccessPermissions: windows.GENERIC_READ | windows.GENERIC_EXECUTE,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(restrictedCode),
		},
	}
	updated, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{entry}, dacl)
	if err != nil {
		t.Fatalf("build fixture DACL: %v", err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION, nil, nil, updated, nil); err != nil {
		t.Fatalf("grant Restricted Code RX on test-owned runner fixture: %v", err)
	}
}

func newExactRestrictedToken(t *testing.T) windows.Token {
	t.Helper()
	var base windows.Token
	access := uint32(windows.TOKEN_DUPLICATE | windows.TOKEN_ASSIGN_PRIMARY | windows.TOKEN_QUERY)
	if err := windows.OpenProcessToken(windows.CurrentProcess(), access, &base); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer base.Close()

	groups, err := base.GetTokenGroups()
	if err != nil {
		t.Fatalf("read process token groups: %v", err)
	}
	disable := make([]windows.SIDAndAttributes, 0, groups.GroupCount)
	for _, group := range groups.AllGroups() {
		// CreateRestrictedToken converts enabled groups to deny-only. Preserve
		// no ambient allow group; already-deny-only groups need not be repeated.
		if group.Attributes&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			disable = append(disable, windows.SIDAndAttributes{Sid: group.Sid})
		}
	}
	restrictedCode, err := windows.StringToSid("S-1-5-12")
	if err != nil {
		t.Fatalf("parse Restricted Code SID: %v", err)
	}
	restricting := []windows.SIDAndAttributes{{Sid: restrictedCode}}
	var disabledPtr, restrictingPtr uintptr
	if len(disable) != 0 {
		disabledPtr = uintptr(unsafe.Pointer(&disable[0]))
	}
	restrictingPtr = uintptr(unsafe.Pointer(&restricting[0]))

	var token windows.Token
	r1, _, callErr := createRestrictedToken.Call(
		uintptr(base),
		uintptr(disableMaxPrivilege|luaToken),
		uintptr(len(disable)), disabledPtr,
		0, 0,
		uintptr(len(restricting)), restrictingPtr,
		uintptr(unsafe.Pointer(&token)),
	)
	runtime.KeepAlive(disable)
	runtime.KeepAlive(restricting)
	if r1 == 0 {
		t.Fatalf("CreateRestrictedToken: %v", callErr)
	}

	restricted, err := token.IsRestricted()
	if err != nil {
		token.Close()
		t.Fatalf("IsTokenRestricted: %v", err)
	}
	if !restricted {
		token.Close()
		t.Fatal("CreateRestrictedToken returned a token Windows does not identify as restricted")
	}
	assertExactRestrictingList(t, token, restrictedCode)
	return token
}

func assertExactRestrictingList(t *testing.T, token windows.Token, want *windows.SID) {
	t.Helper()
	info := tokenInfo(t, token, windows.TokenRestrictedSids)
	groups := (*windows.Tokengroups)(unsafe.Pointer(&info[0])).AllGroups()
	if len(groups) != 1 || !windows.EqualSid(groups[0].Sid, want) {
		got := make([]string, 0, len(groups))
		for _, group := range groups {
			got = append(got, group.Sid.String())
		}
		token.Close()
		t.Fatalf("restricting SID list = %v, want exactly [S-1-5-12]", got)
	}
}

func runRuntimeMatrix(t *testing.T, token windows.Token, probe string) []runtimeResult {
	t.Helper()
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatalf("GetSystemDirectory: %v", err)
	}
	cases := []runtimeCase{
		{name: "installed-runner-go-helper", path: probe, args: []string{"smoke"}, required: true},
		{name: "go-subprocess", path: probe, args: []string{"subprocess"}, required: true},
		{name: "crt-and-dll-initializers", path: probe, args: []string{"dll-initializer"}, required: true},
		{name: "locale-and-console-startup", path: probe, args: []string{"locale-console"}, creationFlags: windows.CREATE_NEW_CONSOLE, required: true},
		{name: "tls-callback-fixture", path: probe, args: []string{"tls-callback"}, required: true},
		{name: "canonical-system32-cmd", path: filepath.Join(system32, "cmd.exe"), args: []string{"/D", "/S", "/C", "exit 0"}, required: true},
		{name: "windows-powershell", path: filepath.Join(system32, `WindowsPowerShell\v1.0\powershell.exe`), args: []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "exit 0"}, required: true},
	}
	cases = append(cases, discoverDocumentedRuntimes(t, probe)...)

	results := make([]runtimeResult, 0, len(cases))
	for _, testCase := range cases {
		result := runRuntimeCase(token, testCase)
		_, statErr := os.Stat(testCase.path)
		if !testCase.required && os.IsNotExist(statErr) {
			result.Status = "NOT_INSTALLED"
			result.Error = "runtime not present on this image"
		}
		results = append(results, result)
	}
	return results
}

func discoverDocumentedRuntimes(t *testing.T, probe string) []runtimeCase {
	t.Helper()
	// SPEC/design promise native programs, Go helpers, cmd, and PowerShell.
	// Python is named by the Windows conformance plan. The remaining entries
	// make the report exhaustive when common tool runtimes are installed; their
	// absence is inventory, never t.Skip and never a fabricated pass.
	candidates := []struct {
		name string
		exe  string
		args []string
	}{
		{"python", "python.exe", []string{"-c", "pass"}},
		{"python-launcher", "py.exe", []string{"-c", "pass"}},
		{"node", "node.exe", []string{"-e", "process.exit(0)"}},
		{"dotnet", "dotnet.exe", []string{"--info"}},
		{"java", "java.exe", []string{"-version"}},
		{"ruby", "ruby.exe", []string{"-e", "exit 0"}},
		{"perl", "perl.exe", []string{"-e", "exit 0"}},
		{"powershell-core", "pwsh.exe", []string{"-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "exit 0"}},
	}
	seen := map[string]bool{strings.ToLower(probe): true}
	var cases []runtimeCase
	for _, candidate := range candidates {
		path, err := exec.LookPath(candidate.exe)
		if err != nil {
			cases = append(cases, runtimeCase{name: candidate.name, path: candidate.exe, args: candidate.args})
			continue
		}
		path, err = filepath.Abs(path)
		if err != nil {
			t.Fatalf("absolute runtime path for %s: %v", candidate.exe, err)
		}
		key := strings.ToLower(path)
		if !seen[key] {
			seen[key] = true
			cases = append(cases, runtimeCase{name: candidate.name, path: path, args: candidate.args})
		}
	}
	return cases
}

func runRuntimeCase(token windows.Token, testCase runtimeCase) runtimeResult {
	result := runtimeResult{
		Name:            testCase.name,
		Path:            testCase.path,
		Arguments:       testCase.args,
		RequestedAccess: "FILE_EXECUTE|FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE (process image and loader startup)",
		Status:          "FAIL",
		ExitCode:        -1,
	}
	result.ObjectIdentity, result.Owner, result.DACL = objectSecurity(testCase.path)

	if _, err := os.Stat(testCase.path); err != nil {
		result.Error = err.Error()
		return result
	}
	ctx := context.Background()
	cmd := exec.CommandContext(ctx, testCase.path, testCase.args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Token:         syscall.Token(token),
		CreationFlags: testCase.creationFlags | windows.CREATE_SUSPENDED,
	}
	var output limitedBuffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	err, timedOut := runInRestrictedJob(cmd, runtimeTimeout)
	result.Output = strings.TrimSpace(output.String())
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if timedOut {
		result.Error = "external watchdog terminated process after " + runtimeTimeout.String()
		return result
	}
	if err != nil {
		result.Error = err.Error()
		return result
	}
	result.Status = "PASS"
	return result
}

func runInRestrictedJob(cmd *exec.Cmd, timeout time.Duration) (runErr error, timedOut bool) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("CreateJobObject: %w", err), false
	}
	defer windows.CloseHandle(job)
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return fmt.Errorf("configure watchdog Job: %w", err), false
	}
	if err := cmd.Start(); err != nil {
		return err, false
	}
	setupErr := cmd.Process.WithHandle(func(processHandle uintptr) {
		if err := windows.AssignProcessToJobObject(job, windows.Handle(processHandle)); err != nil {
			runErr = fmt.Errorf("assign process to watchdog Job: %w", err)
			return
		}
		status, _, callErr := ntResumeProcess.Call(processHandle)
		if status != 0 {
			runErr = fmt.Errorf("resume restricted process: NTSTATUS %#x: %v", status, callErr)
		}
	})
	if setupErr != nil && runErr == nil {
		runErr = fmt.Errorf("access restricted process handle: %w", setupErr)
	}
	if runErr != nil {
		_ = windows.TerminateJobObject(job, 1)
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return runErr, false
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err, false
	case <-timer.C:
		_ = windows.TerminateJobObject(job, 1)
		<-done
		return context.DeadlineExceeded, true
	}
}

func objectSecurity(path string) (identity, owner, dacl string) {
	identity = "unavailable"
	owner = "unavailable"
	dacl = "unavailable"
	p, err := windows.UTF16PtrFromString(path)
	if err == nil {
		h, openErr := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if openErr == nil {
			var info windows.ByHandleFileInformation
			if infoErr := windows.GetFileInformationByHandle(h, &info); infoErr == nil {
				identity = fmt.Sprintf("volume=%08x file=%08x%08x links=%d", info.VolumeSerialNumber, info.FileIndexHigh, info.FileIndexLow, info.NumberOfLinks)
			} else {
				identity = "error: " + infoErr.Error()
			}
			windows.CloseHandle(h)
		} else {
			identity = "error: " + openErr.Error()
		}
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return identity, "error: " + err.Error(), "error: " + err.Error()
	}
	if sid, _, ownerErr := sd.Owner(); ownerErr == nil {
		owner = sid.String()
	} else {
		owner = "error: " + ownerErr.Error()
	}
	dacl = sd.String()
	return identity, owner, dacl
}

func securityInventory(path string) string {
	identity, owner, dacl := objectSecurity(path)
	return fmt.Sprintf("identity=%s owner=%s dacl=%s", identity, owner, dacl)
}

func tokenInventory(t *testing.T, token windows.Token) string {
	t.Helper()
	type sidAttributes struct {
		SID        string `json:"sid"`
		Attributes string `json:"attributes"`
	}
	type privilege struct {
		LUID       string `json:"luid"`
		Attributes string `json:"attributes"`
	}
	record := struct {
		Groups          []sidAttributes `json:"groups"`
		Privileges      []privilege     `json:"privileges"`
		RestrictingSIDs []sidAttributes `json:"restricting_sids"`
		Integrity       string          `json:"integrity"`
	}{Integrity: "unavailable"}

	groups, err := token.GetTokenGroups()
	if err != nil {
		t.Fatalf("token groups: %v", err)
	}
	for _, group := range groups.AllGroups() {
		record.Groups = append(record.Groups, sidAttributes{group.Sid.String(), fmt.Sprintf("0x%08x", group.Attributes)})
	}
	sort.Slice(record.Groups, func(i, j int) bool { return record.Groups[i].SID < record.Groups[j].SID })

	restrictedInfo := tokenInfo(t, token, windows.TokenRestrictedSids)
	for _, group := range (*windows.Tokengroups)(unsafe.Pointer(&restrictedInfo[0])).AllGroups() {
		record.RestrictingSIDs = append(record.RestrictingSIDs, sidAttributes{group.Sid.String(), fmt.Sprintf("0x%08x", group.Attributes)})
	}
	privilegeInfo := tokenInfo(t, token, windows.TokenPrivileges)
	for _, p := range (*windows.Tokenprivileges)(unsafe.Pointer(&privilegeInfo[0])).AllPrivileges() {
		record.Privileges = append(record.Privileges, privilege{
			LUID:       fmt.Sprintf("%08x:%08x", uint32(p.Luid.HighPart), p.Luid.LowPart),
			Attributes: fmt.Sprintf("0x%08x", p.Attributes),
		})
	}
	integrityInfo := tokenInfo(t, token, windows.TokenIntegrityLevel)
	label := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&integrityInfo[0]))
	record.Integrity = label.Label.Sid.String()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("encode token inventory: %v", err)
	}
	return string(encoded)
}

func tokenInfo(t *testing.T, token windows.Token, class uint32) []byte {
	t.Helper()
	var needed uint32
	err := windows.GetTokenInformation(token, class, nil, 0, &needed)
	if err != nil && err != windows.ERROR_INSUFFICIENT_BUFFER {
		t.Fatalf("GetTokenInformation(%d) size: %v", class, err)
	}
	if needed == 0 {
		t.Fatalf("GetTokenInformation(%d) returned empty data", class)
	}
	buffer := make([]byte, needed)
	if err := windows.GetTokenInformation(token, class, &buffer[0], uint32(len(buffer)), &needed); err != nil {
		t.Fatalf("GetTokenInformation(%d): %v", class, err)
	}
	return buffer
}

func platformInventory(t *testing.T) string {
	t.Helper()
	version := windows.RtlGetVersion()
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatalf("GetSystemDirectory: %v", err)
	}
	root := filepath.VolumeName(system32) + `\`
	rootPtr, err := windows.UTF16PtrFromString(root)
	if err != nil {
		t.Fatalf("volume root: %v", err)
	}
	fsName := make([]uint16, windows.MAX_PATH+1)
	var serial, maxComponent, flags uint32
	if err := windows.GetVolumeInformation(rootPtr, nil, 0, &serial, &maxComponent, &flags, &fsName[0], uint32(len(fsName))); err != nil {
		t.Fatalf("GetVolumeInformation(%s): %v", root, err)
	}
	return fmt.Sprintf("windows=%d.%d build=%d service_pack=%q (%d.%d) arch=%s system_volume=%s serial=%08x filesystem=%s flags=%08x", version.MajorVersion, version.MinorVersion, version.BuildNumber, windows.UTF16ToString(version.CsdVersion[:]), version.ServicePackMajor, version.ServicePackMinor, runtime.GOARCH, root, serial, windows.UTF16ToString(fsName), flags)
}
