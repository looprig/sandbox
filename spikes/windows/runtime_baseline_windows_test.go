//go:build windows

package windows_test

import (
	"context"
	"encoding/json"
	"errors"
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

	"github.com/looprig/sandbox/spikes/windows/internal/baseline"
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
	name           string
	path           string
	args           []string
	creationFlags  uint32
	required       bool
	expectedOutput string
	lookupEvidence []string
}

type runtimeResult struct {
	Name             string   `json:"name"`
	Path             string   `json:"path"`
	Arguments        []string `json:"arguments"`
	RequestedAccess  string   `json:"image_startup_access_estimate"`
	ObjectIdentity   string   `json:"object_identity"`
	Owner            string   `json:"owner"`
	DACL             string   `json:"dacl"`
	Status           string   `json:"status"`
	ExitCode         int      `json:"exit_code,omitempty"`
	Error            string   `json:"error,omitempty"`
	Output           string   `json:"output,omitempty"`
	PID              int      `json:"pid,omitempty"`
	ExecutableSHA256 string   `json:"executable_sha256"`
	FailureKind      string   `json:"failure_kind,omitempty"`
	CallerPID        int      `json:"caller_pid,omitempty"`
	AttemptID        string   `json:"attempt_id,omitempty"`
	LookupEvidence   []string `json:"lookup_evidence,omitempty"`
	Win32Error       string   `json:"win32_error,omitempty"`
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
	startedUTC := time.Now().UTC()
	if testing.Short() {
		t.Fatal("restricted runtime baseline is a live gate; -short is not a passing result")
	}

	probe, tlsFixture, aclDelta := buildRuntimeFixtures(t)
	platformText, platform := platformInventory(t)
	t.Logf("platform=%s", platformText)
	t.Logf("fixture_acl_delta=%s", aclDelta)

	token := newExactRestrictedToken(t)
	defer token.Close()
	tokenText := tokenInventory(t, token)
	t.Logf("exact_token=%s", tokenText)

	results := runRuntimeMatrix(t, token, probe, tlsFixture)
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
	manifest := createRunManifest(t, platform, tokenText, encoded, results, len(failures) == 0, startedUTC, time.Now().UTC())
	writeInvocationManifest(t, manifest)
	if len(failures) != 0 {
		t.Fatalf("exact Restricted Code token runtime failures: %s; exact_token_gate_passed=false failure_selection_evidence_complete=false; finalize and validate evidence from this same nonce/PID invocation without rerunning", strings.Join(failures, ", "))
	}
	t.Log("exact_token_gate_passed=true failure_selection_evidence_complete=false")
}

func TestFinalizeRestrictedRuntimeRunManifest(t *testing.T) {
	manifest := mustLoadRunManifestEnv(t, "LOOPRIG_RUNTIME_INVOCATION_MANIFEST")
	collector := baseline.TraceCollector{Name: mustEnv(t, "LOOPRIG_RUNTIME_COLLECTOR_NAME"), Version: mustEnv(t, "LOOPRIG_RUNTIME_COLLECTOR_VERSION"), Command: mustEnv(t, "LOOPRIG_RUNTIME_COLLECTOR_COMMAND")}
	finalized, err := baseline.FinalizeRunManifest(manifest, collector, mustEnv(t, "LOOPRIG_RUNTIME_RAW_TRACE"))
	if err != nil {
		t.Fatal(err)
	}
	writeJSONFile(t, mustEnv(t, "LOOPRIG_RUNTIME_FINAL_MANIFEST_OUT"), finalized)
}

func TestValidateRestrictedRuntimeTraceEvidence(t *testing.T) {
	manifest := mustLoadRunManifestEnv(t, "LOOPRIG_RUNTIME_FINAL_MANIFEST")
	evidence, err := baseline.LoadTraceEvidence(mustEnv(t, "LOOPRIG_RUNTIME_TRACE_JSON"))
	if err != nil {
		t.Fatal(err)
	}
	if err := baseline.ValidateFailureTrace(manifest, evidence); err != nil {
		t.Fatalf("exact_token_gate_passed=false failure_selection_evidence_complete=false: %v", err)
	}
	t.Log("exact_token_gate_passed=false failure_selection_evidence_complete=true")
}

func createRunManifest(t *testing.T, platform baseline.RunPlatform, tokenText string, matrix []byte, results []runtimeResult, passed bool, started, finished time.Time) baseline.RunManifest {
	t.Helper()
	nonce := os.Getenv("LOOPRIG_RUNTIME_RUN_NONCE")
	if os.Getenv("LOOPRIG_RUNTIME_RUN_MANIFEST_OUT") != "" && nonce == "" {
		t.Fatal("LOOPRIG_RUNTIME_RUN_NONCE is required when emitting a traced invocation manifest")
	}
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repositoryRoot(t)
	revision, err := cmd.Output()
	if err != nil {
		t.Fatalf("source revision: %v", err)
	}
	manifest := baseline.RunManifest{SchemaVersion: 3, RunNonce: nonce, SourceRevision: strings.TrimSpace(string(revision)), Platform: platform, TokenInventorySHA256: baseline.SHA256Hex([]byte(tokenText)), RuntimeManifestSHA256: baseline.RuntimeManifestDigest(), MatrixSHA256: baseline.SHA256Hex(matrix), ExactTokenGatePassed: passed, StartedUTC: started.Format(time.RFC3339Nano), FinishedUTC: finished.Format(time.RFC3339Nano)}
	for _, result := range results {
		manifest.Runtimes = append(manifest.Runtimes, baseline.RuntimeExecution{Name: result.Name, ExecutablePath: result.Path, ObjectIdentity: result.ObjectIdentity, ExecutableSHA256: result.ExecutableSHA256, PID: result.PID, Status: result.Status, ExitCode: result.ExitCode, Diagnostic: result.Error, FailureKind: result.FailureKind, CallerPID: result.CallerPID, AttemptID: result.AttemptID, LookupEvidence: result.LookupEvidence, Win32Error: result.Win32Error})
	}
	return manifest
}

func writeInvocationManifest(t *testing.T, manifest baseline.RunManifest) {
	t.Helper()
	if path := os.Getenv("LOOPRIG_RUNTIME_RUN_MANIFEST_OUT"); path != "" {
		writeJSONFile(t, path, manifest)
		t.Logf("run_manifest=%s run_nonce=%s", path, manifest.RunNonce)
	}
}
func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
}
func mustEnv(t *testing.T, name string) string {
	t.Helper()
	value := os.Getenv(name)
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}
func mustLoadRunManifestEnv(t *testing.T, name string) baseline.RunManifest {
	t.Helper()
	manifest, err := baseline.LoadRunManifest(mustEnv(t, name))
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func buildRuntimeFixtures(t *testing.T) (string, string, string) {
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
	tlsImage, err := baseline.GenerateTLSFixture(runtime.GOARCH)
	if err != nil {
		t.Fatalf("generate PE TLS callback fixture: %v", err)
	}
	tlsFixture := filepath.Join(installRoot, "tlsfixture.exe")
	if err := os.WriteFile(tlsFixture, tlsImage, 0o755); err != nil {
		t.Fatalf("write PE TLS callback fixture: %v", err)
	}
	return probe, tlsFixture, fmt.Sprintf("object=%q before={%s} after={%s}; only this test-owned fixture was changed", installRoot, before, after)
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
	assertExactTokenShape(t, base, token)
	return token
}

func assertExactTokenShape(t *testing.T, source, restricted windows.Token) {
	t.Helper()
	for _, token := range []windows.Token{source, restricted} {
		info := tokenInfo(t, token, windows.TokenType)
		if *(*uint32)(unsafe.Pointer(&info[0])) != windows.TokenPrimary {
			t.Fatal("runtime baseline token is not primary")
		}
	}
	sourceIntegrityInfo := tokenInfo(t, source, windows.TokenIntegrityLevel)
	restrictedIntegrityInfo := tokenInfo(t, restricted, windows.TokenIntegrityLevel)
	sourceIntegrity := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&sourceIntegrityInfo[0])).Label.Sid
	restrictedIntegrity := (*windows.Tokenmandatorylabel)(unsafe.Pointer(&restrictedIntegrityInfo[0])).Label.Sid
	if !windows.EqualSid(sourceIntegrity, restrictedIntegrity) {
		t.Fatal("CreateRestrictedToken changed integrity")
	}
	sourceGroups, _ := source.GetTokenGroups()
	restrictedGroups, _ := restricted.GetTokenGroups()
	groupAttrs := map[string]uint32{}
	for _, g := range restrictedGroups.AllGroups() {
		groupAttrs[g.Sid.String()] = g.Attributes
	}
	for _, g := range sourceGroups.AllGroups() {
		if g.Attributes&windows.SE_GROUP_ENABLED != 0 && groupAttrs[g.Sid.String()]&windows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			t.Fatalf("enabled source group %s was not made deny-only", g.Sid)
		}
	}
	sourcePrivInfo := tokenInfo(t, source, windows.TokenPrivileges)
	restrictedPrivInfo := tokenInfo(t, restricted, windows.TokenPrivileges)
	sourcePriv := (*windows.Tokenprivileges)(unsafe.Pointer(&sourcePrivInfo[0])).AllPrivileges()
	restrictedPriv := (*windows.Tokenprivileges)(unsafe.Pointer(&restrictedPrivInfo[0])).AllPrivileges()
	attrs := map[string]uint32{}
	key := func(l windows.LUID) string { return fmt.Sprintf("%08x:%08x", uint32(l.HighPart), l.LowPart) }
	for _, p := range restrictedPriv {
		attrs[key(p.Luid)] = p.Attributes
	}
	var change windows.LUID
	_ = windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr("SeChangeNotifyPrivilege"), &change)
	var removed *windows.LUID
	for _, p := range sourcePriv {
		if p.Attributes&windows.SE_PRIVILEGE_ENABLED != 0 && key(p.Luid) != key(change) && attrs[key(p.Luid)]&windows.SE_PRIVILEGE_ENABLED != 0 {
			t.Fatalf("privilege %s remained enabled", key(p.Luid))
		}
		if key(p.Luid) != key(change) && attrs[key(p.Luid)]&windows.SE_PRIVILEGE_ENABLED == 0 && removed == nil {
			copy := p.Luid
			removed = &copy
		}
	}
	if removed == nil {
		t.Fatal("source token exposed no privilege to prove DISABLE_MAX_PRIVILEGE removal")
	}
	if removed != nil {
		state := windows.Tokenprivileges{PrivilegeCount: 1, Privileges: [1]windows.LUIDAndAttributes{{Luid: *removed, Attributes: windows.SE_PRIVILEGE_ENABLED}}}
		_ = windows.AdjustTokenPrivileges(restricted, false, &state, uint32(unsafe.Sizeof(state)), nil, nil)
		afterInfo := tokenInfo(t, restricted, windows.TokenPrivileges)
		after := (*windows.Tokenprivileges)(unsafe.Pointer(&afterInfo[0])).AllPrivileges()
		for _, p := range after {
			if key(p.Luid) == key(*removed) && p.Attributes&windows.SE_PRIVILEGE_ENABLED != 0 {
				t.Fatal("removed privilege could be re-enabled")
			}
		}
	}
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

func runRuntimeMatrix(t *testing.T, token windows.Token, probe, tlsFixture string) []runtimeResult {
	t.Helper()
	system32, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatalf("GetSystemDirectory: %v", err)
	}
	manifest, err := baseline.LoadRuntimeManifest()
	if err != nil {
		t.Fatalf("load runtime manifest: %v", err)
	}
	var cases []runtimeCase
	for _, spec := range manifest.Required {
		cases = append(cases, resolveRuntimeSpec(t, spec, system32, probe, tlsFixture, true))
	}
	for _, spec := range manifest.InventoryOnly {
		cases = append(cases, resolveRuntimeSpec(t, spec, system32, probe, tlsFixture, false))
	}

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

func resolveRuntimeSpec(t *testing.T, spec baseline.RuntimeSpec, system32, probe, tlsFixture string, required bool) runtimeCase {
	t.Helper()
	testCase := runtimeCase{name: spec.Name, args: spec.Args, required: required}
	if spec.NewConsole {
		testCase.creationFlags = windows.CREATE_NEW_CONSOLE
	}
	switch spec.Resolver {
	case "probe":
		testCase.path = probe
		testCase.args = []string{spec.Mode}
	case "tls-fixture":
		testCase.path = tlsFixture
		testCase.expectedOutput = "TLS_CALLBACK_EXECUTED\nMAIN_AFTER_TLS"
	case "system32":
		if len(spec.Candidates) != 1 {
			t.Fatalf("system32 runtime %q candidates = %v, want exactly one canonical path", spec.Name, spec.Candidates)
		}
		testCase.path = filepath.Join(system32, spec.Candidates[0])
	case "path":
		for _, candidate := range spec.Candidates {
			path, err := exec.LookPath(candidate)
			if err != nil {
				testCase.lookupEvidence = append(testCase.lookupEvidence, candidate+": "+err.Error())
				continue
			}
			testCase.lookupEvidence = append(testCase.lookupEvidence, candidate+": "+path)
			testCase.path, err = filepath.Abs(path)
			if err != nil {
				t.Fatalf("absolute runtime path for %s: %v", candidate, err)
			}
			break
		}
		if testCase.path == "" && len(spec.Candidates) != 0 {
			testCase.path = spec.Candidates[0]
		}
	default:
		t.Fatalf("runtime %q has unsupported resolver %q", spec.Name, spec.Resolver)
	}
	return testCase
}

func runRuntimeCase(token windows.Token, testCase runtimeCase) runtimeResult {
	result := runtimeResult{
		Name:            testCase.name,
		Path:            testCase.path,
		Arguments:       testCase.args,
		RequestedAccess: "FILE_EXECUTE|FILE_READ_DATA|FILE_READ_ATTRIBUTES|SYNCHRONIZE (process image and loader startup)",
		Status:          "FAIL",
		ExitCode:        -1,
		CallerPID:       os.Getpid(),
		AttemptID:       os.Getenv("LOOPRIG_RUNTIME_RUN_NONCE") + "/" + testCase.name,
		LookupEvidence:  append([]string(nil), testCase.lookupEvidence...),
	}
	result.ObjectIdentity, result.Owner, result.DACL = objectSecurity(testCase.path)
	if contents, err := os.ReadFile(testCase.path); err == nil {
		result.ExecutableSHA256 = baseline.SHA256Hex(contents)
	}

	if _, err := os.Stat(testCase.path); err != nil {
		result.Error = err.Error()
		if len(result.LookupEvidence) == 0 {
			result.LookupEvidence = []string{testCase.path + ": " + err.Error()}
		}
		if os.IsNotExist(err) {
			result.FailureKind = baseline.FailureInventoryAbsent
		} else {
			result.FailureKind = baseline.FailurePreSpawn
			result.Win32Error = win32Error(err)
		}
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
	if cmd.Process != nil {
		result.PID = cmd.Process.Pid
	}
	result.Output = strings.TrimSpace(output.String())
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if timedOut {
		result.FailureKind = baseline.FailurePostSpawn
		result.Error = "external watchdog after " + runtimeTimeout.String() + ": " + err.Error()
		return result
	}
	if err != nil {
		result.Error = err.Error()
		if result.PID > 0 {
			result.FailureKind = baseline.FailurePostSpawn
		} else {
			result.FailureKind = baseline.FailurePreSpawn
			result.Win32Error = win32Error(err)
		}
		return result
	}
	if testCase.expectedOutput != "" && result.Output != testCase.expectedOutput {
		result.Error = fmt.Sprintf("observable startup order = %q, want %q", result.Output, testCase.expectedOutput)
		result.FailureKind = baseline.FailurePostSpawn
		return result
	}
	result.Status = "PASS"
	return result
}

func win32Error(err error) string {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return fmt.Sprintf("%d (%s)", uintptr(errno), errno.Error())
	}
	return err.Error()
}

func runInRestrictedJob(cmd *exec.Cmd, timeout time.Duration) (runErr error, timedOut bool) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return fmt.Errorf("CreateJobObject: %w", err), false
	}
	jobOpen := true
	closeJob := func() error {
		if !jobOpen {
			return nil
		}
		jobOpen = false
		return windows.CloseHandle(job)
	}
	defer closeJob()
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
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		cleanup := baseline.CleanupWithWatchdog(done, time.After(2*time.Second), func() error { return windows.TerminateJobObject(job, 1) }, closeJob, cmd.Process.Kill)
		return fmt.Errorf("%w; cleanup=%s", runErr, cleanupDiagnostic(cleanup)), false
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case err := <-done:
		return err, false
	case <-timer.C:
		cleanup := baseline.CleanupWithWatchdog(done, time.After(2*time.Second), func() error { return windows.TerminateJobObject(job, 1) }, closeJob, cmd.Process.Kill)
		return fmt.Errorf("%w; cleanup=%s", context.DeadlineExceeded, cleanupDiagnostic(cleanup)), true
	}
}

func cleanupDiagnostic(result baseline.CleanupResult) string {
	return fmt.Sprintf("completed=%v wait=%v terminate_job=%v close_job=%v kill=%v", result.Completed, result.WaitError, result.TerminateError, result.CloseJobError, result.KillError)
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

func platformInventory(t *testing.T) (string, baseline.RunPlatform) {
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
	text := fmt.Sprintf("windows=%d.%d build=%d service_pack=%q (%d.%d) arch=%s system_volume=%s serial=%08x filesystem=%s flags=%08x", version.MajorVersion, version.MinorVersion, version.BuildNumber, windows.UTF16ToString(version.CsdVersion[:]), version.ServicePackMajor, version.ServicePackMinor, runtime.GOARCH, root, serial, windows.UTF16ToString(fsName), flags)
	return text, baseline.RunPlatform{WindowsBuild: fmt.Sprintf("%d.%d.%d", version.MajorVersion, version.MinorVersion, version.BuildNumber), Architecture: runtime.GOARCH, Filesystem: fmt.Sprintf("%s:%08x:%08x", windows.UTF16ToString(fsName), serial, flags)}
}
