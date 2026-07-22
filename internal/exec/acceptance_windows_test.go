//go:build windows

package exec

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/looprig/sandbox/internal/windows"
	"github.com/looprig/sandbox/pkg/sandboxtest"
	win "golang.org/x/sys/windows"
)

const windowsDisposableACLTest = "SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST"

// TestWindowsRestrictedSandboxtestAcceptance drives the reusable conformance
// suite through the real restricted backend. It is opt-in because construction
// projects and rolls back ACLs on a disposable Windows worker.
func TestWindowsRestrictedSandboxtestAcceptance(t *testing.T) {
	if os.Getenv(windowsDisposableACLTest) != "1" {
		t.Skip(windowsDisposableACLTest + "=1 is required; live ACL acceptance remains unrun")
	}
	requireWindowsDisposableStandardSourceToken(t)

	factory := func(t *testing.T, workspace string) sandboxtest.SUT {
		return newWindowsRestrictedAcceptanceExecutor(t, workspace)
	}

	sandboxtest.RunSuite(t, "windows-restricted", factory)

	// The restricted tier intentionally withholds read/process/network/resource
	// guarantees. Reuse the shared implication gate to pin that none of those
	// behavioral probes becomes a requirement until the backend claims its bit.
	t.Run("withheld-implications", func(t *testing.T) {
		workspace := t.TempDir()
		sut := factory(t, workspace)
		called := false
		probe := func(context.Context, sandboxtest.SUT) (sandboxtest.ImplicationResult, error) {
			called = true
			return sandboxtest.ImplicationResult{PositiveControl: true, GuaranteeHeld: false}, nil
		}
		sandboxtest.CheckClaimedImplications(t, sut, sandboxtest.ImplicationProbes{
			Read: probe, Process: probe, Network: probe, AddressNetwork: probe, TargetNetwork: probe, Resource: probe,
		})
		if called {
			t.Fatal("restricted backend ran an implication probe for a withheld guarantee")
		}
	})
}

func requireWindowsDisposableStandardSourceToken(t *testing.T) {
	t.Helper()
	var token win.Token
	if err := win.OpenProcessToken(win.CurrentProcess(), win.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("inspect disposable-worker source token: %v", err)
	}
	defer token.Close()
	restricted, err := token.IsRestricted()
	if err != nil {
		t.Fatalf("inspect disposable-worker restriction state: %v", err)
	}
	if restricted {
		t.Fatal("disposable restricted acceptance requires a non-restricted source token")
	}
	if token.IsElevated() {
		t.Fatal("disposable restricted acceptance requires a standard-user, non-elevated source token")
	}
}

// TestWindowsRestrictedDescendantPayload is the ordinary CreateProcess child
// used by the production Executor cancellation acceptance below.
func TestWindowsRestrictedDescendantPayload(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || len(os.Args) != separator+4 {
		return
	}
	mode, state, marker := os.Args[separator+1], os.Args[separator+2], os.Args[separator+3]
	switch mode {
	case "parent":
		command := osexec.Command(os.Args[0], "-test.run=^TestWindowsRestrictedDescendantPayload$", "--", "child", state, marker)
		command.Stdout, command.Stderr = os.Stdout, os.Stderr
		if err := command.Run(); err != nil {
			t.Fatalf("ordinary descendant: %v", err)
		}
	case "child":
		inJob, err := currentProcessInJob()
		if err != nil {
			t.Fatalf("query descendant Job membership: %v", err)
		}
		creation, err := acceptanceProcessCreationTime(win.CurrentProcess())
		if err != nil {
			t.Fatalf("query descendant creation time: %v", err)
		}
		if err := os.WriteFile(state, []byte(fmt.Sprintf("%t\n%d\n%d\n", inJob, os.Getpid(), creation)), 0o600); err != nil {
			t.Fatalf("write descendant state: %v", err)
		}
		time.Sleep(1500 * time.Millisecond)
		if err := os.WriteFile(marker, []byte("descendant survived cancellation"), 0o600); err != nil {
			t.Fatalf("write descendant survival marker: %v", err)
		}
		time.Sleep(30 * time.Second)
	default:
		t.Fatalf("unknown descendant payload mode %q", mode)
	}
}

func TestWindowsRestrictedExecutorKillsOrdinaryDescendantsOnCancellation(t *testing.T) {
	if os.Getenv(windowsDisposableACLTest) != "1" {
		t.Skip(windowsDisposableACLTest + "=1 is required; live descendant cancellation remains unrun")
	}
	requireWindowsDisposableStandardSourceToken(t)
	workspace := t.TempDir()
	executor := newWindowsRestrictedAcceptanceExecutor(t, workspace)
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	testExecutable, err = filepath.Abs(testExecutable)
	if err != nil {
		t.Fatal(err)
	}
	cmdPath := filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	if _, err := os.Stat(cmdPath); err != nil {
		t.Fatalf("required cmd.exe runtime is unavailable: %v", err)
	}
	powershellPath, err := osexec.LookPath("powershell.exe")
	if err != nil {
		t.Fatalf("required PowerShell runtime is unavailable: %v", err)
	}
	pythonPath, err := osexec.LookPath("python.exe")
	if err != nil {
		t.Fatalf("required Python runtime is unavailable: %v", err)
	}
	runtimes := []struct {
		name string
		argv func(state, marker string) []string
	}{
		{name: "native", argv: func(state, marker string) []string {
			return descendantHelperArgv(testExecutable, state, marker)
		}},
		{name: "cmd", argv: func(state, marker string) []string {
			command := quoteCmdArgument(testExecutable)
			for _, argument := range descendantHelperArgv(testExecutable, state, marker)[1:] {
				command += " " + quoteCmdArgument(argument)
			}
			return []string{cmdPath, "/D", "/S", "/C", command}
		}},
		{name: "powershell", argv: func(state, marker string) []string {
			arguments := descendantHelperArgv(testExecutable, state, marker)
			quoted := make([]string, len(arguments))
			for index, argument := range arguments {
				quoted[index] = "'" + strings.ReplaceAll(argument, "'", "''") + "'"
			}
			return []string{powershellPath, "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", "& " + strings.Join(quoted, " ")}
		}},
		{name: "python", argv: func(state, marker string) []string {
			arguments := descendantHelperArgv(testExecutable, state, marker)
			return append([]string{pythonPath, "-c", "import subprocess,sys;sys.exit(subprocess.call(sys.argv[1:]))"}, arguments...)
		}},
	}
	for _, runtimeCase := range runtimes {
		runtimeCase := runtimeCase
		t.Run(runtimeCase.name, func(t *testing.T) {
			state := filepath.Join(workspace, runtimeCase.name+"-descendant.state")
			marker := filepath.Join(workspace, runtimeCase.name+"-descendant-survived.marker")
			runRestrictedDescendantCancellation(t, executor, workspace, testExecutable, state, marker, runtimeCase.argv(state, marker))
		})
	}
}

func descendantHelperArgv(testExecutable, state, marker string) []string {
	return []string{testExecutable, "-test.run=^TestWindowsRestrictedDescendantPayload$", "--", "parent", state, marker}
}

func quoteCmdArgument(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func runRestrictedDescendantCancellation(t *testing.T, executor *Executor, workspace, testExecutable, state, marker string, argv []string) {
	t.Helper()
	if err := os.WriteFile(marker, []byte("unconfined positive control"), 0o600); err != nil {
		t.Fatalf("descendant marker positive control is not writable: %v", err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatalf("remove descendant marker positive control: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type runResult struct {
		output []byte
		code   int
		err    error
	}
	done := make(chan runResult, 1)
	go func() {
		output, code, runErr := executor.RunArgv(ctx, workspace, argv)
		done <- runResult{output: output, code: code, err: runErr}
	}()

	inJob, childIdentity := waitForDescendantState(t, state, 5*time.Second)
	if !inJob {
		cancel()
		t.Fatalf("ordinary descendant PID %d was not assigned to the production Executor Job", childIdentity.pid)
	}
	childIdentity.image = testExecutable
	childHandle, err := openVerifiedAcceptanceProcess(childIdentity)
	if err != nil {
		cancel()
		t.Fatalf("bind descendant process identity: %v", err)
	}
	cleanupRequired := true
	t.Cleanup(func() {
		defer win.CloseHandle(childHandle)
		if cleanupRequired {
			terminateAcceptanceHelper(t, childHandle, childIdentity)
		}
	})
	cancel()
	select {
	case result := <-done:
		if result.err == nil {
			t.Errorf("canceled restricted execution returned nil error: code=%d output=%q", result.code, result.output)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("production Executor did not return after cancellation watchdog")
	}

	if !waitForProcessExit(childHandle, 5*time.Second) {
		t.Fatalf("ordinary descendant PID %d survived production Executor cancellation", childIdentity.pid)
	}
	cleanupRequired = false
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ordinary descendant wrote post-cancellation marker: %v", err)
	}
}

func newWindowsRestrictedAcceptanceExecutor(t *testing.T, workspace string) *Executor {
	t.Helper()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Allow, Network: Allow, Command: Allow,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		WithWindowsSandboxMode(windows.RestrictedToken))
	if err != nil {
		t.Fatalf("NewExecutorSet(restricted acceptance): %v", err)
	}
	t.Cleanup(func() {
		if err := set.Close(); err != nil {
			t.Errorf("close restricted acceptance set: %v", err)
		}
	})
	executor, err := set.For("restricted-descendant")
	if err != nil {
		t.Fatalf("ExecutorSet.For(restricted acceptance): %v", err)
	}
	if executor.Level() != LevelNone || executor.GuaranteeBits() != GuaranteeEnvScrub {
		t.Fatalf("restricted posture = level %d, bits %#x; want LevelNone/EnvScrub only", executor.Level(), executor.GuaranteeBits())
	}
	return executor
}

func TestWindowsRestrictedProductionHandleCanaries(t *testing.T) {
	if os.Getenv(windowsDisposableACLTest) != "1" {
		t.Skip(windowsDisposableACLTest + "=1 is required; live production handle canaries remain unrun")
	}
	requireWindowsDisposableStandardSourceToken(t)
	workspace, scratch := t.TempDir(), t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Allow, Network: Allow, Command: Allow,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(scratch), WithMaxExecutors(1),
		WithWindowsSandboxMode(windows.RestrictedToken))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("restricted-handle-canaries")
	if err != nil {
		t.Fatal(err)
	}

	canaries := make(map[string]win.Handle)
	add := func(name string, handle win.Handle, close func() error) {
		t.Helper()
		if err := win.SetHandleInformation(handle, win.HANDLE_FLAG_INHERIT, win.HANDLE_FLAG_INHERIT); err != nil {
			_ = close()
			t.Fatalf("make %s canary inheritable: %v", name, err)
		}
		canaries[name] = handle
		t.Cleanup(func() { _ = close() })
	}
	openDirectory := func(name, path string) {
		pointer, err := win.UTF16PtrFromString(path)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := win.CreateFile(pointer, win.FILE_LIST_DIRECTORY, win.FILE_SHARE_READ|win.FILE_SHARE_WRITE|win.FILE_SHARE_DELETE,
			nil, win.OPEN_EXISTING, win.FILE_FLAG_BACKUP_SEMANTICS, 0)
		if err != nil {
			t.Fatalf("open %s canary: %v", name, err)
		}
		add(name, handle, func() error { return win.CloseHandle(handle) })
	}
	openDirectory("stable-state-root", scratch)
	openDirectory("canonical-workspace-directory", workspace)
	journalRoot := filepath.Join(scratch, "restricted-journal-v1")
	openDirectory("restricted-journal-directory", journalRoot)
	leasePath := filepath.Join(workspace, "representative-live-lease-object.txt")
	leaseFile, err := os.OpenFile(leasePath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	add("representative-live-lease-object", win.Handle(leaseFile.Fd()), leaseFile.Close)
	if err := filepath.WalkDir(journalRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || canaries["restricted-journal-file"] != 0 {
			return nil
		}
		file, openErr := os.Open(path)
		if openErr != nil {
			return openErr
		}
		add("restricted-journal-file", win.Handle(file.Fd()), file.Close)
		return nil
	}); err != nil {
		t.Fatalf("find actual restricted journal file canary: %v", err)
	}
	if canaries["restricted-journal-file"] == 0 {
		t.Fatal("production restricted construction created no durable journal file canary")
	}
	job, err := win.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	add("job", job, func() error { return win.CloseHandle(job) })

	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve acceptance test source")
	}
	helper := filepath.Join(t.TempDir(), "handleprobe.exe")
	build := osexec.Command("go", "build", "-o", helper, filepath.Join(filepath.Dir(source), "..", "windows", "testdata", "handleprobe"))
	build.Dir = filepath.Dir(source)
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build required native handle probe: %v: %s", err, output)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	output, code, err := executor.RunArgv(ctx, workspace, []string{helper})
	if err != nil || code != 0 {
		t.Fatalf("production restricted handle probe: code=%d err=%v output=%q", code, err, output)
	}
	var report struct {
		Standard map[string]uintptr `json:"standard"`
		Handles  []struct {
			Value uintptr `json:"value"`
		} `json:"handles"`
	}
	if err := json.Unmarshal(output[:jsonObjectEnd(output)], &report); err != nil {
		t.Fatalf("decode production handle report: %v: %q", err, output)
	}
	for _, name := range []string{"stdin", "stdout", "stderr"} {
		if report.Standard[name] == 0 {
			t.Errorf("production restricted target did not receive working %s", name)
		}
	}
	if !strings.Contains(string(output), "stderr-ok") {
		t.Errorf("production restricted target stderr was not usable: %q", output)
	}
	for name, canary := range canaries {
		for _, inherited := range report.Handles {
			if inherited.Value == uintptr(canary) {
				t.Errorf("production restricted target inherited %s handle %#x", name, uintptr(canary))
			}
		}
	}
}

func jsonObjectEnd(output []byte) int {
	for index := len(output); index > 0; index-- {
		if output[index-1] == '}' {
			return index
		}
	}
	return len(output)
}

type acceptanceProcessIdentity struct {
	pid          uint32
	creationTime int64
	image        string
}

func waitForDescendantState(t *testing.T, path string, timeout time.Duration) (bool, acceptanceProcessIdentity) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) != 3 {
				t.Fatalf("malformed descendant state %q", data)
			}
			pid, pidErr := strconv.ParseUint(fields[1], 10, 32)
			creation, creationErr := strconv.ParseInt(fields[2], 10, 64)
			if pidErr != nil || creationErr != nil || pid == 0 || creation <= 0 {
				t.Fatalf("malformed descendant PID %q", fields[1])
			}
			return fields[0] == "true", acceptanceProcessIdentity{pid: uint32(pid), creationTime: creation}
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read descendant state: %v", err)
		}
		if time.Now().After(deadline) {
			t.Fatal("ordinary descendant did not reach Job-membership checkpoint")
		}
		time.Sleep(25 * time.Millisecond)
	}
}

var isProcessInJobProc = win.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

func currentProcessInJob() (bool, error) {
	var result int32
	success, _, callErr := isProcessInJobProc.Call(uintptr(win.CurrentProcess()), 0, uintptr(unsafe.Pointer(&result)))
	if success == 0 {
		return false, callErr
	}
	return result != 0, nil
}

func waitForProcessExit(handle win.Handle, timeout time.Duration) bool {
	status, err := win.WaitForSingleObject(handle, uint32(timeout/time.Millisecond))
	return err == nil && status == win.WAIT_OBJECT_0
}

func terminateAcceptanceHelper(t *testing.T, handle win.Handle, expected acceptanceProcessIdentity) {
	t.Helper()
	actual, err := acceptanceIdentityFromHandle(handle, expected.pid)
	if err != nil {
		t.Errorf("verify descendant %d before watchdog cleanup: %v", expected.pid, err)
		return
	}
	if !sameAcceptanceProcess(expected, actual) {
		t.Errorf("refuse to terminate reused/mismatched descendant PID %d", expected.pid)
		return
	}
	status, waitErr := win.WaitForSingleObject(handle, 0)
	if waitErr == nil && status == win.WAIT_OBJECT_0 {
		return
	}
	if err := win.TerminateProcess(handle, 125); err != nil {
		t.Errorf("terminate descendant %d during watchdog cleanup: %v", expected.pid, err)
	}
}

func openVerifiedAcceptanceProcess(expected acceptanceProcessIdentity) (win.Handle, error) {
	handle, err := win.OpenProcess(win.PROCESS_QUERY_LIMITED_INFORMATION|win.PROCESS_TERMINATE|win.SYNCHRONIZE, false, expected.pid)
	if err != nil {
		return 0, err
	}
	actual, err := acceptanceIdentityFromHandle(handle, expected.pid)
	if err != nil || !sameAcceptanceProcess(expected, actual) {
		win.CloseHandle(handle)
		if err != nil {
			return 0, err
		}
		return 0, errors.New("descendant PID was reused or image/creation identity mismatched")
	}
	return handle, nil
}

func acceptanceIdentityFromHandle(handle win.Handle, pid uint32) (acceptanceProcessIdentity, error) {
	buffer := make([]uint16, win.MAX_LONG_PATH)
	size := uint32(len(buffer))
	if err := win.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		return acceptanceProcessIdentity{}, err
	}
	creation, err := acceptanceProcessCreationTime(handle)
	if err != nil {
		return acceptanceProcessIdentity{}, err
	}
	return acceptanceProcessIdentity{pid: pid, creationTime: creation, image: win.UTF16ToString(buffer[:size])}, nil
}

func acceptanceProcessCreationTime(handle win.Handle) (int64, error) {
	var creation, exit, kernel, user win.Filetime
	if err := win.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return creation.Nanoseconds(), nil
}

func sameAcceptanceProcess(expected, actual acceptanceProcessIdentity) bool {
	clean := func(path string) string { return strings.TrimPrefix(filepath.Clean(path), `\\?\`) }
	return expected.pid == actual.pid && expected.creationTime == actual.creationTime &&
		strings.EqualFold(clean(expected.image), clean(actual.image))
}

func TestAcceptanceWatchdogRefusesPIDReuseAndImageMismatch(t *testing.T) {
	want := acceptanceProcessIdentity{pid: 17, creationTime: 99, image: `C:\probe.exe`}
	for name, got := range map[string]acceptanceProcessIdentity{
		"same":            want,
		"pid reuse":       {pid: 17, creationTime: 100, image: `C:\probe.exe`},
		"different image": {pid: 17, creationTime: 99, image: `C:\other.exe`},
	} {
		matched := sameAcceptanceProcess(want, got)
		if matched != (name == "same") {
			t.Errorf("%s match = %v", name, matched)
		}
	}
}
