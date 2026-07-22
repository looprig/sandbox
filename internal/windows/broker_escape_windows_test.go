//go:build windows

package windows_test

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	sandboxexec "github.com/looprig/sandbox/internal/exec"
	sandboxwindows "github.com/looprig/sandbox/internal/windows"
	win "golang.org/x/sys/windows"
)

const (
	disposableRestrictedEnv = "SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST"
	escapeHelperTest        = "TestWindowsBrokerEscapePayload"
	escapeWatchdogTimeout   = 8 * time.Second
)

// TestWindowsBrokerEscapePayload is launched by an adversarial broker attempt.
// The marker is deliberately outside every projected root. A direct restricted
// child cannot create it; an out-of-Job full-user broker process may be able to.
func TestWindowsBrokerEscapePayload(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 || len(os.Args) != separator+3 {
		return
	}
	marker, nonce := os.Args[separator+1], os.Args[separator+2]
	creation, err := processCreationTime(win.CurrentProcess())
	if err != nil {
		t.Fatalf("read broker-escape process creation time: %v", err)
	}
	payload := fmt.Sprintf("%s\n%d\n%d\n", nonce, os.Getpid(), creation)
	if err := os.WriteFile(marker, []byte(payload), 0o600); err != nil {
		t.Fatalf("write broker-escape marker: %v", err)
	}
	// The out-of-sandbox parent watchdog terminates a successful escape. Keeping
	// the process alive makes cleanup observable and prevents a transient escape
	// from being mistaken for a harmless completed launch.
	time.Sleep(2 * time.Minute)
}

func TestRestrictedBrokerEscapeMatrix(t *testing.T) {
	if os.Getenv(disposableRestrictedEnv) != "1" {
		t.Skip("broker escape integration is restricted to a disposable Windows worker")
	}
	requireDisposableStandardSourceToken(t)
	powershell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Fatalf("required PowerShell runtime is unavailable: %v", err)
	}
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	testExecutable, err = filepath.Abs(testExecutable)
	if err != nil {
		t.Fatalf("canonicalize test executable: %v", err)
	}

	workspace := t.TempDir()
	scratch := t.TempDir()
	profile, err := sandboxexec.NewProfile(sandboxexec.ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: sandboxexec.Allow, WorkspaceWrite: sandboxexec.Allow,
		HostRead: sandboxexec.Allow, HostWrite: sandboxexec.Allow,
		Network: sandboxexec.Allow, Command: sandboxexec.Allow,
	})
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	set, err := sandboxexec.NewExecutorSet(profile,
		sandboxexec.WithScratchRoot(scratch), sandboxexec.WithMaxExecutors(1),
		sandboxexec.WithWindowsSandboxMode(sandboxwindows.RestrictedToken),
	)
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := set.Close(); closeErr != nil {
			t.Errorf("ExecutorSet.Close: %v", closeErr)
		}
	})
	executor, err := set.For("broker-escape")
	if err != nil {
		t.Fatalf("ExecutorSet.For: %v", err)
	}
	if executor.Level() != sandboxexec.LevelNone || executor.GuaranteeBits() != sandboxexec.GuaranteeEnvScrub {
		t.Fatalf("restricted posture = level %d, bits %#x; want LevelNone and EnvScrub only", executor.Level(), executor.GuaranteeBits())
	}

	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	marker := filepath.Join(scratch, "broker-escape-"+nonce+".marker")
	payloadArgs := fmt.Sprintf("-test.run=^%s$ -- %s %s", escapeHelperTest, quoteWindowsArgument(marker), quoteWindowsArgument(nonce))
	payloadCommand := quoteWindowsArgument(testExecutable) + " " + payloadArgs
	assertEscapePayloadPositiveControl(t, testExecutable, marker, nonce)

	taskName := `LooprigBrokerEscape-` + nonce
	t.Cleanup(func() {
		deleteScheduledTask(taskName)
		cleanupEscapeMarker(t, marker, nonce, testExecutable)
	})
	probes := []struct {
		name       string
		script     string
		markerWait time.Duration
	}{
		{
			name: "explorer-ishelldispatch-shellexecute",
			script: fmt.Sprintf(`$shell=New-Object -ComObject 'Shell.Application'; $shell.ShellExecute(%s,%s,'','open',0)`,
				quotePowerShellLiteral(testExecutable), quotePowerShellLiteral(payloadArgs)),
			markerWait: 3 * time.Second,
		},
		{
			name: "powershell-start-process",
			script: fmt.Sprintf(`Start-Process -FilePath %s -ArgumentList %s -WindowStyle Hidden`,
				quotePowerShellLiteral(testExecutable), quotePowerShellLiteral(payloadArgs)),
			markerWait: 3 * time.Second,
		},
		{
			name: "wmi-win32-process-create",
			script: fmt.Sprintf(`$result=([wmiclass]'Win32_Process').Create(%s); Write-Output ($result.ReturnValue.ToString()+':'+$result.ProcessId.ToString())`,
				quotePowerShellLiteral(payloadCommand)),
			markerWait: 3 * time.Second,
		},
		{
			name: "scheduled-task",
			script: fmt.Sprintf(`& schtasks.exe /Create /SC ONCE /ST 23:59 /TN %s /TR %s /F; if ($LASTEXITCODE -eq 0) { & schtasks.exe /Run /TN %s }`,
				quotePowerShellLiteral(taskName), quotePowerShellLiteral(payloadCommand), quotePowerShellLiteral(taskName)),
			markerWait: escapeWatchdogTimeout,
		},
		{
			name: "com-wscript-shell-activation",
			script: fmt.Sprintf(`$shell=New-Object -ComObject 'WScript.Shell'; [void]$shell.Run(%s,0,$false)`,
				quotePowerShellLiteral(payloadCommand)),
			markerWait: 3 * time.Second,
		},
		{
			name: "gui-shell-launch",
			script: fmt.Sprintf(`Start-Process -FilePath %s -ArgumentList %s -WindowStyle Normal`,
				quotePowerShellLiteral(testExecutable), quotePowerShellLiteral(payloadArgs)),
			markerWait: 3 * time.Second,
		},
		{
			name:   "com-elevation-moniker",
			script: elevationMonikerProbe,
		},
		{
			name:   "named-pipe-brokers",
			script: namedPipeBrokerProbe,
		},
	}

	for _, probe := range probes {
		probe := probe
		t.Run(probe.name, func(t *testing.T) {
			cleanupEscapeMarker(t, marker, nonce, testExecutable)
			if probe.name == "scheduled-task" {
				deleteScheduledTask(taskName)
			}
			ctx, cancel := context.WithTimeout(context.Background(), escapeWatchdogTimeout)
			out, code, runErr := executor.RunArgv(ctx, workspace, []string{
				powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(probe.script),
			})
			cancel()
			escaped, identity := waitForEscapeMarker(marker, nonce, probe.markerWait)
			if escaped {
				t.Logf("observed and cleaning broker escape from %s (pid=%d); output=%q code=%d err=%v", probe.name, identity.pid, out, code, runErr)
				if claimed := executor.GuaranteeBits() & (sandboxexec.GuaranteeProcessBoundary | sandboxexec.GuaranteeWriteBoundary | sandboxexec.GuaranteeResourceLimits); claimed != 0 {
					t.Errorf("broker escape bypassed claimed guarantees %#x", claimed)
				}
			} else {
				t.Logf("broker attempt %s did not escape; output=%q code=%d err=%v", probe.name, out, code, runErr)
			}
			cleanupEscapeMarker(t, marker, nonce, testExecutable)
			if probe.name == "scheduled-task" {
				deleteScheduledTask(taskName)
			}
			if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
				t.Errorf("broker marker remains after cleanup: %v", statErr)
			}
		})
	}
}

func requireDisposableStandardSourceToken(t *testing.T) {
	t.Helper()
	var token win.Token
	if err := win.OpenProcessToken(win.CurrentProcess(), win.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("inspect disposable-worker source token: %v", err)
	}
	defer token.Close()
	if err := sandboxwindows.ValidateDisposableStandardUserToken(token); err != nil {
		t.Fatalf("validate disposable-worker source token: %v", err)
	}
}

func deleteScheduledTask(taskName string) {
	for _, arguments := range [][]string{
		{"/End", "/TN", taskName},
		{"/Delete", "/TN", taskName, "/F"},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = exec.CommandContext(ctx, "schtasks.exe", arguments...).Run()
		cancel()
	}
}

func assertEscapePayloadPositiveControl(t *testing.T, executable, marker, nonce string) {
	t.Helper()
	cleanupEscapeMarker(t, marker, nonce, executable)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, executable, "-test.run=^"+escapeHelperTest+"$", "--", marker, nonce)
	if err := command.Start(); err != nil {
		t.Fatalf("start escape payload positive control: %v", err)
	}
	escaped, identity := waitForEscapeMarker(marker, nonce, 3*time.Second)
	if !escaped || identity.pid != uint32(command.Process.Pid) {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("escape payload positive control did not create its bound marker: escaped=%v pid=%d want=%d", escaped, identity.pid, command.Process.Pid)
	}
	_ = command.Process.Kill()
	_ = command.Wait()
	cleanupEscapeMarker(t, marker, nonce, executable)
}

type escapedProcessIdentity struct {
	pid          uint32
	creationTime int64
	image        string
}

func waitForEscapeMarker(path, nonce string, timeout time.Duration) (bool, escapedProcessIdentity) {
	deadline := time.Now().Add(timeout)
	for {
		contents, err := os.ReadFile(path)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
			if len(lines) == 3 && lines[0] == nonce {
				pid, pidErr := strconv.ParseUint(lines[1], 10, 32)
				creation, creationErr := strconv.ParseInt(lines[2], 10, 64)
				if pidErr == nil && creationErr == nil && pid > 0 && creation > 0 {
					return true, escapedProcessIdentity{pid: uint32(pid), creationTime: creation}
				}
			}
			return false, escapedProcessIdentity{}
		}
		if !errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
			return false, escapedProcessIdentity{}
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func cleanupEscapeMarker(t *testing.T, path, nonce, executable string) {
	t.Helper()
	if escaped, identity := waitForEscapeMarker(path, nonce, 0); escaped {
		identity.image = executable
		terminateAndWait(t, identity)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Errorf("remove broker marker: %v", err)
	}
}

func terminateAndWait(t *testing.T, expected escapedProcessIdentity) {
	t.Helper()
	handle, err := win.OpenProcess(win.PROCESS_TERMINATE|win.SYNCHRONIZE|win.PROCESS_QUERY_LIMITED_INFORMATION, false, expected.pid)
	if errors.Is(err, win.ERROR_INVALID_PARAMETER) {
		return
	}
	if err != nil {
		t.Errorf("open escaped process %d for cleanup: %v", expected.pid, err)
		return
	}
	defer win.CloseHandle(handle)
	buffer := make([]uint16, win.MAX_LONG_PATH)
	size := uint32(len(buffer))
	if err := win.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		t.Errorf("verify escaped process %d image before cleanup: %v", expected.pid, err)
		return
	}
	actual := escapedProcessIdentity{pid: expected.pid, image: win.UTF16ToString(buffer[:size])}
	actual.creationTime, err = processCreationTime(handle)
	if err != nil {
		t.Errorf("verify escaped process %d creation time before cleanup: %v", expected.pid, err)
		return
	}
	if !sameEscapedProcess(expected, actual) {
		t.Errorf("refuse to terminate reused/mismatched marker PID %d: creation=%d image=%q want creation=%d image=%q",
			expected.pid, actual.creationTime, actual.image, expected.creationTime, expected.image)
		return
	}
	if err := win.TerminateProcess(handle, 125); err != nil {
		t.Errorf("terminate escaped process %d: %v", expected.pid, err)
		return
	}
	if status, err := win.WaitForSingleObject(handle, 5_000); err != nil || status != win.WAIT_OBJECT_0 {
		t.Errorf("wait for escaped process %d cleanup: status=%#x err=%v", expected.pid, status, err)
	}
}

func processCreationTime(handle win.Handle) (int64, error) {
	var creation, exit, kernel, user win.Filetime
	if err := win.GetProcessTimes(handle, &creation, &exit, &kernel, &user); err != nil {
		return 0, err
	}
	return creation.Nanoseconds(), nil
}

func sameEscapedProcess(expected, actual escapedProcessIdentity) bool {
	cleanImage := func(path string) string { return strings.TrimPrefix(filepath.Clean(path), `\\?\`) }
	return expected.pid == actual.pid && expected.creationTime == actual.creationTime &&
		strings.EqualFold(cleanImage(expected.image), cleanImage(actual.image))
}

func TestBrokerEscapeCleanupIdentityRefusesPIDReuseAndImageMismatch(t *testing.T) {
	want := escapedProcessIdentity{pid: 17, creationTime: 99, image: `C:\probe.exe`}
	if !sameEscapedProcess(want, want) {
		t.Fatal("identical bound process identity rejected")
	}
	for name, got := range map[string]escapedProcessIdentity{
		"pid reuse":       {pid: 17, creationTime: 100, image: `C:\probe.exe`},
		"different pid":   {pid: 18, creationTime: 99, image: `C:\probe.exe`},
		"different image": {pid: 17, creationTime: 99, image: `C:\other.exe`},
	} {
		if sameEscapedProcess(want, got) {
			t.Errorf("%s accepted", name)
		}
	}
}

func quotePowerShellLiteral(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "''") + "'"
}

func quoteWindowsArgument(value string) string {
	return `"` + strings.ReplaceAll(value, `"`, `\"`) + `"`
}

func encodePowerShell(script string) string {
	encoded := utf16.Encode([]rune(script))
	bytes := make([]byte, len(encoded)*2)
	for index, value := range encoded {
		bytes[index*2] = byte(value)
		bytes[index*2+1] = byte(value >> 8)
	}
	return base64.StdEncoding.EncodeToString(bytes)
}

const namedPipeBrokerProbe = `$names=@('atsvc','svcctl','spoolss'); foreach ($name in $names) { try { $pipe=New-Object System.IO.Pipes.NamedPipeClientStream('.', $name, [System.IO.Pipes.PipeDirection]::InOut); $pipe.Connect(500); Write-Output ($name+':connected'); $pipe.Dispose() } catch { Write-Output ($name+':'+$_.Exception.GetType().Name) } }`

const elevationMonikerProbe = `$source=@'
using System;
using System.Runtime.InteropServices;
public static class LooprigElevationProbe {
  [StructLayout(LayoutKind.Sequential)] public struct BIND_OPTS3 { public uint cbStruct, grfFlags, grfMode, dwTickCountDeadline, dwTrackFlags, dwClassContext, locale; public IntPtr pServerInfo, hwnd; }
  [DllImport("ole32.dll", CharSet=CharSet.Unicode)] static extern int CoGetObject(string name, ref BIND_OPTS3 options, ref Guid iid, [MarshalAs(UnmanagedType.Interface)] out object value);
  public static int Run() { var options=new BIND_OPTS3(); options.cbStruct=(uint)Marshal.SizeOf(options); options.dwClassContext=4; var iid=new Guid("00000000-0000-0000-C000-000000000046"); object value; return CoGetObject("Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}", ref options, ref iid, out value); }
}
'@; Add-Type -TypeDefinition $source; Write-Output ([LooprigElevationProbe]::Run())`
