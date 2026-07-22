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
	payload := fmt.Sprintf("%s\n%d\n", nonce, os.Getpid())
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
			escaped, pid := waitForEscapeMarker(marker, nonce, probe.markerWait)
			if escaped {
				t.Logf("observed and cleaning broker escape from %s (pid=%d); output=%q code=%d err=%v", probe.name, pid, out, code, runErr)
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
	escaped, pid := waitForEscapeMarker(marker, nonce, 3*time.Second)
	if !escaped || pid != command.Process.Pid {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("escape payload positive control did not create its bound marker: escaped=%v pid=%d want=%d", escaped, pid, command.Process.Pid)
	}
	_ = command.Process.Kill()
	_ = command.Wait()
	cleanupEscapeMarker(t, marker, nonce, executable)
}

func waitForEscapeMarker(path, nonce string, timeout time.Duration) (bool, int) {
	deadline := time.Now().Add(timeout)
	for {
		contents, err := os.ReadFile(path)
		if err == nil {
			lines := strings.Split(strings.TrimSpace(string(contents)), "\n")
			if len(lines) == 2 && lines[0] == nonce {
				pid, parseErr := strconv.Atoi(lines[1])
				if parseErr == nil && pid > 0 {
					return true, pid
				}
			}
			return false, 0
		}
		if !errors.Is(err, os.ErrNotExist) || time.Now().After(deadline) {
			return false, 0
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func cleanupEscapeMarker(t *testing.T, path, nonce, executable string) {
	t.Helper()
	if escaped, pid := waitForEscapeMarker(path, nonce, 0); escaped {
		terminateAndWait(t, uint32(pid), executable)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Errorf("remove broker marker: %v", err)
	}
}

func terminateAndWait(t *testing.T, pid uint32, expectedExecutable string) {
	t.Helper()
	handle, err := win.OpenProcess(win.PROCESS_TERMINATE|win.SYNCHRONIZE|win.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if errors.Is(err, win.ERROR_INVALID_PARAMETER) {
		return
	}
	if err != nil {
		t.Errorf("open escaped process %d for cleanup: %v", pid, err)
		return
	}
	defer win.CloseHandle(handle)
	buffer := make([]uint16, win.MAX_LONG_PATH)
	size := uint32(len(buffer))
	if err := win.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		t.Errorf("verify escaped process %d image before cleanup: %v", pid, err)
		return
	}
	actualExecutable := win.UTF16ToString(buffer[:size])
	cleanImage := func(path string) string { return strings.TrimPrefix(filepath.Clean(path), `\\?\`) }
	if !strings.EqualFold(cleanImage(actualExecutable), cleanImage(expectedExecutable)) {
		t.Errorf("refuse to terminate unbound marker PID %d: image=%q want=%q", pid, actualExecutable, expectedExecutable)
		return
	}
	if err := win.TerminateProcess(handle, 125); err != nil {
		t.Errorf("terminate escaped process %d: %v", pid, err)
		return
	}
	if status, err := win.WaitForSingleObject(handle, 5_000); err != nil || status != win.WAIT_OBJECT_0 {
		t.Errorf("wait for escaped process %d cleanup: status=%#x err=%v", pid, status, err)
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
