//go:build windows

package windows_test

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	sandbox "github.com/looprig/sandbox"
	"github.com/looprig/sandbox/pkg/sandboxtest"
	win "golang.org/x/sys/windows"
)

const elevatedDisposableGate = "SANDBOX_WINDOWS_ELEVATED_TEST"

func TestElevatedDisposableAcceptance(t *testing.T) {
	sandboxtest.RequireLiveGate(t, sandboxtest.LiveGate{
		OptInEnv: elevatedDisposableGate, Description: "installed elevated Windows adversarial matrix",
		Supported: elevatedWorkerSupported,
		Evidence:  elevatedWorkerPrerequisites,
	})

	config := elevatedSetupConfig(t)
	setupAndRequireReady(t, config)

	// A second setup is a real refresh: it revalidates the protected ready
	// generation, rotates credentials, reconciles the exact owned service and
	// replaces ready state only after all dependency checks pass.
	setupAndRequireReady(t, config)
	restartInstalledService(t, config.StateRoot)
	requireElevatedReady(t, config)

	factory := func(t *testing.T, workspace string) sandboxtest.SUT {
		return newElevatedAcceptanceExecutor(t, workspace, config.StateRoot)
	}
	sandboxtest.RunSuite(t, "windows-elevated", factory)

	t.Run("claimed-implications", func(t *testing.T) {
		workspace := t.TempDir()
		sut := factory(t, workspace)
		sandboxtest.CheckClaimedImplications(t, sut, sandboxtest.ImplicationProbes{
			Read:     elevatedReadProbe(t, workspace),
			Process:  elevatedBrokerEscapeProbe(t, workspace),
			Network:  elevatedOfflineNetworkProbe(t, workspace),
			Resource: elevatedJobProbe(t, workspace),
		})
	})
	t.Run("target-network", func(t *testing.T) {
		elevatedTargetNetworkAcceptance(t, config.StateRoot)
	})
	t.Run("configured-resource-limits", func(t *testing.T) {
		runElevatedResourceLimitsAcceptance(t)
	})

	// Exercise owned removal in the live suite, then reinstall so the workflow's
	// unconditional cleanup remains the final authority and independently
	// verifies residue even if a later test or the job is cancelled.
	if err := sandbox.RemoveWindowsSandbox(context.Background(), config); err != nil {
		t.Fatalf("remove elevated setup: %v", err)
	}
	status, err := sandbox.InspectWindowsSandbox(context.Background(), config)
	if err != nil {
		t.Fatalf("inspect removed elevated setup: %v", err)
	}
	if status.Ready {
		t.Fatal("removed elevated setup still reports ready")
	}
	setupAndRequireReady(t, config)
}

// TestElevatedAcceptancePayload is copied into a projected workspace and
// launched by the real installed runner. It is inert in the ordinary test
// process.
func TestElevatedAcceptancePayload(t *testing.T) {
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator < 0 {
		return
	}
	if len(os.Args) == separator+4 && os.Args[separator+1] == "proxy" {
		response, err := (&http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}).
			Get(os.Args[separator+2])
		if err != nil {
			t.Fatalf("proxy request: %v", err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		if err != nil {
			t.Fatalf("read proxy response: %v", err)
		}
		if response.StatusCode != http.StatusOK || string(body) != os.Args[separator+3] {
			t.Fatalf("proxy response = status %d body %q, want 200/%q",
				response.StatusCode, body, os.Args[separator+3])
		}
		return
	}
	if len(os.Args) != separator+3 || os.Args[separator+1] != "job" {
		return
	}
	inJob, err := processInAnyJob()
	if err != nil {
		t.Fatalf("query installed-runner Job membership: %v", err)
	}
	result := elevatedJobProbeResult{InJob: inJob}
	if inJob {
		var limits win.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
		if err := win.QueryInformationJobObject(0, win.JobObjectExtendedLimitInformation,
			uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), nil); err != nil {
			t.Fatalf("query installed-runner Job limits: %v", err)
		}
		result.LimitFlags = limits.BasicLimitInformation.LimitFlags
		var ui win.JOBOBJECT_BASIC_UI_RESTRICTIONS
		if err := win.QueryInformationJobObject(0, win.JobObjectBasicUIRestrictions,
			uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui)), nil); err != nil {
			t.Fatalf("query installed-runner Job UI restrictions: %v", err)
		}
		result.UIFlags = ui.UIRestrictionsClass
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Args[separator+2], encoded, 0o600); err != nil {
		t.Fatalf("write installed-runner Job result: %v", err)
	}
}

type elevatedJobProbeResult struct {
	InJob      bool   `json:"in_job"`
	LimitFlags uint32 `json:"limit_flags"`
	UIFlags    uint32 `json:"ui_flags"`
}

func processInAnyJob() (bool, error) {
	var inJob uint32
	ok, _, callErr := win.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").Call(
		uintptr(win.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inJob)))
	if ok == 0 {
		return false, callErr
	}
	return inJob != 0, nil
}

func elevatedSetupConfig(t *testing.T) sandbox.WindowsSetupConfig {
	t.Helper()
	ports := parseElevatedProxyPorts(t, os.Getenv("SANDBOX_WINDOWS_PROXY_PORTS"))
	return sandbox.WindowsSetupConfig{
		InstallationID:      mustElevatedEnv(t, "SANDBOX_WINDOWS_INSTALLATION_ID"),
		StateRoot:           mustAbsoluteElevatedEnv(t, "SANDBOX_WINDOWS_STATE_ROOT"),
		HostBinary:          mustAbsoluteElevatedEnv(t, "SANDBOX_WINDOWS_HOST_BINARY"),
		ProxyPorts:          ports,
		RuntimeEvidencePath: mustAbsoluteElevatedEnv(t, "SANDBOX_WINDOWS_RUNTIME_EVIDENCE"),
	}
}

func setupAndRequireReady(t *testing.T, config sandbox.WindowsSetupConfig) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := sandbox.SetupWindowsSandbox(ctx, config); err != nil {
		t.Fatalf("setup elevated Windows sandbox: %v", err)
	}
	requireElevatedReady(t, config)
}

func requireElevatedReady(t *testing.T, config sandbox.WindowsSetupConfig) {
	t.Helper()
	status, err := sandbox.InspectWindowsSandbox(context.Background(), config)
	if err != nil {
		t.Fatalf("inspect elevated Windows sandbox: %v", err)
	}
	if !status.Ready || len(status.Problems) != 0 {
		t.Fatalf("elevated setup is not ready: %+v", status)
	}
}

func newElevatedAcceptanceExecutor(t *testing.T, workspace, stateRoot string) *sandbox.Executor {
	t.Helper()
	profile, err := sandbox.NewProfile(sandbox.ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: sandbox.Allow, WorkspaceWrite: sandbox.Allow,
		HostRead: sandbox.Deny, HostWrite: sandbox.Deny,
		Network: sandbox.Deny, Command: sandbox.Allow,
	})
	if err != nil {
		t.Fatalf("create elevated acceptance profile: %v", err)
	}
	set, err := sandbox.NewExecutorSet(profile,
		sandbox.WithScratchRoot(t.TempDir()), sandbox.WithMaxExecutors(1),
		sandbox.WithWindowsSandboxMode(sandbox.WindowsElevated),
		sandbox.WithWindowsSandboxStateRoot(stateRoot),
	)
	if err != nil {
		t.Fatalf("create elevated executor set: %v", err)
	}
	t.Cleanup(func() {
		if err := set.Close(); err != nil {
			t.Errorf("close elevated executor set: %v", err)
		}
	})
	executor, err := set.For("elevated-acceptance")
	if err != nil {
		t.Fatalf("create elevated executor: %v", err)
	}
	return executor
}

func elevatedReadProbe(t *testing.T, workspace string) sandboxtest.ImplicationProbe {
	t.Helper()
	outside := filepath.Join(filepath.Dir(workspace), "elevated-read-positive.txt")
	if err := os.WriteFile(outside, []byte("positive"), 0o600); err != nil {
		t.Fatalf("create elevated read positive control: %v", err)
	}
	if data, err := os.ReadFile(outside); err != nil || string(data) != "positive" {
		t.Fatalf("elevated read positive control: data=%q err=%v", data, err)
	}
	return func(ctx context.Context, sut sandboxtest.SUT) (sandboxtest.ImplicationResult, error) {
		argv, ok := sut.(sandboxtest.ArgvSUT)
		if !ok {
			return sandboxtest.ImplicationResult{}, errors.New("elevated executor lacks argv execution")
		}
		_, code, runErr := argv.RunArgv(ctx, workspace, []string{
			filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/D", "/C", "type", outside,
		})
		return sandboxtest.ImplicationResult{
			PositiveControl: true, GuaranteeHeld: runErr != nil || code != 0,
			Detail: fmt.Sprintf("outside read code=%d err=%v", code, runErr),
		}, nil
	}
}

func elevatedBrokerEscapeProbe(t *testing.T, workspace string) sandboxtest.ImplicationProbe {
	t.Helper()
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	nonce := strconv.FormatInt(time.Now().UnixNano(), 36)
	marker := filepath.Join(filepath.Dir(workspace), "elevated-broker-"+nonce+".marker")
	powershell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Fatalf("PowerShell positive control is unavailable: %v", err)
	}
	payloadArgs := fmt.Sprintf("-test.run=^%s$ -- %s %s", escapeHelperTest, quoteWindowsArgument(marker), quoteWindowsArgument(nonce))
	payloadCommand := quoteWindowsArgument(testExecutable) + " " + payloadArgs
	guiHelper := filepath.Join(filepath.Dir(workspace), "elevated-gui-"+nonce+".exe")
	makeGUIEscapeHelper(t, testExecutable, guiHelper)
	t.Cleanup(func() { _ = os.Remove(guiHelper) })
	t.Cleanup(func() { cleanupKnownEscapeMarker(t, marker, nonce, testExecutable, guiHelper) })
	taskName := "LooprigElevatedEscape-" + nonce
	t.Cleanup(func() { deleteScheduledTask(taskName) })
	type brokerSurface struct{ name, script, executable string }
	surfaces := []brokerSurface{
		{"powershell-start-process", fmt.Sprintf(`$ErrorActionPreference='Stop'; try { Start-Process -FilePath %s -ArgumentList %s -WindowStyle Hidden } catch { Write-Output ('DENIED:'+$_.Exception.Message) }`, quotePowerShellLiteral(testExecutable), quotePowerShellLiteral(payloadArgs)), testExecutable},
		{"wmi-win32-process-create", fmt.Sprintf(`$ErrorActionPreference='Stop'; try { $r=([wmiclass]'Win32_Process').Create(%s); if ($r.ReturnValue -ne 0) { Write-Output ('DENIED:'+($r.ReturnValue.ToString())) } } catch { Write-Output ('DENIED:'+$_.Exception.Message) }`, quotePowerShellLiteral(payloadCommand)), testExecutable},
		{"com-shell-application", fmt.Sprintf(`$ErrorActionPreference='Stop'; try { $s=New-Object -ComObject 'Shell.Application'; $s.ShellExecute(%s,%s,'','open',0) } catch { Write-Output ('DENIED:'+$_.Exception.Message) }`, quotePowerShellLiteral(testExecutable), quotePowerShellLiteral(payloadArgs)), testExecutable},
		{"scheduled-task", fmt.Sprintf(`$ErrorActionPreference='Stop'; try { & schtasks.exe /Create /SC ONCE /ST 23:59 /TN %s /TR %s /F | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'create failed' }; & schtasks.exe /Run /TN %s | Out-Null; if ($LASTEXITCODE -ne 0) { throw 'run failed' } } catch { Write-Output ('DENIED:'+$_.Exception.Message) }`, quotePowerShellLiteral(taskName), quotePowerShellLiteral(payloadCommand), quotePowerShellLiteral(taskName)), testExecutable},
		{"com-wscript-shell", fmt.Sprintf(`$ErrorActionPreference='Stop'; try { $s=New-Object -ComObject 'WScript.Shell'; [void]$s.Run(%s,0,$false) } catch { Write-Output ('DENIED:'+$_.Exception.Message) }`, quotePowerShellLiteral(payloadCommand)), testExecutable},
		{"gui-shell-launch", fmt.Sprintf(`$ErrorActionPreference='Stop'; try { Start-Process -FilePath %s -ArgumentList %s -WindowStyle Normal } catch { Write-Output ('DENIED:'+$_.Exception.Message) }`, quotePowerShellLiteral(guiHelper), quotePowerShellLiteral(payloadArgs)), guiHelper},
	}
	cleanupSurface := func(surface brokerSurface) {
		cleanupEscapeMarker(t, marker, nonce, surface.executable)
		if surface.name == "scheduled-task" {
			deleteScheduledTask(taskName)
		}
	}
	for _, surface := range surfaces {
		cleanupSurface(surface)
		output, err := exec.Command(powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
			"-EncodedCommand", encodePowerShell(surface.script)).CombinedOutput()
		if err != nil {
			t.Fatalf("broker surface %s positive control failed: %v: %s", surface.name, err, output)
		}
		if escaped, _ := waitForEscapeMarker(marker, nonce, escapeWatchdogTimeout); !escaped {
			t.Fatalf("broker surface %s positive control did not launch the bound payload: %s", surface.name, output)
		}
		cleanupSurface(surface)
	}
	elevationAttempt := "$ErrorActionPreference='Stop'; try { " + elevationMonikerProbe + " } catch { Write-Output ('DENIED:'+$_.Exception.Message) }"
	output, err := exec.Command(powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(elevationAttempt)).CombinedOutput()
	if err != nil || !containsPowerShellResult(output, "0") {
		t.Fatalf("COM elevation moniker positive control failed: %v: %s", err, output)
	}
	return func(ctx context.Context, sut sandboxtest.SUT) (sandboxtest.ImplicationResult, error) {
		argv, ok := sut.(sandboxtest.ArgvSUT)
		if !ok {
			return sandboxtest.ImplicationResult{}, errors.New("elevated executor lacks argv execution")
		}
		for _, surface := range surfaces {
			cleanupSurface(surface)
			output, code, runErr := argv.RunArgv(ctx, workspace, []string{
				powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
				"-EncodedCommand", encodePowerShell(surface.script),
			})
			if runErr != nil || code != 0 {
				return sandboxtest.ImplicationResult{}, fmt.Errorf("broker surface %s probe did not execute: output=%q code=%d err=%v", surface.name, output, code, runErr)
			}
			if escaped, _ := waitForEscapeMarker(marker, nonce, escapeWatchdogTimeout); escaped {
				cleanupSurface(surface)
				return sandboxtest.ImplicationResult{
					PositiveControl: true, GuaranteeHeld: false,
					Detail: "full-user process broker created the bound escape marker",
				}, nil
			}
			cleanupSurface(surface)
		}
		output, code, runErr := argv.RunArgv(ctx, workspace, []string{
			powershell, "-NoLogo", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodePowerShell(elevationAttempt),
		})
		if runErr != nil || code != 0 {
			return sandboxtest.ImplicationResult{}, fmt.Errorf("COM elevation moniker probe did not execute: output=%q code=%d err=%v", output, code, runErr)
		}
		if containsPowerShellResult(output, "0") {
			return sandboxtest.ImplicationResult{PositiveControl: true, GuaranteeHeld: false, Detail: "COM elevation moniker activated from sandbox"}, nil
		}
		return sandboxtest.ImplicationResult{PositiveControl: true, GuaranteeHeld: true}, nil
	}
}

func containsPowerShellResult(output []byte, result string) bool {
	for _, line := range strings.Split(strings.ReplaceAll(string(output), "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == result {
			return true
		}
	}
	return false
}

func cleanupKnownEscapeMarker(t *testing.T, marker, nonce string, executables ...string) {
	t.Helper()
	escaped, identity := waitForEscapeMarker(marker, nonce, 0)
	if escaped {
		handle, err := win.OpenProcess(win.PROCESS_QUERY_LIMITED_INFORMATION, false, identity.pid)
		if err == nil {
			buffer := make([]uint16, win.MAX_LONG_PATH)
			size := uint32(len(buffer))
			if err = win.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err == nil {
				actual := win.UTF16ToString(buffer[:size])
				for _, executable := range executables {
					if strings.EqualFold(filepath.Clean(actual), filepath.Clean(executable)) {
						identity.image = executable
						terminateAndWait(t, identity)
						break
					}
				}
			}
			_ = win.CloseHandle(handle)
		}
		if identity.image == "" {
			t.Errorf("could not bind escaped process %d to a known cleanup image: %v", identity.pid, err)
		}
	}
	if err := os.Remove(marker); err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Errorf("remove elevated broker marker: %v", err)
	}
}

func makeGUIEscapeHelper(t *testing.T, source, destination string) {
	t.Helper()
	data, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 0x40 || string(data[:2]) != "MZ" {
		t.Fatal("GUI escape helper source is not a PE image")
	}
	peOffset := int(binary.LittleEndian.Uint32(data[0x3c:0x40]))
	subsystemOffset := peOffset + 24 + 68
	if peOffset < 0 || subsystemOffset+2 > len(data) || string(data[peOffset:peOffset+4]) != "PE\x00\x00" {
		t.Fatal("GUI escape helper has an invalid PE header")
	}
	binary.LittleEndian.PutUint16(data[subsystemOffset:subsystemOffset+2], 2)
	if err := os.WriteFile(destination, data, 0o700); err != nil {
		t.Fatal(err)
	}
}

func elevatedTargetNetworkAcceptance(t *testing.T, stateRoot string) {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target-network listener: %v", err)
	}
	const responseBody = "elevated-target-network-ok"
	server := &http.Server{Handler: http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, responseBody)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
	})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	route, err := sandbox.NewDirectEgressRoute()
	if err != nil {
		t.Fatal(err)
	}
	route = route.WithDialer(
		func(context.Context, string) ([]net.IP, error) {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		},
		func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "tcp4", listener.Addr().String())
		},
	)
	workspace := t.TempDir()
	executor := newElevatedTargetAcceptanceExecutor(t, workspace, stateRoot, route)
	helper, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	projectedHelper := filepath.Join(workspace, "elevated-target-probe.exe")
	copyFileForAcceptance(t, helper, projectedHelper)
	run := func(executionID, host string) ([]byte, int, error) {
		url := "http://" + net.JoinHostPort(host, port) + "/"
		command := fmt.Sprintf(`%s -test.run=^TestElevatedAcceptancePayload$ -- proxy %s %s`,
			quoteWindowsArgument(projectedHelper), quoteWindowsArgument(url), quoteWindowsArgument(responseBody))
		token, issueErr := executor.IssueGrant(context.Background(), executionID, command, workspace,
			"network", "", sandbox.GrantClassNetworkProxyTarget,
			"tcp:"+net.JoinHostPort("allowed.test", port), time.Now().Add(time.Minute).UnixMilli())
		if issueErr != nil {
			t.Fatalf("issue target-network grant: %v", issueErr)
		}
		return executor.RunCommandWithGrants(context.Background(), executionID, workspace, command, []string{token})
	}
	output, code, err := run("target-allowed", "allowed.test")
	if err != nil || code != 0 || !strings.Contains(string(output), "PASS") {
		t.Fatalf("authenticated allowed target = code %d err %v output %q", code, err, output)
	}
	output, code, err = run("target-denied", "denied.test")
	if !errors.Is(err, sandbox.ErrNetworkTargetDenied) {
		t.Fatalf("unapproved target = code %d err %v output %q, want ErrNetworkTargetDenied", code, err, output)
	}
}

func newElevatedTargetAcceptanceExecutor(
	t *testing.T,
	workspace, stateRoot string,
	route sandbox.EgressRoute,
) *sandbox.Executor {
	t.Helper()
	profile, err := sandbox.NewProfile(sandbox.ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: sandbox.Allow, WorkspaceWrite: sandbox.Allow,
		HostRead: sandbox.Deny, HostWrite: sandbox.Deny,
		Network: sandbox.Gated, Command: sandbox.Allow,
	})
	if err != nil {
		t.Fatalf("create elevated target profile: %v", err)
	}
	set, err := sandbox.NewExecutorSet(profile,
		sandbox.WithScratchRoot(t.TempDir()), sandbox.WithMaxExecutors(1),
		sandbox.WithEgressRoute(route),
		sandbox.WithWindowsSandboxMode(sandbox.WindowsElevated),
		sandbox.WithWindowsSandboxStateRoot(stateRoot),
	)
	if err != nil {
		t.Fatalf("create elevated target executor set: %v", err)
	}
	t.Cleanup(func() {
		if err := set.Close(); err != nil {
			t.Errorf("close elevated target executor set: %v", err)
		}
	})
	executor, err := set.For("elevated-target-acceptance")
	if err != nil {
		t.Fatalf("create elevated target executor: %v", err)
	}
	if !executor.Guarantees().TargetNetwork || !executor.Guarantees().NetworkBoundary {
		t.Fatalf("elevated target executor guarantees = %+v, want NetworkBoundary and TargetNetwork",
			executor.Guarantees())
	}
	return executor
}

func runElevatedResourceLimitsAcceptance(t *testing.T) {
	t.Helper()
	testExecutable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command(testExecutable,
		"-test.run=^TestElevatedConfiguredResourceLimitsAcceptance$",
		"-test.v",
	).CombinedOutput()
	if err != nil {
		t.Fatalf("configured resource-limit acceptance failed: %v: %s", err, output)
	}
	if !strings.Contains(string(output), "ELEVATED_RESOURCE_LIMITS_ACCEPTANCE_PASS") {
		t.Fatalf("configured resource-limit acceptance did not execute: %s", output)
	}
}

func elevatedOfflineNetworkProbe(t *testing.T, workspace string) sandboxtest.ImplicationProbe {
	t.Helper()
	listener, address := listenNonLoopback(t)
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan struct{}, 8)
	go func() {
		for {
			connection, err := listener.Accept()
			if err != nil {
				return
			}
			_ = connection.Close()
			accepted <- struct{}{}
		}
	}()
	positive, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("offline-network positive control: %v", err)
	}
	_ = positive.Close()
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("offline-network positive control was not accepted")
	}
	host, port, _ := net.SplitHostPort(address)
	powershell, err := exec.LookPath("powershell.exe")
	if err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf(`$c=New-Object Net.Sockets.TcpClient; $c.Connect(%s,%s); $c.Close()`,
		quotePowerShellLiteral(host), port)
	return func(ctx context.Context, sut sandboxtest.SUT) (sandboxtest.ImplicationResult, error) {
		argv, ok := sut.(sandboxtest.ArgvSUT)
		if !ok {
			return sandboxtest.ImplicationResult{}, errors.New("elevated executor lacks argv execution")
		}
		_, code, runErr := argv.RunArgv(ctx, workspace, []string{
			powershell, "-NoLogo", "-NoProfile", "-NonInteractive",
			"-EncodedCommand", encodePowerShell(script),
		})
		escaped := false
		select {
		case <-accepted:
			escaped = true
		case <-time.After(500 * time.Millisecond):
		}
		return sandboxtest.ImplicationResult{
			PositiveControl: true, GuaranteeHeld: !escaped && (runErr != nil || code != 0),
			Detail: fmt.Sprintf("non-loopback connection code=%d err=%v accepted=%t", code, runErr, escaped),
		}, nil
	}
}

func elevatedJobProbe(t *testing.T, workspace string) sandboxtest.ImplicationProbe {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(workspace, "elevated-acceptance-probe.exe")
	copyFileForAcceptance(t, source, helper)
	control := filepath.Join(workspace, "job-positive-control.txt")
	if output, err := exec.Command(helper, "-test.run=^TestElevatedAcceptancePayload$", "--", "job", control).CombinedOutput(); err != nil {
		t.Fatalf("Job probe positive control: %v: %s", err, output)
	}
	controlData, err := os.ReadFile(control)
	if err != nil {
		t.Fatalf("Job probe positive control did not execute: %v", err)
	}
	var controlResult elevatedJobProbeResult
	if err := json.Unmarshal(controlData, &controlResult); err != nil || controlResult.InJob {
		t.Fatalf("Job probe worker has ambient Job authority: result=%+v err=%v", controlResult, err)
	}
	return func(ctx context.Context, sut sandboxtest.SUT) (sandboxtest.ImplicationResult, error) {
		argv, ok := sut.(sandboxtest.ArgvSUT)
		if !ok {
			return sandboxtest.ImplicationResult{}, errors.New("elevated executor lacks argv execution")
		}
		result := filepath.Join(workspace, "job-sandboxed.txt")
		output, code, runErr := argv.RunArgv(ctx, workspace, []string{
			helper, "-test.run=^TestElevatedAcceptancePayload$", "--", "job", result,
		})
		data, readErr := os.ReadFile(result)
		var observed elevatedJobProbeResult
		decodeErr := json.Unmarshal(data, &observed)
		breakaway := uint32(win.JOB_OBJECT_LIMIT_BREAKAWAY_OK | win.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
		wantUI := uint32(win.JOB_OBJECT_UILIMIT_DESKTOP | win.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
			win.JOB_OBJECT_UILIMIT_EXITWINDOWS | win.JOB_OBJECT_UILIMIT_GLOBALATOMS |
			win.JOB_OBJECT_UILIMIT_HANDLES | win.JOB_OBJECT_UILIMIT_READCLIPBOARD |
			win.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS | win.JOB_OBJECT_UILIMIT_WRITECLIPBOARD)
		return sandboxtest.ImplicationResult{
			PositiveControl: true,
			GuaranteeHeld: runErr == nil && code == 0 && readErr == nil && decodeErr == nil && observed.InJob &&
				observed.LimitFlags&win.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE != 0 && observed.LimitFlags&breakaway == 0 &&
				observed.UIFlags == wantUI,
			Detail: fmt.Sprintf("Job result=%+v output=%q code=%d runErr=%v readErr=%v decodeErr=%v", observed, output, code, runErr, readErr, decodeErr),
		}, nil
	}
}

func restartInstalledService(t *testing.T, stateRoot string) {
	t.Helper()
	script := fmt.Sprintf(
		`$s=@(Get-CimInstance Win32_Service | Where-Object {$_.PathName -like ('*'+%s+'*')}); if($s.Count -ne 1){throw "owned service lookup failed"}; Stop-Service -Name $s[0].Name -Force; Start-Service -Name $s[0].Name`,
		quotePowerShellLiteral(stateRoot))
	if output, err := exec.Command("powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput(); err != nil {
		t.Fatalf("restart installed broker service: %v: %s", err, output)
	}
}

func listenNonLoopback(t *testing.T) (net.Listener, string) {
	t.Helper()
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		ip, _, err := net.ParseCIDR(address.String())
		if err != nil || ip.IsLoopback() || ip.To4() == nil {
			continue
		}
		listener, err := net.Listen("tcp4", net.JoinHostPort(ip.String(), "0"))
		if err == nil {
			return listener, listener.Addr().String()
		}
	}
	t.Fatal("no bindable non-loopback IPv4 address for firewall positive control")
	return nil, ""
}

func copyFileForAcceptance(t *testing.T, source, destination string) {
	t.Helper()
	input, err := os.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	if err := errors.Join(copyErr, closeErr); err != nil {
		t.Fatal(err)
	}
}

func elevatedWorkerSupported() (bool, string) {
	version := win.RtlGetVersion()
	supported := version.MajorVersion == 10 && version.MinorVersion == 0 &&
		((version.ProductType == 1 && version.BuildNumber >= 22000) || version.ProductType == 2 || version.ProductType == 3)
	if !supported {
		return false, fmt.Sprintf("supported Windows 11/Server worker is required; got product=%d build=%d", version.ProductType, version.BuildNumber)
	}
	if !win.GetCurrentProcessToken().IsElevated() {
		return false, "elevated worker token is required"
	}
	return true, ""
}

func elevatedWorkerPrerequisites() (bool, string) {
	if inJob, err := processInAnyJob(); err != nil || inJob {
		return false, "elevated disposable worker must not place the test harness in an ambient Job"
	}
	for _, name := range []string{
		"SANDBOX_WINDOWS_HOST_BINARY", "SANDBOX_WINDOWS_STATE_ROOT",
		"SANDBOX_WINDOWS_INSTALLATION_ID", "SANDBOX_WINDOWS_PROXY_PORTS",
		"SANDBOX_WINDOWS_RUNTIME_EVIDENCE",
	} {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			return false, name + " is required"
		}
	}
	for _, name := range []string{"SANDBOX_WINDOWS_HOST_BINARY", "SANDBOX_WINDOWS_RUNTIME_EVIDENCE"} {
		path := os.Getenv(name)
		if !filepath.IsAbs(path) {
			return false, name + " must be absolute"
		}
		if info, err := os.Stat(path); err != nil || info.IsDir() {
			return false, name + " is missing or not a file"
		}
	}
	root := os.Getenv("SANDBOX_WINDOWS_STATE_ROOT")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false, "SANDBOX_WINDOWS_STATE_ROOT must be canonical and absolute"
	}
	return true, ""
}

func mustElevatedEnv(t *testing.T, name string) string {
	t.Helper()
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		t.Fatalf("%s is required", name)
	}
	return value
}

func mustAbsoluteElevatedEnv(t *testing.T, name string) string {
	t.Helper()
	value := mustElevatedEnv(t, name)
	if !filepath.IsAbs(value) || filepath.Clean(value) != value {
		t.Fatalf("%s must be canonical and absolute", name)
	}
	return value
}

func parseElevatedProxyPorts(t *testing.T, raw string) []uint16 {
	t.Helper()
	var ports []uint16
	seen := map[uint16]struct{}{}
	for _, item := range strings.Split(raw, ",") {
		value, err := strconv.ParseUint(strings.TrimSpace(item), 10, 16)
		port := uint16(value)
		if err != nil || port == 0 {
			t.Fatalf("invalid SANDBOX_WINDOWS_PROXY_PORTS value %q", item)
		}
		if _, duplicate := seen[port]; duplicate {
			t.Fatalf("duplicate SANDBOX_WINDOWS_PROXY_PORTS value %d", port)
		}
		seen[port] = struct{}{}
		ports = append(ports, port)
	}
	return ports
}
