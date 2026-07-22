//go:build windows

package exec

import (
	"context"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
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
			Read: probe, Process: probe, Network: probe, Resource: probe,
		})
		if called {
			t.Fatal("restricted backend ran an implication probe for a withheld guarantee")
		}
	})
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
		if err := os.WriteFile(state, []byte(fmt.Sprintf("%t\n%d\n", inJob, os.Getpid())), 0o600); err != nil {
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
	state := filepath.Join(workspace, "descendant.state")
	marker := filepath.Join(workspace, "descendant-survived.marker")
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
		output, code, runErr := executor.RunArgv(ctx, workspace, []string{
			testExecutable, "-test.run=^TestWindowsRestrictedDescendantPayload$", "--", "parent", state, marker,
		})
		done <- runResult{output: output, code: code, err: runErr}
	}()

	inJob, childPID := waitForDescendantState(t, state, 5*time.Second)
	if !inJob {
		cancel()
		t.Fatalf("ordinary descendant PID %d was not assigned to the production Executor Job", childPID)
	}
	cleanupPID := childPID
	t.Cleanup(func() {
		if cleanupPID > 0 {
			terminateAcceptanceHelper(t, uint32(cleanupPID), testExecutable)
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

	if !waitForProcessExit(uint32(childPID), 5*time.Second) {
		t.Fatalf("ordinary descendant PID %d survived production Executor cancellation", childPID)
	}
	cleanupPID = 0
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("ordinary descendant wrote post-cancellation marker: %v", err)
	}
}

func newWindowsRestrictedAcceptanceExecutor(t *testing.T, workspace string) *Executor {
	t.Helper()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
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

func waitForDescendantState(t *testing.T, path string, timeout time.Duration) (bool, int) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		data, err := os.ReadFile(path)
		if err == nil {
			fields := strings.Fields(string(data))
			if len(fields) != 2 {
				t.Fatalf("malformed descendant state %q", data)
			}
			pid, parseErr := strconv.Atoi(fields[1])
			if parseErr != nil || pid <= 0 {
				t.Fatalf("malformed descendant PID %q", fields[1])
			}
			return fields[0] == "true", pid
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

func waitForProcessExit(pid uint32, timeout time.Duration) bool {
	handle, err := win.OpenProcess(win.SYNCHRONIZE, false, pid)
	if errors.Is(err, win.ERROR_INVALID_PARAMETER) {
		return true
	}
	if err != nil {
		return false
	}
	defer win.CloseHandle(handle)
	status, err := win.WaitForSingleObject(handle, uint32(timeout/time.Millisecond))
	return err == nil && status == win.WAIT_OBJECT_0
}

func terminateAcceptanceHelper(t *testing.T, pid uint32, expectedExecutable string) {
	t.Helper()
	handle, err := win.OpenProcess(win.PROCESS_QUERY_LIMITED_INFORMATION|win.PROCESS_TERMINATE|win.SYNCHRONIZE, false, pid)
	if errors.Is(err, win.ERROR_INVALID_PARAMETER) {
		return
	}
	if err != nil {
		t.Errorf("open descendant %d for watchdog cleanup: %v", pid, err)
		return
	}
	defer win.CloseHandle(handle)
	buffer := make([]uint16, win.MAX_LONG_PATH)
	size := uint32(len(buffer))
	if err := win.QueryFullProcessImageName(handle, 0, &buffer[0], &size); err != nil {
		t.Errorf("verify descendant %d before watchdog cleanup: %v", pid, err)
		return
	}
	actual := strings.TrimPrefix(filepath.Clean(win.UTF16ToString(buffer[:size])), `\\?\`)
	want := strings.TrimPrefix(filepath.Clean(expectedExecutable), `\\?\`)
	if !strings.EqualFold(actual, want) {
		t.Errorf("refuse to terminate unbound descendant PID %d: image=%q want=%q", pid, actual, want)
		return
	}
	status, waitErr := win.WaitForSingleObject(handle, 0)
	if waitErr == nil && status == win.WAIT_OBJECT_0 {
		return
	}
	if err := win.TerminateProcess(handle, 125); err != nil {
		t.Errorf("terminate descendant %d during watchdog cleanup: %v", pid, err)
	}
}
