//go:build windows

package exec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/looprig/sandbox/internal/policy"
	winapi "golang.org/x/sys/windows"
)

const (
	processTreeHelperMode = "LOOPRIG_PROCESS_TREE_HELPER"
	processTreeMarker     = "LOOPRIG_PROCESS_TREE_MARKER"
)

func TestProcessTreeOptionsReachConfiguredJob(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessTreeHelper$")
	tree, err := newProcessTree(cmd, processTreeOptions{
		Sandboxed: true,
		Limits: policy.Limits{
			MaxPIDs:     3,
			MaxMemBytes: 32 << 20,
			MaxCPUPct:   50,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tree.close()
	if tree.job == nil || !tree.job.ResourceLimitsInstalled() {
		t.Fatal("process tree did not retain a Job with validated resource limits")
	}
}

// TestProcessTreeLifetimeIsNeverEnforcedForWrapSpawns pins M5: every Windows
// spawn built through this tree runs as the caller's own user (restricted
// token or Unconfined), so a same-user broker can create a process outside
// the Job. The elevated tier's Enforced answer comes from its backend-owned
// Launch path, which never constructs a processTree.
func TestProcessTreeLifetimeIsNeverEnforcedForWrapSpawns(t *testing.T) {
	for _, test := range []struct {
		name    string
		options processTreeOptions
		want    LifetimeContainment
	}{
		{"restricted tier", processTreeOptions{Sandboxed: true, Supervised: true}, LifetimeContainmentBestEffort},
		{"restricted tier synchronous", processTreeOptions{Sandboxed: true}, LifetimeContainmentBestEffort},
		{"unconfined", processTreeOptions{Supervised: true}, LifetimeContainmentUnspecified},
	} {
		t.Run(test.name, func(t *testing.T) {
			tree, err := newProcessTree(exec.Command(os.Args[0], "-test.run=^TestProcessTreeHelper$"), test.options)
			if err != nil {
				t.Fatal(err)
			}
			defer tree.close()
			var reporter lifetimeReporter = tree
			if got := reporter.lifetimeContainment(); got != test.want {
				t.Fatalf("lifetimeContainment() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestProcessTreeCancellationAndJobClosePreventDelayedGrandchild(t *testing.T) {
	for _, tc := range []struct {
		name string
		stop func(*processTree) error
	}{
		{name: "cancellation", stop: func(tree *processTree) error { return tree.terminate() }},
		{name: "host death closes job", stop: func(tree *processTree) error { tree.close(); return nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			marker := filepath.Join(dir, "grandchild-marker")
			ready := filepath.Join(dir, "ready")
			breakaway := filepath.Join(dir, "breakaway-marker")
			cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestProcessTreeHelper$")
			cmd.Env = append(os.Environ(),
				processTreeHelperMode+"=parent",
				processTreeMarker+"="+marker,
				"LOOPRIG_PROCESS_TREE_READY="+ready,
				"LOOPRIG_PROCESS_TREE_BREAKAWAY="+breakaway,
			)
			tree, err := newProcessTree(cmd, processTreeOptions{Sandboxed: true})
			if err != nil {
				t.Fatal(err)
			}
			defer tree.close()
			if err := tree.start(cmd); err != nil {
				t.Fatal(err)
			}
			waitForFile(t, ready, 5*time.Second)
			if err := tc.stop(tree); err != nil {
				t.Fatal(err)
			}
			_ = cmd.Wait()
			if tc.name == "cancellation" {
				if terminateErr, proofErr := tree.terminateAndWait(); terminateErr != nil || proofErr != nil {
					t.Fatal(errors.Join(terminateErr, proofErr))
				}
			}
			time.Sleep(750 * time.Millisecond)
			if _, err := os.Stat(marker); !os.IsNotExist(err) {
				t.Fatalf("delayed ordinary grandchild escaped Job: %v", err)
			}
			if _, err := os.Stat(breakaway); !os.IsNotExist(err) {
				t.Fatalf("CREATE_BREAKAWAY_FROM_JOB escaped Job: %v", err)
			}
		})
	}
}

func TestProcessTreeHelper(t *testing.T) {
	switch os.Getenv(processTreeHelperMode) {
	case "parent":
		breakaway := exec.Command(os.Args[0], "-test.run=^TestProcessTreeHelper$")
		breakaway.Env = append(os.Environ(), processTreeHelperMode+"=grandchild", processTreeMarker+"="+os.Getenv("LOOPRIG_PROCESS_TREE_BREAKAWAY"))
		breakaway.SysProcAttr = &syscall.SysProcAttr{CreationFlags: winapi.CREATE_BREAKAWAY_FROM_JOB}
		if err := breakaway.Start(); err == nil {
			_ = breakaway.Process.Release()
		}
		ordinary := exec.Command(os.Args[0], "-test.run=^TestProcessTreeHelper$")
		ordinary.Env = append(os.Environ(), processTreeHelperMode+"=grandchild")
		if err := ordinary.Start(); err != nil {
			os.Exit(2)
		}
		if err := os.WriteFile(os.Getenv("LOOPRIG_PROCESS_TREE_READY"), []byte("ready"), 0o600); err != nil {
			os.Exit(3)
		}
		select {}
	case "grandchild":
		time.Sleep(500 * time.Millisecond)
		if err := os.WriteFile(os.Getenv(processTreeMarker), []byte("escaped"), 0o600); err != nil {
			os.Exit(4)
		}
		os.Exit(0)
	case "console-processes":
		// A detached pipe child must have no console. Refuse unexpected
		// errors as well as successful attachment; neither proves isolation.
		_, err := currentConsoleProcessList()
		if !errors.Is(err, winapi.ERROR_INVALID_HANDLE) {
			_ = os.WriteFile(os.Getenv(processTreeMarker), []byte(fmt.Sprintf("console query: %v", err)), 0o600)
			os.Exit(7)
		}
		if err := os.WriteFile(os.Getenv(processTreeMarker), []byte("no-console\n"), 0o600); err != nil {
			os.Exit(8)
		}
		os.Exit(0)
	case "job-membership":
		// This payload's very first action queries and records its own Job
		// membership, then exits immediately — see
		// TestProcessTreeWindowsJobBeforeResume for why that ordering is the
		// entire point: newProcessTree's start() (process_tree_windows.go)
		// creates this process CREATE_SUSPENDED and only ever calls
		// NtResumeProcess AFTER tree.job.Assign has already succeeded, so
		// this payload cannot execute this — or any — instruction until
		// assignment has already completed.
		inJob, err := currentProcessInJob()
		if err != nil {
			os.Exit(5)
		}
		payload := "false\n"
		if inJob {
			payload = "true\n"
		}
		if err := os.WriteFile(os.Getenv(processTreeMarker), []byte(payload), 0o600); err != nil {
			os.Exit(6)
		}
		os.Exit(0)
	}
}

// jobMembershipPayloadCommand builds the self-exec argv the "job-membership"
// TestProcessTreeHelper case above expects, following the same
// env-var-dispatched self-exec convention TestProcessTreeCancellationAndJobClosePreventDelayedGrandchild
// already uses in this file.
func jobMembershipPayloadCommand(marker string) *exec.Cmd {
	// newProcessTree replaces CommandContext's Cancel with whole-Job teardown.
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestProcessTreeHelper$")
	cmd.Env = append(os.Environ(), processTreeHelperMode+"=job-membership", processTreeMarker+"="+marker)
	return cmd
}

// TestProcessTreeWindowsJobBeforeResume is Task 12d's first queued phase-gate
// selector. It proves the restricted backend's suspended-create/Job-before-
// resume ordering directly against a real Windows Job and a real child
// process: the child's own observation of its Job membership, recorded at
// its own first instruction (see the "job-membership" TestProcessTreeHelper
// case above), is itself the proof — not a same-process assertion on
// tree.assigned alone, which only proves this process believes it called
// Assign, not that the child could never have run first.
func TestProcessTreeWindowsJobBeforeResume(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "job-membership-marker")
	cmd := jobMembershipPayloadCommand(marker)

	tree, err := newProcessTree(cmd, processTreeOptions{Sandboxed: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tree.close()

	if err := tree.start(cmd); err != nil {
		t.Fatal(err)
	}
	if !tree.assigned {
		t.Fatal("start returned successfully without ever recording Job assignment")
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("payload exited with an error: %v", err)
	}

	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read payload marker: %v", err)
	}
	if got := strings.TrimSpace(string(data)); got != "true" {
		t.Fatalf("payload observed Job membership %q at its own first instruction; want %q — assignment must precede resume", got, "true")
	}
}

// TestProcessTreeWindowsJobEmptyOnClose is Task 12d's second queued phase-
// gate selector. It proves close is genuinely gated on confirmed Job
// emptiness rather than a fixed grace sleep or a best-effort guess.
// terminateAndWait is the exact zero proof process.go's supervise() /
// process_quarantine.go's spawn.release already require before this tree's
// Job authority is ever released — prover.close() is only ever reached
// after prover.terminateAndWait() has already returned a nil proof error —
// so exercising it directly here against a real Job and a real child is
// what this test asserts, then independently re-queries the Job's own
// active process count before close to confirm "empty" was not merely
// assumed.
func TestProcessTreeWindowsJobEmptyOnClose(t *testing.T) {
	dir := t.TempDir()
	marker := filepath.Join(dir, "job-empty-marker")
	cmd := jobMembershipPayloadCommand(marker)

	tree, err := newProcessTree(cmd, processTreeOptions{Sandboxed: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.start(cmd); err != nil {
		t.Fatal(err)
	}

	terminateErr, proofErr := tree.terminateAndWait()
	if proofErr != nil {
		t.Fatalf("terminateAndWait proof = %v, want nil (Job confirmed empty)", proofErr)
	}
	if terminateErr != nil {
		t.Logf("terminateAndWait termination error (informational; the payload may already have exited on its own before the defensive terminate): %v", terminateErr)
	}
	// The payload already exited (terminateAndWait's proof cannot succeed
	// otherwise), so this only reaps it; ignore a redundant wait error.
	_ = cmd.Wait()

	active, err := tree.job.ActiveProcesses()
	if err != nil {
		t.Fatalf("query Job active process count before close: %v", err)
	}
	if active != 0 {
		t.Fatalf("Job active process count = %d before close, want 0 — terminateAndWait's proof did not actually confirm emptiness", active)
	}

	// close() must not error, hang, or panic once emptiness is genuinely
	// confirmed; it is the exact call spawn.release makes immediately after
	// this same proof succeeds in production.
	tree.close()
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

var procGetConsoleProcessList = winapi.NewLazySystemDLL("kernel32.dll").NewProc("GetConsoleProcessList")

// currentConsoleProcessList is GetConsoleProcessList for this process.
func currentConsoleProcessList() ([]uint32, error) {
	pids := make([]uint32, 64)
	count, _, err := procGetConsoleProcessList.Call(uintptr(unsafe.Pointer(&pids[0])), uintptr(len(pids)))
	if count == 0 {
		return nil, err
	}
	if int(count) > len(pids) {
		return nil, errors.New("console process list exceeds the fixed buffer")
	}
	return pids[:count], nil
}

// TestProcessTreeLaunchFlagsDetachSandboxedPipeSpawns pins H8's
// flag decisions hermetically: a sandboxed pipe-backed launch adds
// DETACHED_PROCESS (no console and no implicit console host), an Unconfined one does not, and a ConPTY
// launch never carries it whatever it inherited.
func TestProcessTreeLaunchFlagsDetachSandboxedPipeSpawns(t *testing.T) {
	base := uint32(winapi.CREATE_SUSPENDED | winapi.CREATE_NEW_PROCESS_GROUP)
	private := pipeLaunchCreationFlags(base, true)
	if private&winapi.DETACHED_PROCESS == 0 || private&(winapi.CREATE_NO_WINDOW|winapi.CREATE_NEW_CONSOLE) != 0 || private&base != base {
		t.Fatalf("sandboxed pipe flags = %#x", private)
	}
	if shared := pipeLaunchCreationFlags(base|winapi.DETACHED_PROCESS, false); shared&winapi.DETACHED_PROCESS != 0 || shared&base != base {
		t.Fatalf("unconfined pipe flags = %#x", shared)
	}
	// A ConPTY launch keeps CREATE_SUSPENDED but drops CREATE_NEW_PROCESS_GROUP,
	// whose root starts with CTRL+C disabled and would make the in-band ^C
	// interrupt a no-op (conPTYLaunchCreationFlags).
	conpty := conPTYLaunchCreationFlags(base | winapi.CREATE_NO_WINDOW | winapi.DETACHED_PROCESS | winapi.CREATE_NEW_CONSOLE)
	if conpty&(winapi.CREATE_NO_WINDOW|winapi.DETACHED_PROCESS|winapi.CREATE_NEW_CONSOLE) != 0 || conpty&winapi.CREATE_NEW_PROCESS_GROUP != 0 || conpty&winapi.CREATE_SUSPENDED == 0 ||
		conpty&winapi.EXTENDED_STARTUPINFO_PRESENT == 0 || conpty&winapi.CREATE_UNICODE_ENVIRONMENT == 0 {
		t.Fatalf("ConPTY flags = %#x", conpty)
	}
	for _, test := range []struct {
		options processTreeOptions
		want    bool
	}{
		{processTreeOptions{Sandboxed: true}, true},
		{processTreeOptions{Sandboxed: true, Supervised: true}, true},
		{processTreeOptions{}, false},
		{processTreeOptions{Supervised: true}, false},
	} {
		tree, err := newProcessTree(exec.Command(os.Args[0], "-test.run=^TestProcessTreeHelper$"), test.options)
		if err != nil {
			t.Fatal(err)
		}
		if tree.privateConsole != test.want {
			t.Errorf("options %+v privateConsole = %v, want %v", test.options, tree.privateConsole, test.want)
		}
		tree.close()
	}
}

// TestProcessTreeSandboxedInterruptIsTypedUnsupported: with a private console
// there is no safe CTRL_BREAK path, so interrupt fails closed with
// ErrProcessSignalUnsupported and never reaches GenerateConsoleCtrlEvent.
func TestProcessTreeSandboxedInterruptIsTypedUnsupported(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessTreeHelper$")
	tree, err := newProcessTree(cmd, processTreeOptions{Sandboxed: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tree.close()
	cmd.Process = &os.Process{Pid: 4}
	if err := tree.sendInterrupt(); !errors.Is(err, ErrProcessSignalUnsupported) {
		t.Fatalf("sandboxed interrupt = %v, want ErrProcessSignalUnsupported", err)
	}
}

// TestProcessTreeSandboxedChildDoesNotShareTheHostConsole proves H8 against
// a real child: GetConsoleProcessList reports ERROR_INVALID_HANDLE because
// the pipe-backed child has no console at all.
func TestProcessTreeSandboxedChildDoesNotShareTheHostConsole(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "console-processes")
	cmd := exec.CommandContext(context.Background(), os.Args[0], "-test.run=^TestProcessTreeHelper$")
	cmd.Env = append(os.Environ(), processTreeHelperMode+"=console-processes", processTreeMarker+"="+marker)
	tree, err := newProcessTree(cmd, processTreeOptions{Sandboxed: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tree.close()
	if err := tree.start(cmd); err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr.CreationFlags&winapi.DETACHED_PROCESS == 0 {
		t.Fatal("sandboxed pipe-backed launch did not detach from the console")
	}
	if err := cmd.Wait(); err != nil {
		data, _ := os.ReadFile(marker)
		t.Fatalf("payload failed: %v (%s)", err, data)
	}
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "no-console\n" {
		t.Fatalf("detached child's console observation = %q, want no-console", data)
	}
}
