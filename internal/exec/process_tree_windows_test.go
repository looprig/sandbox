//go:build windows

package exec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

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
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessTreeHelper$")
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
