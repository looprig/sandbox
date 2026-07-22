//go:build windows

package exec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
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
	}
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
