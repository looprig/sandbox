//go:build darwin || linux

package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestExecutorSetCloseRevokesBackgroundDescendant(t *testing.T) {
	for _, commandAccess := range []Access{Allow, Gated} {
		commandAccess := commandAccess
		name := map[Access]string{Allow: "allowed", Gated: "granted"}[commandAccess]
		t.Run(name, func(t *testing.T) {
			workspace := t.TempDir()
			profile := mustProfile(t, ProfileConfig{
				WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
				HostRead: Allow, HostWrite: Deny, Network: Deny, Command: commandAccess,
			})
			set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
				withExecutorSetConfig(withBackend(&captureBackend{
					bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
				})))
			if err != nil {
				t.Fatal(err)
			}
			executor, err := set.For("tree")
			if err != nil {
				t.Fatal(err)
			}

			pidPath := filepath.Join(workspace, "descendant.pid")
			markerPath := filepath.Join(workspace, "descendant.marker")
			command := "(trap '' HUP; sleep 2; printf survived > " + markerPath + ") & printf %s $! > " + pidPath + "; wait"
			var token string
			if commandAccess == Gated {
				now := time.Now()
				token = issueTestGrant(t, executor, now, "tree-revoke", command, workspace,
					"command.execute", "", "command.start.v1", command)
			}
			runDone := make(chan error, 1)
			go func() {
				var runErr error
				if commandAccess == Allow {
					_, _, runErr = executor.RunCommand(context.Background(), workspace, command)
				} else {
					_, _, runErr = executor.RunCommandWithGrants(context.Background(), "tree-revoke", workspace, command, []string{token})
				}
				runDone <- runErr
			}()

			waitForPath(t, pidPath)
			pidBytes, err := os.ReadFile(pidPath)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
			if err != nil || pid <= 0 {
				t.Fatalf("descendant pid = %q: %v", pidBytes, err)
			}

			closeDone := make(chan error, 1)
			go func() { closeDone <- set.Close() }()
			select {
			case err := <-closeDone:
				if err != nil {
					t.Fatalf("Close: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Close hung waiting for a killed background descendant")
			}
			if err := <-runDone; !errors.Is(err, ErrExecutorClosed) && !errors.Is(err, context.Canceled) {
				t.Fatalf("run error = %v, want executor closed or context canceled", err)
			}
			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("Close returned while descendant pid %d remained live: %v", pid, err)
			}
			time.Sleep(2200 * time.Millisecond)
			if _, err := os.Stat(markerPath); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("descendant retained delayed authority after Close: marker stat = %v", err)
			}
		})
	}
}

func TestExecutorContextCancelRevokesBackgroundDescendant(t *testing.T) {
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(&captureBackend{
			bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		})))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("cancel-tree")
	if err != nil {
		t.Fatal(err)
	}

	pidPath := filepath.Join(workspace, "cancel-descendant.pid")
	markerPath := filepath.Join(workspace, "cancel-descendant.marker")
	command := "(trap '' HUP; sleep 2; printf survived > " + markerPath + ") & printf %s $! > " + pidPath + "; wait"
	ctx, cancel := context.WithCancel(context.Background())
	runDone := make(chan error, 1)
	go func() {
		_, _, err := executor.RunCommand(ctx, workspace, command)
		runDone <- err
	}()
	waitForPath(t, pidPath)
	pidBytes, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil || pid <= 0 {
		t.Fatalf("descendant pid = %q: %v", pidBytes, err)
	}

	cancel()
	if err := <-runDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("run error = %v, want context canceled", err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("run returned while canceled descendant pid %d remained live: %v", pid, err)
	}
	time.Sleep(2200 * time.Millisecond)
	if _, err := os.Stat(markerPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("canceled descendant retained delayed authority: marker stat = %v", err)
	}
}

func TestProcessTreeStartFailureDoesNotBlockClose(t *testing.T) {
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(&captureBackend{
			bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		})))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := set.For("start-failure")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := executor.RunArgv(context.Background(), workspace, []string{"/definitely/not/a/sandbox-command"}); err == nil {
		t.Fatal("missing executable unexpectedly started")
	}
	done := make(chan error, 1)
	go func() { done <- set.Close() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Close after start failure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close deadlocked after process-tree start failure")
	}
}
