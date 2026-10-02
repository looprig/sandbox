//go:build unix

package exec

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The first Windows CI run (2026-10-02) failed every real synchronous spawn
// the same way: the captured output was complete and correct, yet RunCommand
// returned exit -1 with "close |0: file already closed" after exactly
// outputDrainGrace (~2.03 s). The cause is a parent-side duplicate of the
// output pipe's write end that outlived Start. On Windows the child handle
// list (configureChildHandleList -> internal/windows narrowStandardHandles)
// replaces cmd.Stdout/cmd.Stderr with least-access DUPLICATES the parent owns
// until the returned cleanup runs, and run() deferred that cleanup to spawn
// release — which itself waits for the drain. The drain therefore could never
// observe EOF: the parent was the last writer, waiting on itself, until the
// M10 grace expired.
//
// This test reproduces that exact shape on any Unix host by swapping in a
// handle-list configurator that does what narrowStandardHandles does —
// replace the two output streams with parent-held duplicates released only by
// the cleanup — so the fix (release the duplicates as soon as Start returns)
// is pinned on darwin and Linux CI as well, not only on a Windows runner.
func TestRunReleasesChildHandleListDuplicatesBeforeDraining(t *testing.T) {
	original := configureChildHandleList
	configureChildHandleList = duplicatingChildHandleList(t)
	t.Cleanup(func() { configureChildHandleList = original })

	ws := carveoutWorkspace(t)
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws),
		withBackend(newTestPassthroughBackend()))
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}
	started := time.Now()
	out, code, err := e.RunCommand(context.Background(), ws, "echo drained")
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("RunCommand = %v after %s; a parent-held duplicate of the output write end kept the drain from observing EOF", err, elapsed)
	}
	if code != 0 || !strings.Contains(string(out), "drained") {
		t.Fatalf("RunCommand = code %d output %q, want 0 and the echoed text", code, out)
	}
	// The drain must end by EOF, not by the M10 grace: anything near
	// outputDrainGrace means the duplicates were still open while draining.
	if elapsed >= outputDrainGrace {
		t.Fatalf("RunCommand took %s (>= outputDrainGrace %s): the drain waited out the grace instead of observing EOF", elapsed, outputDrainGrace)
	}
}

// duplicatingChildHandleList mimics internal/windows narrowStandardHandles on
// Unix: every *os.File stream is replaced with a dup the configurator owns,
// and only the returned cleanup closes those dups.
func duplicatingChildHandleList(t *testing.T) func(*exec.Cmd) (func(), error) {
	t.Helper()
	return func(cmd *exec.Cmd) (func(), error) {
		var owned []*os.File
		dup := func(value any) (any, error) {
			file, ok := value.(*os.File)
			if !ok || file == nil {
				return value, nil
			}
			fd, err := syscall.Dup(int(file.Fd()))
			if err != nil {
				return nil, err
			}
			syscall.CloseOnExec(fd)
			duplicate := os.NewFile(uintptr(fd), file.Name()+"-dup")
			owned = append(owned, duplicate)
			return duplicate, nil
		}
		stdout, err := dup(cmd.Stdout)
		if err != nil {
			return nil, err
		}
		stderr, err := dup(cmd.Stderr)
		if err != nil {
			return nil, errors.Join(err, closeAll(owned))
		}
		cmd.Stdout, cmd.Stderr = stdout.(*os.File), stderr.(*os.File)
		return func() { _ = closeAll(owned); owned = nil }, nil
	}
}

func closeAll(files []*os.File) error {
	var err error
	for _, file := range files {
		err = errors.Join(err, file.Close())
	}
	return err
}
