//go:build darwin || linux

package exec

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// processTree owns one dedicated Unix process group. The group ID is the
// immediate child's PID, so cancellation and normal completion can revoke every
// descendant that remains in the run's group before the execution lease ends.
type processTree struct {
	cmd  *exec.Cmd
	pgid int
}

func newProcessTree(cmd *exec.Cmd, _ processTreeOptions) (*processTree, error) {
	if cmd == nil {
		return nil, errors.New("sandbox: nil command process tree")
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	tree := &processTree{cmd: cmd}
	cmd.Cancel = tree.terminate
	return tree, nil
}

func (tree *processTree) start(cmd *exec.Cmd) error {
	if tree == nil || cmd == nil || cmd != tree.cmd {
		return errors.New("sandbox: invalid command process tree")
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	tree.pgid = cmd.Process.Pid
	return nil
}

func (tree *processTree) terminate() error {
	if tree == nil || tree.cmd == nil || tree.cmd.Process == nil {
		return nil
	}
	// cmd.Process is published by exec.Cmd before it starts the context watcher
	// that may call Cancel. The child is configured with Setpgid, so its PID is
	// always the group ID; using it directly avoids sharing tree.pgid with Start.
	pgid := tree.cmd.Process.Pid
	if pgid <= 0 {
		return nil
	}
	err := syscall.Kill(-pgid, syscall.SIGKILL)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

func (tree *processTree) terminateAndWait() error {
	if tree == nil || tree.pgid <= 0 {
		return nil
	}
	for {
		reapProcessGroup(tree.pgid)
		active, err := processGroupActive(tree.pgid)
		if err != nil {
			// Inspection failure is not evidence that the group is gone. Keep the
			// lease and every backing resource live until absence can be verified.
			time.Sleep(time.Millisecond)
			continue
		}
		if !active {
			return nil
		}
		// Cancellation may already have delivered SIGKILL while the group is in
		// the exit transition. Darwin can report EPERM for a redundant kill during
		// that window. No kill error proves absence, so retain authority and retry
		// after inspecting the group again.
		_ = tree.terminate()
		time.Sleep(time.Millisecond)
	}
}

func (tree *processTree) close() {}
