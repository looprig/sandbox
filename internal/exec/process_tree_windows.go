//go:build windows

package exec

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"

	winjob "github.com/looprig/sandbox/internal/windows"
	"golang.org/x/sys/windows"
)

var ntResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

// processTree owns one Windows Job Object. The Job is fully configured before
// the child is created suspended, assigned before resume, and retained until
// every process in the Job has exited.
type processTree struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	job      *winjob.Job
	assigned bool
}

func newProcessTree(cmd *exec.Cmd, options processTreeOptions) (*processTree, error) {
	if cmd == nil {
		return nil, errors.New("sandbox: nil command process tree")
	}
	limits := options.Limits
	if limits.Disabled {
		limits.MaxPIDs = 0
		limits.MaxMemBytes = 0
		limits.MaxCPUPct = 0
	}
	job, err := winjob.NewJob(winjob.JobOptions{
		Sandboxed:      options.Sandboxed,
		MaxProcesses:   limits.MaxPIDs,
		MaxMemoryBytes: limits.MaxMemBytes,
		MaxCPUPct:      limits.MaxCPUPct,
	})
	if err != nil {
		return nil, err
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED
	tree := &processTree{cmd: cmd, job: job}
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
	var setupErr error
	err := cmd.Process.WithHandle(func(processHandle uintptr) {
		if err := tree.job.Assign(windows.Handle(processHandle)); err != nil {
			setupErr = fmt.Errorf("assign process to job: %w", err)
			return
		}
		tree.mu.Lock()
		tree.assigned = true
		tree.mu.Unlock()
		status, _, callErr := ntResumeProcess.Call(processHandle)
		if status != 0 {
			setupErr = fmt.Errorf("resume job process: NTSTATUS %#x: %v", status, callErr)
		}
	})
	if err != nil && setupErr == nil {
		setupErr = fmt.Errorf("access process handle: %w", err)
	}
	if setupErr == nil {
		return nil
	}
	// The process is still suspended on every setup failure. Terminate it before
	// returning, whether assignment succeeded or not.
	_ = tree.terminate()
	_ = cmd.Wait()
	return fmt.Errorf("sandbox: start process tree: %w", setupErr)
}

func (tree *processTree) terminate() error {
	if tree == nil {
		return nil
	}
	tree.mu.Lock()
	assigned := tree.assigned
	job := tree.job
	cmd := tree.cmd
	tree.mu.Unlock()
	if assigned && job != nil {
		return job.Terminate(1)
	}
	if cmd == nil || cmd.Process == nil {
		return nil
	}
	err := cmd.Process.Kill()
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return nil
	}
	return err
}

func (tree *processTree) terminateAndWait() error {
	if tree == nil {
		return nil
	}
	tree.mu.Lock()
	assigned := tree.assigned
	job := tree.job
	tree.mu.Unlock()
	if !assigned || job == nil {
		return nil
	}
	for {
		// Neither termination nor inspection failure proves that the Job is
		// empty. Retain the Job and execution lease until zero is read back.
		_ = tree.terminate()
		active, err := job.ActiveProcesses()
		if err != nil {
			time.Sleep(time.Millisecond)
			continue
		}
		if active == 0 {
			return nil
		}
		time.Sleep(time.Millisecond)
	}
}

func (tree *processTree) close() {
	if tree == nil {
		return
	}
	tree.mu.Lock()
	job := tree.job
	tree.job = nil
	tree.mu.Unlock()
	if job != nil {
		_ = job.Close()
	}
}
