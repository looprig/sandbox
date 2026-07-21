//go:build windows

package exec

import (
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ntResumeProcess = windows.NewLazySystemDLL("ntdll.dll").NewProc("NtResumeProcess")

type jobBasicAccounting struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

// processTree owns one Windows Job Object. The child is created suspended,
// assigned to the job, and only then resumed, so it has no opportunity to fork
// outside the tree before job ownership is established.
type processTree struct {
	mu       sync.Mutex
	cmd      *exec.Cmd
	job      windows.Handle
	assigned bool
}

func newProcessTree(cmd *exec.Cmd) (*processTree, error) {
	if cmd == nil {
		return nil, errors.New("sandbox: nil command process tree")
	}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("sandbox: create process job: %w", err)
	}
	limits := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
	); err != nil {
		_ = windows.CloseHandle(job)
		return nil, fmt.Errorf("sandbox: configure process job: %w", err)
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
		if err := windows.AssignProcessToJobObject(tree.job, windows.Handle(processHandle)); err != nil {
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
	if assigned && job != 0 {
		if err := windows.TerminateJobObject(job, 1); err != nil {
			return err
		}
		return nil
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
	if !assigned || job == 0 {
		return nil
	}
	for {
		// Neither termination nor inspection failure proves that the job is
		// empty. Retain the lease and job handle until zero active processes can
		// be verified; the sleep prevents a transient OS failure from busy-looping.
		_ = tree.terminate()
		var accounting jobBasicAccounting
		if err := windows.QueryInformationJobObject(
			job,
			windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&accounting)),
			uint32(unsafe.Sizeof(accounting)),
			nil,
		); err != nil {
			time.Sleep(time.Millisecond)
			continue
		}
		if accounting.ActiveProcesses == 0 {
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
	tree.job = 0
	tree.mu.Unlock()
	if job != 0 {
		_ = windows.CloseHandle(job)
	}
}
