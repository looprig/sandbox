//go:build windows

package exec

import (
	"context"
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

const jobCompletionWaitTimeout = 30 * time.Second

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
	// CREATE_NEW_PROCESS_GROUP makes the child's own PID its console process-
	// group ID, distinct from this sandbox's own group: sendInterrupt (below)
	// needs that so a targeted CTRL_BREAK_EVENT reaches only this run's tree,
	// never this process's own console session. It also means a Ctrl+C
	// delivered to the sandbox's own console no longer implicitly reaches a
	// confined child — teardown for this tree is only ever the explicit
	// Job/signal machinery below, exactly as intended.
	cmd.SysProcAttr.CreationFlags |= windows.CREATE_SUSPENDED | windows.CREATE_NEW_PROCESS_GROUP
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

func (tree *processTree) terminateAndWait() (error, error) {
	if tree == nil {
		return nil, nil
	}
	tree.mu.Lock()
	assigned := tree.assigned
	job := tree.job
	tree.mu.Unlock()
	if !assigned || job == nil {
		return nil, nil
	}
	terminateErr := tree.terminate()
	waitCtx, cancel := context.WithTimeout(context.Background(), jobCompletionWaitTimeout)
	defer cancel()
	waitErr := job.WaitActiveProcessesZero(waitCtx)
	return terminateErr, waitErr
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

// sendInterrupt requests cooperative interruption by delivering a
// CTRL_BREAK_EVENT console control event to this run's own process group —
// the closest cooperative-interrupt primitive Windows actually offers.
// Windows has no POSIX-style per-process SIGINT, and CTRL_C_EVENT can only
// ever be broadcast to the caller's own group (group ID 0, which would also
// signal this sandbox process itself); CTRL_BREAK_EVENT against a distinct
// target group ID is the one variant GenerateConsoleCtrlEvent lets a caller
// aim at a specific child tree. newProcessTree creates the child with
// CREATE_NEW_PROCESS_GROUP specifically so its own PID becomes that distinct
// group ID. Like every ProcessSignalInterrupt dispatch, this never itself
// decides the process is terminal — only Process.Wait's own confirmed exit
// does that.
func (tree *processTree) sendInterrupt() error {
	if tree == nil || tree.cmd == nil || tree.cmd.Process == nil {
		return nil
	}
	pid := tree.cmd.Process.Pid
	if pid <= 0 {
		return nil
	}
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(pid))
}

// sendTerminate requests termination. Windows has no distinct graceful-vs-
// forceful signal for a Job-confined process the way Unix has SIGTERM vs
// SIGKILL: the only primitive this tree owns for actually stopping the
// process tree is TerminateJobObject/TerminateProcess (see terminate,
// above), which is unconditionally forceful. Rather than inventing a second,
// weaker mechanism this platform cannot actually back, sendTerminate shares
// the identical primitive sendKill and cmd.Cancel already use. The
// process.go Signal state machine's terminate-then-grace-then-kill
// escalation still behaves correctly on top of this: the process is simply
// already gone well before the grace period elapses, so the eventual
// escalation kill becomes a confirmedTerminal no-op instead of a second live
// dispatch.
func (tree *processTree) sendTerminate() error { return tree.terminate() }

// sendKill force-terminates immediately — the identical primitive
// sendTerminate (above) and cmd.Cancel/terminateAndWait's own defensive kill
// already use, never a second, independently-aimed mechanism.
func (tree *processTree) sendKill() error { return tree.terminate() }

// attachSignaler is the Windows counterpart to lifetime_unix.go's own
// attachSignaler: it wires a freshly constructed Process's Signal seam
// (process.go) to tree, closing Task 12A's fail-closed gap
// (ErrProcessSignalUnsupported) for the Windows restricted async path — the
// last platform this seam needed wiring for. tree always implements
// processSignalTarget (the three methods above), so this assignment is
// unconditional once tree is non-nil. lifetime_other.go's build constraint
// excludes windows so there is exactly one attachSignaler definition per
// platform, never two competing for the same build.
func attachSignaler(proc *Process, tree processTreeBoundary) {
	if proc == nil || tree == nil {
		return
	}
	if signaler, ok := tree.(processSignalTarget); ok {
		proc.signaler = signaler
	}
}
