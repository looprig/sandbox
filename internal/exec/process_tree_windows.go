//go:build windows

package exec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
	"unsafe"

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

	// conPTY, once set by openTerminal (terminal_windows.go), is the pending
	// ConPTY launch start must drive through startConPTY instead of the plain
	// cmd.Start() path below: nil for every ordinary pipe-backed spawn, which
	// continues to use cmd.Start() exactly as it always has. Guarded by mu for
	// consistency with every other field on this type, even though in
	// practice openTerminal (which sets it) and start (which reads it) are
	// always called sequentially, from the same goroutine, by
	// startConfinedTTY (process.go), with no concurrent access to this field
	// from anywhere else at that point.
	conPTY *conPTYPendingLaunch
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
	tree.mu.Lock()
	pending := tree.conPTY
	tree.mu.Unlock()
	if pending != nil {
		// A ConPTY-backed launch cannot go through cmd.Start() at all — see
		// openTerminal's own doc comment (terminal_windows.go) for why —
		// so startConPTY performs the equivalent CreateSuspended -> AssignJob
		// -> Resume sequence itself, composing with this SAME tree.job the
		// plain path below already uses, never a second Job or a second,
		// unconfined containment mechanism.
		return tree.startConPTY(cmd, pending)
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

// conPTYPendingLaunch is what openTerminal (below) hands to start via
// tree.conPTY once it has performed ConPTYStepAllocatePipes and
// ConPTYStepCreatePseudoConsole for real (conpty_launch_plan.go): just
// enough of a ConPTYLaunchPlan's own fields for startConPTY to build and
// validate a full plan recording the whole launch before performing its
// remaining three steps. Everything else startConPTY needs — argv, working
// directory, environment — is read directly from the SAME cmd both
// openTerminal and start already receive, so this type carries nothing else.
type conPTYPendingLaunch struct {
	pipes     ConPTYPipes
	attribute ConPTYAttribute
}

// openTerminal implements processTreeTerminalOpener (process.go): it
// performs ConPTYStepAllocatePipes and ConPTYStepCreatePseudoConsole
// (conpty_launch_plan.go) for real — allocating the two pipe pairs and
// creating the pseudo console — and stashes the result on tree itself
// (rather than returning it directly to its caller the way
// openProcessTerminal does on Unix) so the later start(cmd) call —
// openConfinedTterminal's caller (startConfinedTTY, process.go) always makes
// one on the same cmd afterward, via lease.start — can perform the
// remaining three steps (CreateSuspended, AssignJob, Resume) composing with
// the SAME tree.job this tree already created in newProcessTree, never a
// second Job or a second, unconfined containment mechanism.
//
// This deliberately does NOT itself create, assign, or resume any process:
// doing so here — before lease.start's own linearization check
// (executor_lifecycle.go acquires lifecycle.mu and re-checks lease.ctx) —
// would spawn (and, once resumed, run) a process even if the executor set
// had already begun closing between PrepareProcess and Start, defeating that
// check's whole purpose. Every other platform's openProcessTerminal
// (terminal_unix.go, terminal_other.go) keeps the identical property: it
// only ever allocates a terminal DEVICE, never a process, strictly before
// lease.start's own critical section runs.
//
// A ConPTY-backed launch cannot instead go through the plain cmd.Start()
// path start (above) already uses for a pipe-backed spawn: Go's os/exec has
// no extensibility point for attaching the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE
// attribute CreateProcess needs — syscall.SysProcAttr's Windows fields are
// fixed (HideWindow, CmdLine, CreationFlags, Token, ProcessAttributes,
// ThreadAttributes, NoInheritHandles, AdditionalInheritedHandles,
// ParentProcess), none of them a general "extra ProcThreadAttributeList
// entry" seam — so startConPTY (below) performs the equivalent raw
// CreateProcess call itself instead.
func (tree *processTree) openTerminal(cmd *exec.Cmd) (processTerminal, func() error, error) {
	if tree == nil {
		return nil, nil, errors.New("sandbox: nil ConPTY process tree")
	}
	if err := conPTYProbe(); err != nil {
		return nil, nil, err
	}

	var inRead, inWrite, outRead, outWrite windows.Handle
	if err := windows.CreatePipe(&inRead, &inWrite, nil, 0); err != nil {
		return nil, nil, fmt.Errorf("sandbox: allocate ConPTY input pipe: %w", err)
	}
	if err := windows.CreatePipe(&outRead, &outWrite, nil, 0); err != nil {
		_ = closeConPTYHandles(inRead, inWrite)
		return nil, nil, fmt.Errorf("sandbox: allocate ConPTY output pipe: %w", err)
	}

	var console windows.Handle
	if err := windows.CreatePseudoConsole(defaultConPTYSize, inRead, outWrite, 0, &console); err != nil {
		_ = closeConPTYHandles(inRead, inWrite, outRead, outWrite)
		return nil, nil, fmt.Errorf("sandbox: create pseudo console: %w", err)
	}

	// CreatePseudoConsole has taken what it needs from inRead/outWrite; drop
	// the parent's own copies now, exactly like ConPTYPipes's own doc comment
	// requires (conpty_launch_plan.go) — this happens here, synchronously,
	// rather than via the closeSlave closure this method returns below,
	// because ConPTY (unlike a Unix PTY slave, which the CHILD must still
	// inherit its own copy of via fork before the parent may drop its own)
	// needs nothing further from these two handles once CreatePseudoConsole
	// itself has returned: no child exists yet, and none needs to for this
	// step.
	if err := closeConPTYHandles(inRead, outWrite); err != nil {
		windows.ClosePseudoConsole(console)
		_ = closeConPTYHandles(inWrite, outRead)
		return nil, nil, fmt.Errorf("sandbox: release handed-off ConPTY pipe ends: %w", err)
	}

	tree.mu.Lock()
	tree.conPTY = &conPTYPendingLaunch{
		pipes: ConPTYPipes{
			ConsoleInputRead: uintptr(inRead), ConsoleInputWrite: uintptr(inWrite),
			ConsoleOutputRead: uintptr(outRead), ConsoleOutputWrite: uintptr(outWrite),
		},
		attribute: ConPTYAttribute{PseudoConsoleHandle: uintptr(console)},
	}
	tree.mu.Unlock()

	terminal := &conPTYTerminal{
		console: console,
		input:   os.NewFile(uintptr(inWrite), "sandbox-conpty-input"),
		output:  os.NewFile(uintptr(outRead), "sandbox-conpty-output"),
	}
	// No parent-side handle remains to drop after start(cmd) succeeds — see
	// this method's own doc comment above for why that already happened,
	// synchronously, right after CreatePseudoConsole returned — so the
	// returned closeSlave is a harmless no-op, called at the same point
	// startConfinedTTY (process.go) already calls it for the Unix path.
	return terminal, func() error { return nil }, nil
}

// startConPTY performs a ConPTY-backed launch's remaining three steps —
// ConPTYStepCreateSuspended, ConPTYStepAssignJob, ConPTYStepResume
// (conpty_launch_plan.go) — composing with this SAME tree.job the plain
// cmd.Start()-driven path (start, above) already uses, never a second,
// unconfined containment mechanism. It builds and validates a full
// ConPTYLaunchPlan from pending's already-completed first two steps plus
// this tree's own Job, then — unlike an earlier version of this method,
// which built that plan only to validate its fields and then executed a
// hand-written sequence that merely happened to agree with it — actually
// iterates plan.Steps() and dispatches each one to conPTYLaunch.perform:
// the order actually walked here IS the plan's own returned order, not a
// parallel sequence a future edit could silently desynchronize from it. A
// step reordering would now have to happen inside conpty_launch_plan.go's
// own canonicalConPTYLaunchOrder — guarded by TestConPTYLaunchPlanOrdersJobBeforeResume
// and friends — rather than merely in this file, to change what actually
// executes and in what order.
func (tree *processTree) startConPTY(cmd *exec.Cmd, pending *conPTYPendingLaunch) error {
	jobHandle := tree.job.Handle()
	if jobHandle == 0 {
		return errors.New("sandbox: ConPTY launch has no Windows Job to assign")
	}
	plan, err := NewConPTYLaunchPlan(pending.pipes, pending.attribute, ConPTYJobAssignment{JobHandle: uintptr(jobHandle)}, ConPTYBrokerCredentials{})
	if err != nil {
		return fmt.Errorf("sandbox: build ConPTY launch plan: %w", err)
	}

	launch := &conPTYLaunch{cmd: cmd, tree: tree, pending: pending}
	for _, step := range plan.Steps() {
		if err := launch.perform(step); err != nil {
			return err
		}
	}
	return nil
}

// conPTYLaunch carries the state one ConPTY-backed launch accumulates as
// startConPTY walks plan.Steps() (above): pi is populated by
// ConPTYStepCreateSuspended and consumed by ConPTYStepAssignJob and
// ConPTYStepResume in turn, exactly the "how much state each step needs to
// thread to the next" this type exists to hold so startConPTY's own loop
// body can stay a plain step-to-method dispatch.
type conPTYLaunch struct {
	cmd     *exec.Cmd
	tree    *processTree
	pending *conPTYPendingLaunch

	pi windows.ProcessInformation
}

// perform dispatches one ConPTYLaunchStep to the real Windows call it names.
// The switch's own case order is irrelevant to execution order — that is
// entirely determined by the order startConPTY's loop feeds steps into this
// method, i.e. by plan.Steps() itself — so reordering the cases below (e.g.
// swapping the ConPTYStepAssignJob/ConPTYStepResume bodies' positions in
// this source file) has no effect on what actually runs first; only
// changing the plan's own canonical order does.
func (launch *conPTYLaunch) perform(step ConPTYLaunchStep) error {
	switch step {
	case ConPTYStepAllocatePipes, ConPTYStepCreatePseudoConsole:
		// Already performed, for real, by openTerminal — before this launch's
		// plan even existed — because the actual process creation
		// (ConPTYStepCreateSuspended, below) must not run before lease.start's
		// own linearization check, while pure resource allocation with no
		// process involved yet is safe earlier, exactly like every other
		// platform's openProcessTerminal (see openTerminal's own doc comment).
		// This still walks both steps here, as real, checked steps in the
		// same loop every other step goes through, rather than silently
		// skipping them: a caller that somehow reached this method with
		// invalid pipes/attribute is rejected here, not several steps later
		// against a nonsensical CreateProcess call.
		if !launch.pending.pipes.valid() || !launch.pending.attribute.valid() {
			return errors.New("sandbox: ConPTY launch reached startConPTY with invalid pipes or pseudo-console attribute")
		}
		return nil
	case ConPTYStepCreateSuspended:
		return launch.createSuspended()
	case ConPTYStepAssignJob:
		return launch.assignJob()
	case ConPTYStepResume:
		return launch.resume()
	default:
		return fmt.Errorf("sandbox: ConPTY launch plan produced an unhandled step %v", step)
	}
}

// createSuspended performs ConPTYStepCreateSuspended: builds the raw
// CreateProcess/CreateProcessAsUser call's application path, command line,
// environment block, and PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE attribute list,
// then creates the process CREATE_SUSPENDED — through the caller's own token
// when cmd.SysProcAttr.Token is unset, or through that specific token via
// CreateProcessAsUser when a backend (today: configureRestrictedSpawn,
// internal/windows/backend_windows.go) has set one — recording the result in
// launch.pi for assignJob/resume to consume. See the token dispatch below,
// just before the CreateProcess/CreateProcessAsUser call itself, for why
// both branches must exist rather than only the token-less one.
func (launch *conPTYLaunch) createSuspended() error {
	cmd := launch.cmd
	appPath, err := conPTYApplicationPath(cmd)
	if err != nil {
		return err
	}
	appPath16, err := windows.UTF16PtrFromString(appPath)
	if err != nil {
		return err
	}
	cmdLine, err := conPTYCommandLine(cmd.Args)
	if err != nil {
		return err
	}
	cmdLine16, err := windows.UTF16PtrFromString(cmdLine)
	if err != nil {
		return err
	}
	envBlock, err := conPTYEnvBlock(cmd.Env)
	if err != nil {
		return err
	}
	var dir16 *uint16
	if cmd.Dir != "" {
		dir16, err = windows.UTF16PtrFromString(cmd.Dir)
		if err != nil {
			return err
		}
	}

	attributes, err := windows.NewProcThreadAttributeList(1)
	if err != nil {
		return fmt.Errorf("sandbox: allocate ConPTY process attribute list: %w", err)
	}
	defer attributes.Delete()
	pconsole := conPTYAttributeHandle(launch.pending.attribute)
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE, unsafe.Pointer(&pconsole), unsafe.Sizeof(pconsole)); err != nil {
		return fmt.Errorf("sandbox: attach ConPTY attribute: %w", err)
	}

	// EXTENDED_STARTUPINFO_PRESENT is required for ProcThreadAttributeList to
	// take effect at all; CREATE_UNICODE_ENVIRONMENT is required because
	// envBlock above is UTF-16. cmd.SysProcAttr.CreationFlags already carries
	// CREATE_SUSPENDED | CREATE_NEW_PROCESS_GROUP (newProcessTree, above),
	// exactly like the plain path, preserving sendInterrupt's own
	// CTRL_BREAK_EVENT targeting unchanged for a ConPTY-backed Process too.
	flags := cmd.SysProcAttr.CreationFlags | windows.CREATE_UNICODE_ENVIRONMENT | windows.EXTENDED_STARTUPINFO_PRESENT
	// StartupInfo.Flags deliberately does NOT include STARTF_USESTDHANDLES: a
	// ConPTY-attached child's console I/O routes entirely through the
	// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE attribute above, never through
	// inherited stdio handles — Microsoft's own ConPTY sample code uses the
	// identical bInheritHandles=FALSE, no-STARTF_USESTDHANDLES shape this
	// call mirrors.
	startup := windows.StartupInfoEx{
		StartupInfo:             windows.StartupInfo{Cb: uint32(unsafe.Sizeof(windows.StartupInfoEx{}))},
		ProcThreadAttributeList: attributes.List(),
	}
	// cmd.SysProcAttr.Token, when non-zero, is the restricted token
	// configureRestrictedSpawn (internal/windows/backend_windows.go) already
	// built for this spawn. cmd.Start() would launch through it via
	// CreateProcessAsUser (see syscall.StartProcess, syscall/exec_windows.go:
	// "if sys.Token != 0 { ... CreateProcessAsUser(sys.Token, ...) } else {
	// ... CreateProcess(...) }") — but a ConPTY-backed launch bypasses
	// cmd.Start() entirely (this file's own top-of-file doc comment), so it
	// must reproduce that SAME dispatch itself. Falling through to the
	// token-less CreateProcess below unconditionally — as an earlier version
	// of this method did — would silently launch the child under THIS
	// process's own full token instead of the restricted one: the Job
	// containment would still hold, but the entire token/ACL restriction
	// configureRestrictedSpawn established would be dropped with no error or
	// warning. CreateProcessAsUser takes the identical argument list as
	// CreateProcess with the token prepended; the call below mirrors
	// syscall.StartProcess's own shape exactly, using the same
	// appPath16/cmdLine16/envBlock/dir16/startup values built above either way.
	var pi windows.ProcessInformation
	if cmd.SysProcAttr.Token != 0 {
		err = windows.CreateProcessAsUser(windows.Token(cmd.SysProcAttr.Token), appPath16, cmdLine16, nil, nil, false, flags, &envBlock[0], dir16, &startup.StartupInfo, &pi)
	} else {
		err = windows.CreateProcess(appPath16, cmdLine16, nil, nil, false, flags, &envBlock[0], dir16, &startup.StartupInfo, &pi)
	}
	if err != nil {
		return fmt.Errorf("sandbox: create suspended ConPTY process: %w", err)
	}
	launch.pi = pi
	return nil
}

// assignJob performs ConPTYStepAssignJob: assigns the still-suspended
// process launch.pi.Process (createSuspended, above, always runs first —
// plan.Steps() guarantees ConPTYStepCreateSuspended precedes
// ConPTYStepAssignJob) to launch.tree's own Job. The process is still
// suspended on any failure here, exactly mirroring start's own plain-path
// setup-failure handling above ("The process is still suspended on every
// setup failure...") — terminate it directly, before returning.
func (launch *conPTYLaunch) assignJob() error {
	if err := launch.tree.job.Assign(launch.pi.Process); err != nil {
		_ = windows.TerminateProcess(launch.pi.Process, 1)
		_ = closeConPTYHandles(launch.pi.Thread, launch.pi.Process)
		return fmt.Errorf("sandbox: assign ConPTY process to job: %w", err)
	}
	launch.tree.mu.Lock()
	launch.tree.assigned = true
	launch.tree.mu.Unlock()
	return nil
}

// resume performs ConPTYStepResume: resumes launch.pi.Process, which
// plan.Steps() guarantees was already assigned to launch.tree's Job
// (assignJob, above) — a process must never run a single instruction of its
// own code before it is already contained by its Job, which is exactly why
// ConPTYStepAssignJob is ordered before ConPTYStepResume in the first place.
// On success it also performs the tail bookkeeping the original hand-written
// sequence performed at this same point: closing the now-redundant thread
// handle and wrapping the process into a real *os.Process for
// exec.Cmd.Wait/Process.runWait to reap, both documented in place below.
func (launch *conPTYLaunch) resume() error {
	status, _, callErr := ntResumeProcess.Call(uintptr(launch.pi.Process))
	if status != 0 {
		_ = launch.tree.terminate()
		_ = closeConPTYHandles(launch.pi.Thread, launch.pi.Process)
		return fmt.Errorf("sandbox: resume ConPTY process: NTSTATUS %#x: %v", status, callErr)
	}

	// The process is already resumed and running, correctly Job-confined, by
	// this point — every step below is redundant-handle bookkeeping, not
	// part of establishing that confinement, so a failure here must be
	// folded into best-effort cleanup rather than reported as a launch
	// failure: reporting an error here while the process is already
	// irrevocably running (and, once os.FindProcess below succeeds,
	// abandoning it with no *Process to ever Wait on) would be strictly
	// worse than leaking one redundant OS handle in this sandbox's own
	// process — mirrors the identical principle startConfined's pipe-backed
	// path already applies to its own post-spawn handle-closing failures
	// (process.go: "A failure here is folded into terminal cleanup instead
	// of failing Start: the process is already running under confinement,
	// so it must not be abandoned mid-handoff").
	_ = windows.CloseHandle(launch.pi.Thread)

	// exec.Cmd.Wait (invoked by Process.runWait, process.go) requires
	// cmd.Process to be a real *os.Process; since startConPTY bypassed
	// cmd.Start() entirely, nothing has set it. os.FindProcess opens its OWN
	// fresh handle by PID — there is no public API to wrap launch.pi.Process's
	// already-open handle directly into an *os.Process. This does carry one
	// honestly-disclosed, unavoidable-without-a-private-stdlib-hook race: if
	// the PID were reused by an unrelated process in the vanishingly small
	// window between resume and this call, os.FindProcess would open a
	// handle to the WRONG process. This is the same trade-off any Windows
	// PID-based API carries and is not specific to this method. Unlike the
	// thread handle above, a failure HERE is still a real launch failure —
	// with no *os.Process, Process.runWait's own cmd.Wait() call would find
	// cmd.Process nil and never be able to reap or observe this process at
	// all — so launch.tree.terminate() (the process is already assigned, so
	// this reaches the real Job-based termination, not a bare Process.Kill)
	// really is the right response specifically for this one failure.
	process, err := os.FindProcess(int(launch.pi.ProcessId))
	if err != nil {
		_ = launch.tree.terminate()
		_ = windows.CloseHandle(launch.pi.Process)
		return fmt.Errorf("sandbox: reopen ConPTY process handle: %w", err)
	}
	launch.cmd.Process = process
	// launch.pi.Process is now redundant (os.FindProcess above opened its own
	// handle); closing it is cleanup, not part of the launch — see this
	// method's own comment on the identical thread-handle close above for
	// why a failure here must not be reported as a launch failure once
	// cmd.Process is already set.
	_ = windows.CloseHandle(launch.pi.Process)
	return nil
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
// unconditional once tree is non-nil, EXCEPT for a ConPTY-backed Process
// (tree.conPTY != nil, set by openTerminal — terminal_windows.go), which
// gets conPTYSignaler instead: tree's own sendInterrupt cannot reach a
// ConPTY-attached child at all (see conPTYSignaler's own doc comment,
// terminal_windows.go, for exactly why), so wiring tree directly for that
// case would silently accept an interrupt request this platform cannot
// actually honor for it. lifetime_other.go's build constraint excludes
// windows so there is exactly one attachSignaler definition per platform,
// never two competing for the same build.
func attachSignaler(proc *Process, tree processTreeBoundary) {
	if proc == nil || tree == nil {
		return
	}
	signaler, ok := tree.(processSignalTarget)
	if !ok {
		return
	}
	if concrete, ok := tree.(*processTree); ok {
		concrete.mu.Lock()
		isConPTY := concrete.conPTY != nil
		concrete.mu.Unlock()
		if isConPTY {
			if terminal, ok := proc.terminalCloser.(*conPTYTerminal); ok {
				proc.signaler = conPTYSignaler{terminal: terminal, tree: signaler}
				return
			}
		}
	}
	proc.signaler = signaler
}
