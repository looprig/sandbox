//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
	"unsafe"

	winapi "golang.org/x/sys/windows"
)

const (
	jobObjectCPURateControlEnable  = 0x1
	jobObjectCPURateControlHardCap = 0x4

	sandboxUIRestrictions = winapi.JOB_OBJECT_UILIMIT_HANDLES |
		winapi.JOB_OBJECT_UILIMIT_DESKTOP |
		winapi.JOB_OBJECT_UILIMIT_GLOBALATOMS |
		winapi.JOB_OBJECT_UILIMIT_READCLIPBOARD |
		winapi.JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
		winapi.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
		winapi.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
		winapi.JOB_OBJECT_UILIMIT_EXITWINDOWS
)

// JobOptions contains only primitive Job Object policy. Keeping policy package
// types out of this leaf package avoids a dependency cycle.
type JobOptions struct {
	Sandboxed      bool
	MaxProcesses   int
	MaxMemoryBytes int64
	MaxCPUPct      int
}

type jobObjectCPURateControlInformation struct {
	ControlFlags uint32
	CPURate      uint32
}

type jobBasicAccountingInformation struct {
	TotalUserTime             int64
	TotalKernelTime           int64
	ThisPeriodTotalUserTime   int64
	ThisPeriodTotalKernelTime int64
	TotalPageFaultCount       uint32
	TotalProcesses            uint32
	ActiveProcesses           uint32
	TotalTerminatedProcesses  uint32
}

type jobAssociateCompletionPort struct {
	CompletionKey  uintptr
	CompletionPort winapi.Handle
}

// procSetInformationJobObject and procQueryInformationJobObject are called
// through LazyProc.Call (setJobInformation / queryJobInformation, below),
// never through golang.org/x/sys/windows's SetInformationJobObject and
// QueryInformationJobObject wrappers. Those wrappers take the information
// buffer as a bare uintptr, so a caller writes
// uintptr(unsafe.Pointer(&local)) — and that conversion is only safe in the
// argument list of a function the compiler knows about (syscall.SyscallN,
// marked //go:uintptrkeepalive, or LazyProc.Call, marked
// //go:uintptrescapes). The x/sys wrapper is neither: escape analysis keeps
// the buffer on the goroutine's STACK, and the wrapper's own prologue is a
// stack-growth check. When the goroutine's stack is grown (copied) at that
// point, every typed pointer is adjusted but the uintptr is not, so the
// kernel reads the old, freed copy (SetInformationJobObject: usually still
// intact, so it "succeeds") and QueryInformationJobObject WRITES its result
// into the freed copy while the caller's live buffer stays as it was.
//
// That is the second Windows CI run's "Windows Job kill-on-close was not
// installed" in internal/exec, with internal/windows's own Job tests green on
// the same runner and the same options: the two packages reach NewJob at
// different stack depths (internal/exec through newProcessTree), a Windows
// goroutine's first stack is small (_StackSystem reserves 4 KiB of the 8 KiB),
// and -race doubles the stack guard, so the read-back query in internal/exec
// is where the stack first outgrows its initial size. The read-back flags
// were the zero value the caller declared, not anything the kernel wrote. A
// freed stack is reused by the next goroutine, so the same bug is also a
// silent write of up to 144 bytes into an unrelated goroutine's stack.
//
// LazyProc.Call's //go:uintptrescapes makes the compiler move every buffer
// converted in its argument list to the heap (Go's heap never moves) and
// keep it alive for the call, so neither failure is possible through these
// helpers.
var (
	procSetInformationJobObject   = winapi.NewLazySystemDLL("kernel32.dll").NewProc("SetInformationJobObject")
	procQueryInformationJobObject = winapi.NewLazySystemDLL("kernel32.dll").NewProc("QueryInformationJobObject")
)

// setJobInformation is SetInformationJobObject(job, class, info,
// sizeof(*info)). info's pointee is moved to the heap by Call's
// //go:uintptrescapes; see procSetInformationJobObject.
func setJobInformation[T any](job winapi.Handle, class uint32, info *T) error {
	ok, _, callErr := procSetInformationJobObject.Call(uintptr(job), uintptr(class), uintptr(unsafe.Pointer(info)), unsafe.Sizeof(*info))
	if ok == 0 {
		return callErr
	}
	return nil
}

// queryJobInformation is QueryInformationJobObject(job, class, info,
// sizeof(*info), &returned) and reports the byte count the kernel says it
// wrote, for read-back diagnostics. See procSetInformationJobObject for why
// it is not the x/sys wrapper.
func queryJobInformation[T any](job winapi.Handle, class uint32, info *T) (uint32, error) {
	returned := new(uint32)
	ok, _, callErr := procQueryInformationJobObject.Call(uintptr(job), uintptr(class), uintptr(unsafe.Pointer(info)), unsafe.Sizeof(*info), uintptr(unsafe.Pointer(returned)))
	if ok == 0 {
		return 0, callErr
	}
	return *returned, nil
}

// jobReadbackSentinel pre-fills the LimitFlags a read-back query must
// overwrite. No JOB_OBJECT_LIMIT_* combination equals it (it sets bits far
// above JOB_OBJECT_LIMIT_VALID_FLAGS), so finding it after a successful query
// proves the kernel's write did not land in the buffer this process reads —
// the exact stale-pointer failure described at procSetInformationJobObject —
// rather than that Windows dropped a flag.
const jobReadbackSentinel uint32 = 0xA5A5_0000

// Job owns one configured Windows Job Object.
type Job struct {
	mu                      sync.Mutex
	completionMu            sync.Mutex
	handle                  winapi.Handle
	completionPort          winapi.Handle
	completionKey           uintptr
	resourceLimitsInstalled bool
}

// NewJob creates, configures, and reads back a Job before it can receive a
// process. Any setup or validation failure closes the Job.
func NewJob(options JobOptions) (_ *Job, err error) {
	if err := validateJobOptions(options); err != nil {
		return nil, err
	}
	handle, err := winapi.CreateJobObject(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("sandbox: create Windows Job: %w", err)
	}
	job := &Job{handle: handle, completionKey: 1}
	defer func() {
		if err != nil {
			_ = job.Close()
		}
	}()
	completionPort, err := winapi.CreateIoCompletionPort(winapi.InvalidHandle, 0, 0, 1)
	if err != nil {
		return nil, fmt.Errorf("sandbox: create Windows Job completion port: %w", err)
	}
	job.completionPort = completionPort
	association := jobAssociateCompletionPort{
		CompletionKey:  job.completionKey,
		CompletionPort: completionPort,
	}
	if err := setJobInformation(handle, winapi.JobObjectAssociateCompletionPortInformation, &association); err != nil {
		return nil, fmt.Errorf("sandbox: associate Windows Job completion port: %w", err)
	}

	limits := winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = requestedJobLimitFlags(options)
	if options.MaxProcesses > 0 {
		limits.BasicLimitInformation.ActiveProcessLimit = uint32(options.MaxProcesses)
	}
	if options.MaxMemoryBytes > 0 {
		limits.JobMemoryLimit = uintptr(options.MaxMemoryBytes)
	}
	if err := setJobInformation(handle, winapi.JobObjectExtendedLimitInformation, &limits); err != nil {
		return nil, fmt.Errorf("sandbox: configure Windows Job limits: %w", err)
	}

	if options.Sandboxed {
		ui := winapi.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: sandboxUIRestrictions}
		if err := setJobInformation(handle, winapi.JobObjectBasicUIRestrictions, &ui); err != nil {
			return nil, fmt.Errorf("sandbox: configure Windows Job UI restrictions: %w", err)
		}
	}
	if options.MaxCPUPct > 0 {
		cpu := jobObjectCPURateControlInformation{
			ControlFlags: jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
			CPURate:      uint32(options.MaxCPUPct * 100),
		}
		if err := setJobInformation(handle, winapi.JobObjectCpuRateControlInformation, &cpu); err != nil {
			return nil, fmt.Errorf("sandbox: configure Windows Job CPU rate: %w", err)
		}
	}
	if err := job.validateReadback(options); err != nil {
		return nil, err
	}
	job.resourceLimitsInstalled = true
	return job, nil
}

func validateJobOptions(options JobOptions) error {
	if options.MaxProcesses < 0 || uint64(options.MaxProcesses) > uint64(^uint32(0)) {
		return fmt.Errorf("sandbox: invalid Windows Job process limit %d", options.MaxProcesses)
	}
	if options.MaxMemoryBytes < 0 || uint64(options.MaxMemoryBytes) > uint64(^uintptr(0)) {
		return fmt.Errorf("sandbox: invalid Windows Job memory limit %d", options.MaxMemoryBytes)
	}
	if options.MaxCPUPct < 0 || options.MaxCPUPct > 100 {
		return fmt.Errorf("sandbox: invalid Windows Job CPU percentage %d", options.MaxCPUPct)
	}
	return nil
}

// requestedJobLimitFlags is the exact LimitFlags NewJob installs for options:
// kill-on-close always, plus the active-process and job-memory limits when
// requested. validateReadback reports it next to what Windows read back.
func requestedJobLimitFlags(options JobOptions) uint32 {
	flags := uint32(winapi.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
	if options.MaxProcesses > 0 {
		flags |= winapi.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
	}
	if options.MaxMemoryBytes > 0 {
		flags |= winapi.JOB_OBJECT_LIMIT_JOB_MEMORY
	}
	return flags
}

func (job *Job) validateReadback(options JobOptions) error {
	var limits winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	limits.BasicLimitInformation.LimitFlags = jobReadbackSentinel
	returned, err := queryJobInformation(job.handle, winapi.JobObjectExtendedLimitInformation, &limits)
	if err != nil {
		return fmt.Errorf("sandbox: read back Windows Job limits: %w", err)
	}
	flags := limits.BasicLimitInformation.LimitFlags
	// Every read-back refusal names what was requested, what Windows
	// returned and how much it says it wrote, so a CI log alone tells a
	// dropped flag apart from a write that never reached this buffer.
	describe := func(problem string) error {
		sentinel := ""
		if flags == jobReadbackSentinel {
			sentinel = " (the pre-query sentinel survived: the kernel's write did not land in this buffer)"
		}
		return fmt.Errorf("sandbox: %s: requested LimitFlags %#x ActiveProcessLimit %d JobMemoryLimit %d; read back LimitFlags %#x%s ActiveProcessLimit %d JobMemoryLimit %d (%d of %d bytes returned)",
			problem, requestedJobLimitFlags(options), options.MaxProcesses, options.MaxMemoryBytes,
			flags, sentinel, limits.BasicLimitInformation.ActiveProcessLimit, uint64(limits.JobMemoryLimit),
			returned, unsafe.Sizeof(limits))
	}
	if flags == jobReadbackSentinel || flags&winapi.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 {
		return describe("Windows Job kill-on-close was not installed")
	}
	breakaway := uint32(winapi.JOB_OBJECT_LIMIT_BREAKAWAY_OK | winapi.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
	if flags&breakaway != 0 {
		return describe(fmt.Sprintf("Windows Job breakaway flags unexpectedly enabled (%#x)", flags&breakaway))
	}
	if options.MaxProcesses > 0 && (flags&winapi.JOB_OBJECT_LIMIT_ACTIVE_PROCESS == 0 || limits.BasicLimitInformation.ActiveProcessLimit != uint32(options.MaxProcesses)) {
		return describe("Windows Job active-process limit read-back mismatch")
	}
	if options.MaxMemoryBytes > 0 && (flags&winapi.JOB_OBJECT_LIMIT_JOB_MEMORY == 0 || uint64(limits.JobMemoryLimit) != uint64(options.MaxMemoryBytes)) {
		return describe("Windows Job memory limit read-back mismatch")
	}

	var ui winapi.JOBOBJECT_BASIC_UI_RESTRICTIONS
	if _, err := queryJobInformation(job.handle, winapi.JobObjectBasicUIRestrictions, &ui); err != nil {
		return fmt.Errorf("sandbox: read back Windows Job UI restrictions: %w", err)
	}
	wantUI := uint32(0)
	if options.Sandboxed {
		wantUI = sandboxUIRestrictions
	}
	if ui.UIRestrictionsClass != wantUI {
		return fmt.Errorf("sandbox: Windows Job UI restriction read-back mismatch: got %#x want %#x", ui.UIRestrictionsClass, wantUI)
	}
	if options.MaxCPUPct > 0 {
		var cpu jobObjectCPURateControlInformation
		if _, err := queryJobInformation(job.handle, winapi.JobObjectCpuRateControlInformation, &cpu); err != nil {
			return fmt.Errorf("sandbox: read back Windows Job CPU rate: %w", err)
		}
		wantFlags := uint32(jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap)
		if cpu.ControlFlags != wantFlags || cpu.CPURate != uint32(options.MaxCPUPct*100) {
			return fmt.Errorf("sandbox: Windows Job CPU rate read-back mismatch: got flags %#x rate %d, want flags %#x rate %d", cpu.ControlFlags, cpu.CPURate, wantFlags, uint32(options.MaxCPUPct*100))
		}
	}
	return nil
}

// Handle exposes the Job handle for assignment APIs and read-only tests;
// ownership remains with Job.
func (job *Job) Handle() winapi.Handle {
	if job == nil {
		return 0
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	return job.handle
}

// ResourceLimitsInstalled confirms read-back of all requested limits. This is
// not by itself an end-to-end process-boundary guarantee.
func (job *Job) ResourceLimitsInstalled() bool {
	if job == nil {
		return false
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	return job.resourceLimitsInstalled
}

func (job *Job) Assign(process winapi.Handle) error {
	if job == nil || process == 0 {
		return errors.New("sandbox: invalid Windows Job assignment")
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.handle == 0 {
		return errors.New("sandbox: assign process to closed Windows Job")
	}
	return winapi.AssignProcessToJobObject(job.handle, process)
}

func (job *Job) Terminate(exitCode uint32) error {
	if job == nil {
		return nil
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.handle == 0 {
		return nil
	}
	return winapi.TerminateJobObject(job.handle, exitCode)
}

func (job *Job) ActiveProcesses() (uint32, error) {
	if job == nil {
		return 0, errors.New("sandbox: inspect nil Windows Job")
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.handle == 0 {
		return 0, errors.New("sandbox: inspect closed Windows Job")
	}
	var accounting jobBasicAccountingInformation
	if _, err := queryJobInformation(job.handle, winapi.JobObjectBasicAccountingInformation, &accounting); err != nil {
		return 0, err
	}
	return accounting.ActiveProcesses, nil
}

// WaitActiveProcessesZero consumes Job completion notifications until the OS
// reports JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO. The completion port is associated
// before any process can be assigned to this Job, so an early notification
// remains queued until this method reads it.
func (job *Job) WaitActiveProcessesZero(ctx context.Context) error {
	if job == nil {
		return fmt.Errorf("%w: nil Job", ErrJobCompletionWait)
	}
	job.mu.Lock()
	key := job.completionKey
	job.mu.Unlock()
	return waitForJobActiveProcessZero(ctx, key, job.nextCompletion, jobCompletionWaitOptions{})
}

func (job *Job) nextCompletion(timeout time.Duration) jobCompletionEvent {
	job.completionMu.Lock()
	defer job.completionMu.Unlock()
	job.mu.Lock()
	port := job.completionPort
	job.mu.Unlock()
	if port == 0 {
		return jobCompletionEvent{err: errJobCompletionPortClosed}
	}
	milliseconds := timeout.Milliseconds()
	if milliseconds < 1 {
		milliseconds = 1
	}
	if milliseconds > int64(^uint32(0)-1) {
		milliseconds = int64(^uint32(0) - 1)
	}
	var message uint32
	var key uintptr
	var overlapped *winapi.Overlapped
	if err := winapi.GetQueuedCompletionStatus(port, &message, &key, &overlapped, uint32(milliseconds)); err != nil {
		switch {
		case errors.Is(err, winapi.WAIT_TIMEOUT):
			return jobCompletionEvent{err: errJobCompletionPollTimeout}
		case errors.Is(err, winapi.ERROR_ABANDONED_WAIT_0):
			return jobCompletionEvent{err: errJobCompletionPortClosed}
		default:
			return jobCompletionEvent{err: err}
		}
	}
	return jobCompletionEvent{message: message, key: key}
}

func (job *Job) Close() error {
	if job == nil {
		return nil
	}
	job.mu.Lock()
	handle := job.handle
	completionPort := job.completionPort
	job.handle = 0
	job.completionPort = 0
	job.mu.Unlock()
	if handle == 0 && completionPort == 0 {
		return nil
	}
	// Wait for any bounded GetQueuedCompletionStatus call to leave the port
	// before closing its handle. New reads already observe completionPort == 0.
	job.completionMu.Lock()
	defer job.completionMu.Unlock()
	// Close the Job first so kill-on-close remains authoritative until the last
	// possible moment. A concurrent waiter then reports a terminal close error.
	var err error
	if handle != 0 {
		err = errors.Join(err, winapi.CloseHandle(handle))
	}
	if completionPort != 0 {
		err = errors.Join(err, winapi.CloseHandle(completionPort))
	}
	return err
}
