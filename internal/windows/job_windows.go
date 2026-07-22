//go:build windows

package windows

import (
	"errors"
	"fmt"
	"sync"
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

// Job owns one configured Windows Job Object.
type Job struct {
	mu                      sync.Mutex
	handle                  winapi.Handle
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
	job := &Job{handle: handle}
	defer func() {
		if err != nil {
			_ = job.Close()
		}
	}()

	limits := winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	limits.BasicLimitInformation.LimitFlags = winapi.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if options.MaxProcesses > 0 {
		limits.BasicLimitInformation.LimitFlags |= winapi.JOB_OBJECT_LIMIT_ACTIVE_PROCESS
		limits.BasicLimitInformation.ActiveProcessLimit = uint32(options.MaxProcesses)
	}
	if options.MaxMemoryBytes > 0 {
		limits.BasicLimitInformation.LimitFlags |= winapi.JOB_OBJECT_LIMIT_JOB_MEMORY
		limits.JobMemoryLimit = uintptr(options.MaxMemoryBytes)
	}
	if _, err := winapi.SetInformationJobObject(handle, winapi.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits))); err != nil {
		return nil, fmt.Errorf("sandbox: configure Windows Job limits: %w", err)
	}

	if options.Sandboxed {
		ui := winapi.JOBOBJECT_BASIC_UI_RESTRICTIONS{UIRestrictionsClass: sandboxUIRestrictions}
		if _, err := winapi.SetInformationJobObject(handle, winapi.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui))); err != nil {
			return nil, fmt.Errorf("sandbox: configure Windows Job UI restrictions: %w", err)
		}
	}
	if options.MaxCPUPct > 0 {
		cpu := jobObjectCPURateControlInformation{
			ControlFlags: jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap,
			CPURate:      uint32(options.MaxCPUPct * 100),
		}
		if _, err := winapi.SetInformationJobObject(handle, winapi.JobObjectCpuRateControlInformation, uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu))); err != nil {
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

func (job *Job) validateReadback(options JobOptions) error {
	var limits winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := winapi.QueryInformationJobObject(job.handle, winapi.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)), nil); err != nil {
		return fmt.Errorf("sandbox: read back Windows Job limits: %w", err)
	}
	flags := limits.BasicLimitInformation.LimitFlags
	if flags&winapi.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE == 0 {
		return errors.New("sandbox: Windows Job kill-on-close was not installed")
	}
	breakaway := uint32(winapi.JOB_OBJECT_LIMIT_BREAKAWAY_OK | winapi.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
	if flags&breakaway != 0 {
		return fmt.Errorf("sandbox: Windows Job breakaway flags unexpectedly enabled: %#x", flags&breakaway)
	}
	if options.MaxProcesses > 0 && (flags&winapi.JOB_OBJECT_LIMIT_ACTIVE_PROCESS == 0 || limits.BasicLimitInformation.ActiveProcessLimit != uint32(options.MaxProcesses)) {
		return errors.New("sandbox: Windows Job active-process limit read-back mismatch")
	}
	if options.MaxMemoryBytes > 0 && (flags&winapi.JOB_OBJECT_LIMIT_JOB_MEMORY == 0 || uint64(limits.JobMemoryLimit) != uint64(options.MaxMemoryBytes)) {
		return errors.New("sandbox: Windows Job memory limit read-back mismatch")
	}

	var ui winapi.JOBOBJECT_BASIC_UI_RESTRICTIONS
	if err := winapi.QueryInformationJobObject(job.handle, winapi.JobObjectBasicUIRestrictions, uintptr(unsafe.Pointer(&ui)), uint32(unsafe.Sizeof(ui)), nil); err != nil {
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
		if err := winapi.QueryInformationJobObject(job.handle, winapi.JobObjectCpuRateControlInformation, uintptr(unsafe.Pointer(&cpu)), uint32(unsafe.Sizeof(cpu)), nil); err != nil {
			return fmt.Errorf("sandbox: read back Windows Job CPU rate: %w", err)
		}
		wantFlags := uint32(jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap)
		if cpu.ControlFlags != wantFlags || cpu.CPURate != uint32(options.MaxCPUPct*100) {
			return errors.New("sandbox: Windows Job CPU rate read-back mismatch")
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
	if err := winapi.QueryInformationJobObject(job.handle, winapi.JobObjectBasicAccountingInformation, uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil); err != nil {
		return 0, err
	}
	return accounting.ActiveProcesses, nil
}

func (job *Job) Close() error {
	if job == nil {
		return nil
	}
	job.mu.Lock()
	defer job.mu.Unlock()
	if job.handle == 0 {
		return nil
	}
	err := winapi.CloseHandle(job.handle)
	job.handle = 0
	return err
}
