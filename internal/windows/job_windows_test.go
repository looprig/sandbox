//go:build windows

package windows

import (
	"testing"
	"unsafe"

	winapi "golang.org/x/sys/windows"
)

func TestJobReadbackContainmentAndLimits(t *testing.T) {
	job, err := NewJob(JobOptions{
		Sandboxed:      true,
		MaxProcesses:   7,
		MaxMemoryBytes: 64 << 20,
		MaxCPUPct:      25,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()

	var limits winapi.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if err := winapi.QueryInformationJobObject(
		job.Handle(),
		winapi.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)),
		uint32(unsafe.Sizeof(limits)),
		nil,
	); err != nil {
		t.Fatal(err)
	}
	wantFlags := uint32(winapi.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE |
		winapi.JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
		winapi.JOB_OBJECT_LIMIT_JOB_MEMORY)
	if got := limits.BasicLimitInformation.LimitFlags; got&wantFlags != wantFlags {
		t.Errorf("limit flags = %#x, missing %#x", got, wantFlags&^got)
	}
	breakaway := uint32(winapi.JOB_OBJECT_LIMIT_BREAKAWAY_OK | winapi.JOB_OBJECT_LIMIT_SILENT_BREAKAWAY_OK)
	if got := limits.BasicLimitInformation.LimitFlags; got&breakaway != 0 {
		t.Errorf("limit flags = %#x, breakaway flags must be unset", got)
	}
	if got := limits.BasicLimitInformation.ActiveProcessLimit; got != 7 {
		t.Errorf("active process limit = %d, want 7", got)
	}
	if got := uint64(limits.JobMemoryLimit); got != 64<<20 {
		t.Errorf("job memory limit = %d, want %d", got, uint64(64<<20))
	}

	var cpu jobObjectCPURateControlInformation
	if err := winapi.QueryInformationJobObject(
		job.Handle(),
		winapi.JobObjectCpuRateControlInformation,
		uintptr(unsafe.Pointer(&cpu)),
		uint32(unsafe.Sizeof(cpu)),
		nil,
	); err != nil {
		t.Fatal(err)
	}
	wantCPUFlags := uint32(jobObjectCPURateControlEnable | jobObjectCPURateControlHardCap)
	if cpu.ControlFlags != wantCPUFlags {
		t.Errorf("CPU control flags = %#x, want %#x", cpu.ControlFlags, wantCPUFlags)
	}
	if cpu.CPURate != 2500 {
		t.Errorf("CPU rate = %d, want 2500", cpu.CPURate)
	}
	if !job.ResourceLimitsInstalled() {
		t.Error("requested resource limits were not validated by read-back")
	}
}

func TestJobSandboxedUIRestrictions(t *testing.T) {
	job, err := NewJob(JobOptions{Sandboxed: true})
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()

	var ui winapi.JOBOBJECT_BASIC_UI_RESTRICTIONS
	if err := winapi.QueryInformationJobObject(
		job.Handle(),
		winapi.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)),
		uint32(unsafe.Sizeof(ui)),
		nil,
	); err != nil {
		t.Fatal(err)
	}
	want := uint32(winapi.JOB_OBJECT_UILIMIT_HANDLES |
		winapi.JOB_OBJECT_UILIMIT_DESKTOP |
		winapi.JOB_OBJECT_UILIMIT_GLOBALATOMS |
		winapi.JOB_OBJECT_UILIMIT_READCLIPBOARD |
		winapi.JOB_OBJECT_UILIMIT_WRITECLIPBOARD |
		winapi.JOB_OBJECT_UILIMIT_DISPLAYSETTINGS |
		winapi.JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS |
		winapi.JOB_OBJECT_UILIMIT_EXITWINDOWS)
	if ui.UIRestrictionsClass != want {
		t.Errorf("UI restrictions = %#x, want exactly %#x", ui.UIRestrictionsClass, want)
	}
}

func TestJobUnconfinedHasNoSandboxUIRestrictions(t *testing.T) {
	job, err := NewJob(JobOptions{Sandboxed: false})
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()

	var ui winapi.JOBOBJECT_BASIC_UI_RESTRICTIONS
	if err := winapi.QueryInformationJobObject(
		job.Handle(),
		winapi.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&ui)),
		uint32(unsafe.Sizeof(ui)),
		nil,
	); err != nil {
		t.Fatal(err)
	}
	if ui.UIRestrictionsClass != 0 {
		t.Errorf("unconfined UI restrictions = %#x, want 0", ui.UIRestrictionsClass)
	}
}
