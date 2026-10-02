//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

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
	if _, err := queryJobInformation(job.Handle(), winapi.JobObjectExtendedLimitInformation, &limits); err != nil {
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
	if _, err := queryJobInformation(job.Handle(), winapi.JobObjectCpuRateControlInformation, &cpu); err != nil {
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

// TestJobReadbackSurvivesStackGrowthAtEveryDepth pins the second Windows CI
// run's "Windows Job kill-on-close was not installed" (see
// procSetInformationJobObject, job_windows.go): NewJob is called from fresh
// goroutines whose stacks were first consumed by a sweep of depths, so for
// some depth the goroutine's stack is grown — copied — exactly while a
// Set/QueryInformationJobObject call is in flight. Through the old x/sys
// uintptr wrappers that copy left the kernel writing into the freed stack
// and the read-back seeing the zero value; through setJobInformation /
// queryJobInformation every buffer is on the heap and every depth must
// validate. The options are internal/exec's sandboxed restricted-tier shape
// (UI restrictions plus all three resource limits).
func TestJobReadbackSurvivesStackGrowthAtEveryDepth(t *testing.T) {
	options := JobOptions{Sandboxed: true, MaxProcesses: 3, MaxMemoryBytes: 32 << 20, MaxCPUPct: 50}
	for depth := 0; depth <= 96; depth++ {
		done := make(chan error, 1)
		go consumeStackThen(depth, func() {
			job, err := NewJob(options)
			if err == nil {
				err = job.Close()
			}
			done <- err
		})
		if err := <-done; err != nil {
			t.Fatalf("NewJob after consuming %d stack frames: %v", depth, err)
		}
	}
}

// stackSweepSink keeps consumeStackThen's frame-local array from being
// optimised away.
var stackSweepSink byte

// consumeStackThen recurses depth times through a frame carrying a 96-byte
// array (about 150 bytes a frame), then calls fn: a sweep of depths moves
// the point at which the goroutine's stack first has to grow across every
// call fn makes.
//
//go:noinline
func consumeStackThen(depth int, fn func()) {
	var pad [96]byte
	pad[depth%len(pad)] = byte(depth)
	if depth == 0 {
		fn()
	} else {
		consumeStackThen(depth-1, fn)
	}
	stackSweepSink += pad[(depth*7)%len(pad)]
}

// TestJobReadbackDiagnosticNamesBothSides pins the read-back refusal's
// content: a CI log must show what was requested and what came back.
func TestJobReadbackDiagnosticNamesBothSides(t *testing.T) {
	job, err := NewJob(JobOptions{MaxProcesses: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()
	// Ask the read-back to confirm a limit this Job was not given.
	err = job.validateReadback(JobOptions{MaxProcesses: 2, MaxMemoryBytes: 1 << 20})
	if err == nil {
		t.Fatal("read-back accepted a memory limit the Job was never given")
	}
	for _, want := range []string{
		fmt.Sprintf("requested LimitFlags %#x", requestedJobLimitFlags(JobOptions{MaxProcesses: 2, MaxMemoryBytes: 1 << 20})),
		"read back LimitFlags",
		"bytes returned",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("read-back error %q does not contain %q", err, want)
		}
	}
}

func TestJobSandboxedUIRestrictions(t *testing.T) {
	job, err := NewJob(JobOptions{Sandboxed: true})
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()

	var ui winapi.JOBOBJECT_BASIC_UI_RESTRICTIONS
	if _, err := queryJobInformation(job.Handle(), winapi.JobObjectBasicUIRestrictions, &ui); err != nil {
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
	if _, err := queryJobInformation(job.Handle(), winapi.JobObjectBasicUIRestrictions, &ui); err != nil {
		t.Fatal(err)
	}
	if ui.UIRestrictionsClass != 0 {
		t.Errorf("unconfined UI restrictions = %#x, want 0", ui.UIRestrictionsClass)
	}
}

func TestJobCompletionWaitCloseRaceTerminates(t *testing.T) {
	job, err := NewJob(JobOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	waitDone := make(chan error, 1)
	go func() { waitDone <- job.WaitActiveProcessesZero(ctx) }()
	time.Sleep(10 * time.Millisecond)
	if err := job.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-waitDone:
		if !errors.Is(err, ErrJobCompletionWait) {
			t.Fatalf("wait error = %v, want completion wait failure", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("completion wait deadlocked with Job close")
	}
}
