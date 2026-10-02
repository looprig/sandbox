//go:build windows

package exec

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/looprig/sandbox/internal/enforce"
	winsandbox "github.com/looprig/sandbox/internal/windows"
	"golang.org/x/sys/windows"
)

// TestConPTYLaunchDiagnosticMatrix exists because the first Windows CI run's
// ConPTY failures (no output, an 8m46s hang, and one exit of 0xC0000142
// STATUS_DLL_INIT_FAILED) had more than one candidate cause, and each CI
// iteration costs twenty minutes. It launches the same trivial console
// command through the real openTerminal + start ConPTY path under every
// containment shape the diagnosis turns on and LOGS one line per shape:
//
//   - job-ui-full: the production sandboxed Job, every JOB_OBJECT_UILIMIT_*
//     restriction installed (the shape the production ConPTY tests use).
//   - job-ui-none: a Job with no UI restrictions.
//   - job-ui-minus-handles: the production restrictions without
//     JOB_OBJECT_UILIMIT_HANDLES. The pseudo console's host (conhost.exe) is
//     created by CreatePseudoConsole in THIS process, outside the Job, and
//     UILIMIT_HANDLES forbids a Job member the USER handles of a process
//     outside its Job; if the console attach depends on one, job-ui-full
//     fails while this shape passes.
//   - job-ui-full+restricted-token: the production Job plus a
//     WRITE_RESTRICTED token built exactly like the restricted tier's
//     (CreateRestrictedToken with one fresh executor trustee). The console
//     driver objects the client opens for write are created with this
//     process's default DACL, which names no restricting SID; if a
//     write-restricted client cannot attach, only this shape fails.
//
// Only job-ui-full is asserted: it is the production shape, so a failure
// there fails the production ConPTY tests too and this test adds the
// discriminating evidence. The other shapes are evidence only.
func TestConPTYLaunchDiagnosticMatrix(t *testing.T) {
	const marker = "conpty-probe-ok"
	interpreter := enforce.ShellArgv("")[0]
	if interpreter == "" {
		t.Fatal("system command interpreter could not be resolved")
	}
	shapes := []struct {
		name     string
		ui       func(uint32) uint32
		token    bool
		asserted bool
	}{
		{name: "job-ui-full", ui: func(full uint32) uint32 { return full }, asserted: true},
		{name: "job-ui-none", ui: func(uint32) uint32 { return 0 }},
		{name: "job-ui-minus-handles", ui: func(full uint32) uint32 { return full &^ windows.JOB_OBJECT_UILIMIT_HANDLES }},
		{name: "job-ui-full+restricted-token", ui: func(full uint32) uint32 { return full }, token: true},
	}
	for _, shape := range shapes {
		cmd := exec.Command(interpreter, "/D", "/S", "/C", "echo "+marker)
		cmd.Env = []string{}
		applyShellCommandLine(cmd)
		outcome := runConPTYDiagnosticShape(t, cmd, shape.ui, shape.token, marker)
		t.Logf("ConPTY shape %-30s %s", shape.name, outcome.String())
		if shape.asserted && !outcome.ok() {
			t.Errorf("production ConPTY shape %s failed: %s", shape.name, outcome.String())
		}
	}
}

type conPTYDiagnosticOutcome struct {
	stage    string
	err      error
	uiClass  uint32
	exitCode int
	exited   bool
	output   string
	sawEOF   bool
	marker   string
}

func (outcome conPTYDiagnosticOutcome) ok() bool {
	return outcome.err == nil && outcome.exited && outcome.exitCode == 0 && strings.Contains(outcome.output, outcome.marker)
}

func (outcome conPTYDiagnosticOutcome) String() string {
	if outcome.err != nil {
		return fmt.Sprintf("FAILED at %s (UI %#x): %v", outcome.stage, outcome.uiClass, outcome.err)
	}
	exit := "did not exit within 15s"
	if outcome.exited {
		exit = "exit " + describeExitCode(outcome.exitCode)
	}
	return fmt.Sprintf("UI %#x: %s; marker seen=%v; output EOF after hangup=%v; output=%q",
		outcome.uiClass, exit, strings.Contains(outcome.output, outcome.marker), outcome.sawEOF, truncateForLog(outcome.output, 300))
}

func truncateForLog(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

func runConPTYDiagnosticShape(t *testing.T, cmd *exec.Cmd, ui func(uint32) uint32, restrictedToken bool, marker string) (outcome conPTYDiagnosticOutcome) {
	t.Helper()
	outcome.marker = marker
	fail := func(stage string, err error) conPTYDiagnosticOutcome {
		outcome.stage, outcome.err = stage, err
		return outcome
	}
	tree, err := newProcessTree(cmd, processTreeOptions{Sandboxed: true})
	if err != nil {
		return fail("newProcessTree", err)
	}
	defer tree.close()
	jobHandle := tree.job.Handle()
	var restrictions windows.JOBOBJECT_BASIC_UI_RESTRICTIONS
	if err := windows.QueryInformationJobObject(jobHandle, windows.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&restrictions)), uint32(unsafe.Sizeof(restrictions)), nil); err != nil {
		return fail("query Job UI restrictions", err)
	}
	restrictions.UIRestrictionsClass = ui(restrictions.UIRestrictionsClass)
	if _, err := windows.SetInformationJobObject(jobHandle, windows.JobObjectBasicUIRestrictions,
		uintptr(unsafe.Pointer(&restrictions)), uint32(unsafe.Sizeof(restrictions))); err != nil {
		return fail("set Job UI restrictions", err)
	}
	outcome.uiClass = restrictions.UIRestrictionsClass
	if restrictedToken {
		token, err := diagnosticRestrictedToken()
		if err != nil {
			return fail("build restricted token", err)
		}
		defer token.Close()
		cmd.SysProcAttr.Token = syscall.Token(token)
	}

	terminal, _, err := tree.openTerminal(cmd)
	if err != nil {
		return fail("openTerminal", err)
	}
	conpty := terminal.(*conPTYTerminal)
	defer conpty.Close()
	var output strings.Builder
	var outputMu sync.Mutex
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 4096)
		for {
			n, readErr := conpty.Read(buf)
			if n > 0 {
				outputMu.Lock()
				output.Write(buf[:n])
				outputMu.Unlock()
			}
			if readErr != nil {
				return
			}
		}
	}()
	if err := tree.start(cmd); err != nil {
		return fail("start", err)
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case <-waited:
		outcome.exited = true
		if cmd.ProcessState != nil {
			outcome.exitCode = cmd.ProcessState.ExitCode()
		}
	case <-time.After(15 * time.Second):
		_ = tree.terminate()
		select {
		case <-waited:
		case <-time.After(5 * time.Second):
		}
	}
	conpty.hangupAfterExit()
	select {
	case <-readDone:
		outcome.sawEOF = true
	case <-time.After(10 * time.Second):
	}
	outputMu.Lock()
	outcome.output = output.String()
	outputMu.Unlock()
	return outcome
}

// diagnosticRestrictedToken builds the restricted tier's token shape: the
// current primary token, WRITE_RESTRICTED, with one fresh executor trustee.
// The source handle carries TOKEN_ASSIGN_PRIMARY because CreateRestrictedToken
// returns a handle with the source handle's access, and CreateProcessAsUser
// requires that right.
func diagnosticRestrictedToken() (windows.Token, error) {
	entropy := make([]byte, 16)
	if _, err := rand.Read(entropy); err != nil {
		return 0, err
	}
	sid, err := winsandbox.ExecutorSID("conpty-diagnostic", hex.EncodeToString(entropy))
	if err != nil {
		return 0, err
	}
	var source windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(),
		windows.TOKEN_DUPLICATE|windows.TOKEN_QUERY|windows.TOKEN_ASSIGN_PRIMARY, &source); err != nil {
		return 0, err
	}
	defer source.Close()
	return winsandbox.CreateRestrictedToken(source, []winsandbox.SID{sid})
}
