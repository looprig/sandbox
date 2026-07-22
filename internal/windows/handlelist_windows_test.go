//go:build windows

package windows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	winapi "golang.org/x/sys/windows"
)

var getHandleInformation = winapi.NewLazySystemDLL("kernel32.dll").NewProc("GetHandleInformation")

func TestConfigureExplicitHandleListRejectsInvalidCommand(t *testing.T) {
	if _, err := ConfigureExplicitHandleList(nil, nil); err == nil {
		t.Fatal("ConfigureExplicitHandleList(nil) succeeded")
	}
}

func TestConfigureExplicitHandleListRejectsAmbientHandles(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "exit 0")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		AdditionalInheritedHandles: []syscall.Handle{syscall.Handle(42)},
	}
	if _, err := ConfigureExplicitHandleList(cmd, nil); err == nil {
		t.Fatal("ConfigureExplicitHandleList accepted a preconfigured inherited handle")
	}
}

func TestConfigureExplicitHandleListRejectsPseudoHandles(t *testing.T) {
	cmd := exec.Command("cmd.exe", "/c", "exit 0")
	for _, handle := range []winapi.Handle{
		winapi.CurrentProcess(),
		winapi.CurrentThread(),
		winapi.InvalidHandle,
		0,
	} {
		if _, err := ConfigureExplicitHandleList(cmd, []ExplicitHandle{{Handle: handle, Access: winapi.GENERIC_READ}}); err == nil {
			t.Errorf("ConfigureExplicitHandleList accepted handle %#x", uintptr(handle))
		}
	}
}

func TestConfigureExplicitHandleListRejectsDuplicateSources(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	handle := winapi.Handle(r.Fd())
	cmd := exec.Command("cmd.exe", "/c", "exit 0")
	if _, err := ConfigureExplicitHandleList(cmd, []ExplicitHandle{
		{Handle: handle, Access: winapi.FILE_READ_DATA},
		{Handle: handle, Access: winapi.FILE_READ_DATA},
	}); err == nil {
		t.Fatal("ConfigureExplicitHandleList accepted a duplicate source handle")
	}
}

func TestConfigureExplicitHandleListRejectsWiderAccess(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()

	cmd := exec.Command("cmd.exe", "/c", "exit 0")
	if _, err := ConfigureExplicitHandleList(cmd, []ExplicitHandle{{
		Handle: winapi.Handle(r.Fd()),
		Access: winapi.GENERIC_ALL,
	}}); err == nil {
		t.Fatal("ConfigureExplicitHandleList accepted access wider than the source handle")
	}
}

func TestHandleListDuplicatesOnlyDeclaredMinimumAccess(t *testing.T) {
	helper := buildHandleProbe(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	defer w.Close()
	source := winapi.Handle(r.Fd())

	var sourceFlags uint32
	if err := readHandleInformation(source, &sourceFlags); err != nil {
		t.Fatal(err)
	}
	if sourceFlags&winapi.HANDLE_FLAG_INHERIT != 0 {
		t.Fatal("Go pipe source unexpectedly inheritable")
	}

	cmd := exec.Command(helper)
	cmd.Stdin = strings.NewReader("stdio-ok")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cleanup, err := ConfigureExplicitHandleList(cmd, []ExplicitHandle{{
		Handle: source,
		Access: winapi.FILE_READ_DATA,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got := len(cmd.SysProcAttr.AdditionalInheritedHandles); got != 1 {
		t.Fatalf("AdditionalInheritedHandles = %d, want 1", got)
	}
	duplicate := winapi.Handle(cmd.SysProcAttr.AdditionalInheritedHandles[0])
	if duplicate == source {
		t.Fatal("declared handle was not duplicated")
	}
	var duplicateFlags uint32
	if err := readHandleInformation(duplicate, &duplicateFlags); err != nil {
		t.Fatal(err)
	}
	if duplicateFlags&winapi.HANDLE_FLAG_INHERIT == 0 {
		t.Fatal("declared duplicate is not inheritable")
	}
	if err := readHandleInformation(source, &sourceFlags); err != nil {
		t.Fatal(err)
	}
	if sourceFlags&winapi.HANDLE_FLAG_INHERIT != 0 {
		t.Fatal("declaring a handle changed the source inheritance flag")
	}
	if access, err := handleGrantedAccess(duplicate); err != nil {
		t.Fatal(err)
	} else if access != winapi.FILE_READ_DATA {
		t.Fatalf("duplicate access = %#x, want %#x", access, winapi.FILE_READ_DATA)
	}

	if err := cmd.Run(); err != nil {
		t.Fatalf("run handle probe: %v: %s", err, stderr.String())
	}
	var report probeReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, inherited := range report.Handles {
		if inherited.Value == uintptr(duplicate) {
			found = true
			if inherited.Access != winapi.FILE_READ_DATA {
				t.Errorf("inherited duplicate access = %#x, want %#x", inherited.Access, winapi.FILE_READ_DATA)
			}
		}
	}
	if !found {
		t.Fatalf("declared duplicate %#x was not inherited", uintptr(duplicate))
	}
}

func readHandleInformation(handle winapi.Handle, flags *uint32) error {
	ok, _, callErr := getHandleInformation.Call(uintptr(handle), uintptr(unsafe.Pointer(flags)))
	if ok == 0 {
		return callErr
	}
	return nil
}

type probeReport struct {
	Stdin   string `json:"stdin"`
	Handles []struct {
		Value  uintptr `json:"value"`
		Type   string  `json:"type"`
		Access uint32  `json:"access"`
	} `json:"handles"`
}

func TestInheritedHandleCanariesAreExcluded(t *testing.T) {
	helper := buildHandleProbe(t)
	canaries := createHandleCanaries(t)
	runHandleProbe(t, helper, canaries)
}

func TestHandleListRunnerRequestIsExcludedFromTarget(t *testing.T) {
	helper := buildHandleProbe(t)
	requestRead, requestWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer requestRead.Close()
	defer requestWrite.Close()
	makeInheritable(t, winapi.Handle(requestRead.Fd()))

	// This models the runner retaining a sealed request read handle while it
	// launches the actual target. The target gets only standard streams.
	runHandleProbe(t, helper, map[string]winapi.Handle{
		"sealed-request-read": winapi.Handle(requestRead.Fd()),
	})
}

func buildHandleProbe(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate handle probe source")
	}
	output := filepath.Join(t.TempDir(), "handleprobe.exe")
	cmd := exec.Command("go", "build", "-o", output, "./testdata/handleprobe")
	cmd.Dir = filepath.Dir(source)
	if buildOutput, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build handle probe: %v\n%s", err, buildOutput)
	}
	return output
}

func runHandleProbe(t *testing.T, helper string, canaries map[string]winapi.Handle) {
	t.Helper()
	cmd := exec.Command(helper)
	cmd.Stdin = strings.NewReader("stdio-ok")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cleanup, err := ConfigureExplicitHandleList(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := cmd.Run(); err != nil {
		t.Fatalf("run handle probe: %v: %s", err, stderr.String())
	}

	var report probeReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode handle probe: %v: %q", err, stdout.String())
	}
	if report.Stdin != "stdio-ok" {
		t.Fatalf("probe stdin = %q, want stdio-ok", report.Stdin)
	}
	if got := stderr.String(); got != "stderr-ok\r\n" && got != "stderr-ok\n" {
		t.Fatalf("probe stderr = %q, want stderr-ok", got)
	}
	for name, canary := range canaries {
		for _, inherited := range report.Handles {
			if inherited.Value == uintptr(canary) {
				t.Errorf("target inherited %s canary handle %#x (type=%s access=%#x)", name, uintptr(canary), inherited.Type, inherited.Access)
			}
		}
	}
}

func ExampleConfigureExplicitHandleList() {
	cmd := exec.Command("target.exe")
	cleanup, err := ConfigureExplicitHandleList(cmd, nil)
	if err != nil {
		panic(err)
	}
	defer cleanup()
	fmt.Println(len(cmd.SysProcAttr.AdditionalInheritedHandles))
	// Output: 0
}

func createHandleCanaries(t *testing.T) map[string]winapi.Handle {
	t.Helper()
	result := make(map[string]winapi.Handle)
	add := func(name string, handle winapi.Handle, close func() error) {
		t.Helper()
		makeInheritable(t, handle)
		result[name] = handle
		t.Cleanup(func() { _ = close() })
	}

	file, err := os.OpenFile(filepath.Join(t.TempDir(), "writable"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	add("writable-file", winapi.Handle(file.Fd()), file.Close)

	directoryPath, err := syscall.UTF16PtrFromString(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	directory, err := winapi.CreateFile(directoryPath, winapi.FILE_LIST_DIRECTORY, winapi.FILE_SHARE_READ|winapi.FILE_SHARE_WRITE|winapi.FILE_SHARE_DELETE, nil, winapi.OPEN_EXISTING, winapi.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	add("directory", directory, func() error { return winapi.CloseHandle(directory) })

	job, err := winapi.CreateJobObject(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	add("job", job, func() error { return winapi.CloseHandle(job) })

	var token winapi.Token
	if err := winapi.OpenProcessToken(winapi.CurrentProcess(), winapi.TOKEN_QUERY, &token); err != nil {
		t.Fatal(err)
	}
	add("token", winapi.Handle(token), token.Close)

	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pipeWrite.Close() })
	add("pipe", winapi.Handle(pipeRead.Fd()), pipeRead.Close)

	event, err := winapi.CreateEvent(nil, 1, 0, nil)
	if err != nil {
		t.Fatal(err)
	}
	add("event", event, func() error { return winapi.CloseHandle(event) })
	return result
}

func makeInheritable(t *testing.T, handle winapi.Handle) {
	t.Helper()
	if err := winapi.SetHandleInformation(handle, winapi.HANDLE_FLAG_INHERIT, winapi.HANDLE_FLAG_INHERIT); err != nil {
		t.Fatalf("make handle %#x inheritable: %v", uintptr(handle), err)
	}
}
