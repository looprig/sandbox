//go:build windows

package windows

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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

func TestConfigureExplicitHandleListNarrowsWideRegularStandardFiles(t *testing.T) {
	file, err := os.OpenFile(filepath.Join(t.TempDir(), "stdio"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	for _, stream := range []string{"stdin", "stdout", "stderr"} {
		t.Run(stream, func(t *testing.T) {
			cmd := exec.Command("cmd.exe", "/c", "exit 0")
			switch stream {
			case "stdin":
				cmd.Stdin = file
			case "stdout":
				cmd.Stdout = file
			case "stderr":
				cmd.Stderr = file
			}
			cleanup, err := ConfigureExplicitHandleList(cmd, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			var narrow *os.File
			want := uint32(standardOutputAccess)
			switch stream {
			case "stdin":
				narrow = cmd.Stdin.(*os.File)
				want = standardInputAccess
			case "stdout":
				narrow = cmd.Stdout.(*os.File)
			case "stderr":
				narrow = cmd.Stderr.(*os.File)
			}
			if narrow == file {
				t.Fatalf("%s was not replaced", stream)
			}
			assertHandleAccess(t, narrow, want)
			assertHandleNonInheritable(t, narrow)
		})
	}
}

func TestConfigureExplicitHandleListRejectsNonStreamKernelObjects(t *testing.T) {
	tests := []struct {
		name   string
		create func(t *testing.T) winapi.Handle
	}{
		{name: "token", create: func(t *testing.T) winapi.Handle {
			var token winapi.Token
			if err := winapi.OpenProcessToken(winapi.CurrentProcess(), winapi.TOKEN_QUERY, &token); err != nil {
				t.Fatal(err)
			}
			return winapi.Handle(token)
		}},
		{name: "job", create: func(t *testing.T) winapi.Handle {
			job, err := winapi.CreateJobObject(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			return duplicateTestHandle(t, job, 1, func() { _ = winapi.CloseHandle(job) })
		}},
		{name: "event", create: func(t *testing.T) winapi.Handle {
			event, err := winapi.CreateEvent(nil, 1, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			return duplicateTestHandle(t, event, 1, func() { _ = winapi.CloseHandle(event) })
		}},
		{name: "directory", create: func(t *testing.T) winapi.Handle {
			path, err := syscall.UTF16PtrFromString(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			directory, err := winapi.CreateFile(path, winapi.FILE_LIST_DIRECTORY, winapi.FILE_SHARE_READ|winapi.FILE_SHARE_WRITE|winapi.FILE_SHARE_DELETE, nil, winapi.OPEN_EXISTING, winapi.FILE_FLAG_BACKUP_SEMANTICS, 0)
			if err != nil {
				t.Fatal(err)
			}
			return directory
		}},
		{name: "device", create: func(t *testing.T) winapi.Handle {
			path, err := syscall.UTF16PtrFromString("NUL")
			if err != nil {
				t.Fatal(err)
			}
			device, err := winapi.CreateFile(path, winapi.GENERIC_READ, winapi.FILE_SHARE_READ|winapi.FILE_SHARE_WRITE, nil, winapi.OPEN_EXISTING, 0, 0)
			if err != nil {
				t.Fatal(err)
			}
			return device
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handle := tt.create(t)
			file := os.NewFile(uintptr(handle), tt.name)
			if file == nil {
				t.Fatal("os.NewFile returned nil")
			}
			defer file.Close()
			cmd := exec.Command("cmd.exe", "/c", "exit 0")
			cmd.Stdin = file
			if _, err := ConfigureExplicitHandleList(cmd, nil); err == nil {
				t.Fatalf("ConfigureExplicitHandleList accepted %s as stdin", tt.name)
			}
		})
	}
}

func TestConfigureExplicitHandleListNarrowsSuppliedStandardFiles(t *testing.T) {
	stdin, stdinPeer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	defer stdinPeer.Close()
	stdoutPeer, stdout, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdoutPeer.Close()
	defer stdout.Close()

	cmd := exec.Command("cmd.exe", "/c", "exit 0")
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stdout
	cleanup, err := ConfigureExplicitHandleList(cmd, nil)
	if err != nil {
		t.Fatal(err)
	}
	narrowStdin, ok := cmd.Stdin.(*os.File)
	if !ok || narrowStdin == stdin {
		t.Fatal("stdin was not replaced with an owned narrow duplicate")
	}
	narrowStdout, ok := cmd.Stdout.(*os.File)
	if !ok || narrowStdout == stdout {
		t.Fatal("stdout was not replaced with an owned narrow duplicate")
	}
	narrowStderr, ok := cmd.Stderr.(*os.File)
	if !ok || narrowStderr == stdout || narrowStderr == narrowStdout {
		t.Fatal("stderr was not replaced with its own owned narrow duplicate")
	}
	assertHandleAccess(t, narrowStdin, standardInputAccess)
	assertHandleAccess(t, narrowStdout, standardOutputAccess)
	assertHandleAccess(t, narrowStderr, standardOutputAccess)
	assertHandleNonInheritable(t, narrowStdin)
	assertHandleNonInheritable(t, narrowStdout)
	assertHandleNonInheritable(t, narrowStderr)
	stdinDuplicate := winapi.Handle(narrowStdin.Fd())
	stdoutDuplicate := winapi.Handle(narrowStdout.Fd())
	stderrDuplicate := winapi.Handle(narrowStderr.Fd())
	cleanup()
	for name, handle := range map[string]winapi.Handle{
		"stdin duplicate": stdinDuplicate, "stdout duplicate": stdoutDuplicate, "stderr duplicate": stderrDuplicate,
	} {
		if _, err := handleGrantedAccess(handle); err == nil {
			t.Errorf("%s remains open after cleanup", name)
		}
	}
	if _, err := handleGrantedAccess(winapi.Handle(stdin.Fd())); err != nil {
		t.Errorf("cleanup closed caller stdin: %v", err)
	}
	if _, err := handleGrantedAccess(winapi.Handle(stdout.Fd())); err != nil {
		t.Errorf("cleanup closed caller stdout: %v", err)
	}
}

func TestSuppliedStandardFilesHaveExactChildAccess(t *testing.T) {
	helper := buildHandleProbe(t)
	t.Run("pipe", func(t *testing.T) {
		stdin, stdinWriter, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer stdin.Close()
		defer stdinWriter.Close()
		stdoutReader, stdout, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer stdoutReader.Close()
		defer stdout.Close()
		stderrReader, stderr, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer stderrReader.Close()
		defer stderr.Close()

		cmd := exec.Command(helper)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
		cleanup, err := ConfigureExplicitHandleList(cmd, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if _, err := stdinWriter.Write([]byte("stdio-ok")); err != nil {
			t.Fatal(err)
		}
		_ = stdinWriter.Close()
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		cleanup()
		_ = stdout.Close()
		_ = stderr.Close()
		stdoutBytes, err := io.ReadAll(stdoutReader)
		if err != nil {
			t.Fatal(err)
		}
		stderrBytes, err := io.ReadAll(stderrReader)
		if err != nil {
			t.Fatal(err)
		}
		assertProbeStandardAuthority(t, stdoutBytes, stderrBytes)
	})

	t.Run("regular", func(t *testing.T) {
		open := func(name string) *os.File {
			file, err := os.OpenFile(filepath.Join(t.TempDir(), name), os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = file.Close() })
			return file
		}
		stdin := open("stdin")
		stdout := open("stdout")
		stderr := open("stderr")
		if _, err := stdin.WriteString("stdio-ok"); err != nil {
			t.Fatal(err)
		}
		if _, err := stdin.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(helper)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, stdout, stderr
		cleanup, err := ConfigureExplicitHandleList(cmd, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer cleanup()
		if err := cmd.Run(); err != nil {
			t.Fatal(err)
		}
		cleanup()
		if _, err := stdout.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		if _, err := stderr.Seek(0, 0); err != nil {
			t.Fatal(err)
		}
		stdoutBytes, err := io.ReadAll(stdout)
		if err != nil {
			t.Fatal(err)
		}
		stderrBytes, err := io.ReadAll(stderr)
		if err != nil {
			t.Fatal(err)
		}
		assertProbeStandardAuthority(t, stdoutBytes, stderrBytes)
	})
}

func assertProbeStandardAuthority(t *testing.T, stdout, stderr []byte) {
	t.Helper()
	var report probeReport
	if err := json.Unmarshal(stdout, &report); err != nil {
		t.Fatalf("decode handle probe: %v: %q", err, stdout)
	}
	if report.Stdin != "stdio-ok" {
		t.Fatalf("probe stdin = %q, want stdio-ok", report.Stdin)
	}
	if got := string(stderr); got != "stderr-ok\r\n" && got != "stderr-ok\n" {
		t.Fatalf("probe stderr = %q, want stderr-ok", got)
	}
	assertStandardHandleAccess(t, report, standardInputAccess, standardOutputAccess)
}

func duplicateTestHandle(t *testing.T, source winapi.Handle, access uint32, closeSource func()) winapi.Handle {
	t.Helper()
	defer closeSource()
	var duplicate winapi.Handle
	if err := winapi.DuplicateHandle(winapi.CurrentProcess(), source, winapi.CurrentProcess(), &duplicate, access, false, 0); err != nil {
		t.Fatal(err)
	}
	return duplicate
}

func assertHandleAccess(t *testing.T, file *os.File, want uint32) {
	t.Helper()
	got, err := handleGrantedAccess(winapi.Handle(file.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("handle access = %#x, want exact %#x", got, want)
	}
}

func assertHandleNonInheritable(t *testing.T, file *os.File) {
	t.Helper()
	var flags uint32
	if err := readHandleInformation(winapi.Handle(file.Fd()), &flags); err != nil {
		t.Fatal(err)
	}
	if flags&winapi.HANDLE_FLAG_INHERIT != 0 {
		t.Fatalf("owned standard handle %#x is inheritable before Start", file.Fd())
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
	makeNonInheritable(t, source)

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
	assertStandardHandleAccess(t, report, winapi.FILE_GENERIC_READ, winapi.FILE_GENERIC_WRITE)
}

func readHandleInformation(handle winapi.Handle, flags *uint32) error {
	ok, _, callErr := getHandleInformation.Call(uintptr(handle), uintptr(unsafe.Pointer(flags)))
	if ok == 0 {
		return callErr
	}
	return nil
}

type probeReport struct {
	Stdin    string             `json:"stdin"`
	Standard map[string]uintptr `json:"standard"`
	Handles  []struct {
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
	runTwoStageHandleProbe(t, helper)
}

func runTwoStageHandleProbe(t *testing.T, helper string) {
	t.Helper()
	requestRead, requestWrite, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer requestRead.Close()
	makeNonInheritable(t, winapi.Handle(requestRead.Fd()))

	cmd := exec.Command(helper, "runner", "pending")
	cmd.Stdin = strings.NewReader("stdio-ok")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	cleanup, err := ConfigureExplicitHandleList(cmd, []ExplicitHandle{{
		Handle: winapi.Handle(requestRead.Fd()),
		Access: winapi.FILE_READ_DATA,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	requestHandle := uintptr(cmd.SysProcAttr.AdditionalInheritedHandles[0])
	cmd.Args[2] = strconv.FormatUint(uint64(requestHandle), 16)
	if _, err := requestWrite.Write([]byte{0x7f}); err != nil {
		t.Fatal(err)
	}
	if err := requestWrite.Close(); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Run(); err != nil {
		t.Fatalf("run two-stage handle probe: %v: %s", err, stderr.String())
	}

	var report probeReport
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("decode target report: %v: %q", err, stdout.String())
	}
	if report.Stdin != "stdio-ok" {
		t.Fatalf("target stdin = %q, want stdio-ok", report.Stdin)
	}
	if got := stderr.String(); got != "stderr-ok\r\n" && got != "stderr-ok\n" {
		t.Fatalf("target stderr = %q, want stderr-ok", got)
	}
	assertStandardHandleAccess(t, report, standardInputAccess, standardOutputAccess)
	for _, inherited := range report.Handles {
		if inherited.Value == requestHandle {
			t.Fatalf("target has runner request handle value %#x (type=%s access=%#x)", requestHandle, inherited.Type, inherited.Access)
		}
	}
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
	assertStandardHandleAccess(t, report, winapi.FILE_GENERIC_READ, winapi.FILE_GENERIC_WRITE)
	for name, canary := range canaries {
		for _, inherited := range report.Handles {
			if inherited.Value == uintptr(canary) {
				t.Errorf("target inherited %s canary handle %#x (type=%s access=%#x)", name, uintptr(canary), inherited.Type, inherited.Access)
			}
		}
	}
}

func assertStandardHandleAccess(t *testing.T, report probeReport, inputAccess, outputAccess uint32) {
	t.Helper()
	want := map[string]uint32{
		"stdin":  inputAccess,
		"stdout": outputAccess,
		"stderr": outputAccess,
	}
	for name, expected := range want {
		value, ok := report.Standard[name]
		if !ok {
			t.Errorf("target did not report %s handle", name)
			continue
		}
		found := false
		for _, handle := range report.Handles {
			if handle.Value == value {
				found = true
				if handle.Access != expected {
					t.Errorf("target %s access = %#x, want exact %#x", name, handle.Access, expected)
				}
				break
			}
		}
		if !found {
			t.Errorf("target %s handle %#x absent from enumeration", name, value)
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

func makeNonInheritable(t *testing.T, handle winapi.Handle) {
	t.Helper()
	if err := winapi.SetHandleInformation(handle, winapi.HANDLE_FLAG_INHERIT, 0); err != nil {
		t.Fatalf("make handle %#x non-inheritable: %v", uintptr(handle), err)
	}
}
