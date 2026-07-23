//go:build windows

package windows

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	win "golang.org/x/sys/windows"
)

type fakeElevatedRunnerAPI struct {
	events       []string
	request      runnerRequest
	createToken  win.Token
	createHost   string
	createDesk   string
	createHandle runnerInheritedHandles
	waitCode     uint32
	waitErr      error
	jobWaitErr   error
	released     bool
}

func (api *fakeElevatedRunnerAPI) event(value string) { api.events = append(api.events, value) }
func (api *fakeElevatedRunnerAPI) VerifyHost(path, hash string) error {
	api.event("verify-host")
	if path == "" || hash == "" {
		return errors.New("missing host")
	}
	return nil
}
func (api *fakeElevatedRunnerAPI) VerifyToken(token win.Token) error {
	api.event("verify-token")
	if token == 0 {
		return errors.New("missing token")
	}
	return nil
}
func (api *fakeElevatedRunnerAPI) CreateDesktop(spec privateDesktopSpec) (*privateDesktop, error) {
	api.event("desktop")
	return &privateDesktop{
		Name: spec.WindowStation + `\` + spec.Desktop,
		api:  fakeElevatedDesktopClose{api: api},
	}, nil
}
func (api *fakeElevatedRunnerAPI) CreateJob(JobOptions) (*Job, error) {
	api.event("job")
	return &Job{}, nil
}
func (api *fakeElevatedRunnerAPI) CreateRequest(request runnerRequest, streams [3]win.Handle) (runnerInheritedHandles, error) {
	api.event("request")
	api.request = request
	if streams != [3]win.Handle{11, 12, 13} {
		return runnerInheritedHandles{}, errors.New("unexpected streams")
	}
	return runnerInheritedHandles{
		Stdin: 21, Stdout: 22, Stderr: 23, Request: 24,
		close: func() error { api.event("close-inherited"); return nil },
	}, nil
}
func (api *fakeElevatedRunnerAPI) CreateSuspended(token win.Token, host, desktop string, env []string, handles runnerInheritedHandles) (runnerProcessHandles, error) {
	api.event("create-suspended")
	api.createToken, api.createHost, api.createDesk, api.createHandle = token, host, desktop, handles
	return runnerProcessHandles{Process: 31, Thread: 32}, nil
}
func (api *fakeElevatedRunnerAPI) Assign(*Job, win.Handle) error {
	api.event("assign")
	return nil
}
func (api *fakeElevatedRunnerAPI) Resume(win.Handle) error {
	api.event("resume")
	return nil
}
func (api *fakeElevatedRunnerAPI) WaitProcess(context.Context, win.Handle) (uint32, error) {
	api.event("wait-process")
	return api.waitCode, api.waitErr
}
func (api *fakeElevatedRunnerAPI) WaitJobEmpty(context.Context, *Job) error {
	api.event("wait-job-empty")
	return api.jobWaitErr
}
func (api *fakeElevatedRunnerAPI) TerminateProcess(win.Handle) error {
	api.event("terminate-process")
	return nil
}
func (api *fakeElevatedRunnerAPI) CloseHandle(handle win.Handle) error {
	switch handle {
	case 32:
		api.event("close-thread")
	case 31:
		api.event("close-process")
	}
	return nil
}
func (api *fakeElevatedRunnerAPI) CloseToken(win.Token) error {
	api.event("close-token")
	return nil
}

type fakeElevatedDesktopClose struct{ api *fakeElevatedRunnerAPI }

func (fakeElevatedDesktopClose) CreateWindowStation(string, *win.SECURITY_DESCRIPTOR) (desktopHandle, error) {
	panic("not used")
}
func (fakeElevatedDesktopClose) CreateDesktop(string, desktopHandle, *win.SECURITY_DESCRIPTOR) (desktopHandle, error) {
	panic("not used")
}
func (fakeElevatedDesktopClose) VerifyProtectedACL(desktopHandle, *win.SECURITY_DESCRIPTOR) error {
	panic("not used")
}
func (close fakeElevatedDesktopClose) CloseWindowStation(desktopHandle) error {
	close.api.event("close-station")
	return nil
}
func (close fakeElevatedDesktopClose) CloseDesktop(desktopHandle) error {
	close.api.event("close-desktop")
	return nil
}

func validElevatedRunnerLaunchForTest(api *fakeElevatedRunnerAPI) elevatedRunnerLaunch {
	return elevatedRunnerLaunch{
		Token: 7, HostPath: `C:\ProgramData\Looprig\slots\one\sandbox-host.exe`,
		HostSHA256: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		Argv:       []string{`C:\work\tool.exe`, "arg"}, CWD: `C:\work`,
		Desktop: privateDesktopSpec{WindowStation: "SandboxStation", Desktop: "SandboxDesktop",
			SecurityDescriptor: &win.SECURITY_DESCRIPTOR{}},
		Stdin: 11, Stdout: 12, Stderr: 13,
		Job:          JobOptions{MaxProcesses: 4, MaxMemoryBytes: 64 << 20, MaxCPUPct: 25},
		ReleaseLease: func() error { api.event("release"); api.released = true; return nil },
	}
}

func TestElevatedRunnerLaunchOrdersAllAuthorityBoundaries(t *testing.T) {
	api := &fakeElevatedRunnerAPI{waitCode: 42}
	launcher, err := newElevatedRunnerLauncher(api)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := launcher.Launch(validElevatedRunnerLaunchForTest(api))
	if err != nil {
		t.Fatal(err)
	}
	wantLaunch := []string{
		"verify-host", "verify-token", "desktop", "job", "request",
		"create-suspended", "close-token", "close-inherited", "assign", "resume",
		"close-thread",
	}
	if !reflect.DeepEqual(api.events, wantLaunch) {
		t.Fatalf("launch events = %v, want %v", api.events, wantLaunch)
	}
	if api.createToken != 7 || api.createHost != `C:\ProgramData\Looprig\slots\one\sandbox-host.exe` ||
		api.createDesk != `SandboxStation\SandboxDesktop` {
		t.Fatalf("create inputs = token %v host %q desktop %q", api.createToken, api.createHost, api.createDesk)
	}
	if nonceIsZero(api.request.Nonce) || api.request.Desktop != api.createDesk ||
		!reflect.DeepEqual(api.request.Argv, []string{`C:\work\tool.exe`, "arg"}) {
		t.Fatalf("sealed request = %#v", api.request)
	}
	code, err := execution.Wait(context.Background())
	if err != nil || code != 42 {
		t.Fatalf("Wait = (%d, %v)", code, err)
	}
	wantAll := append(wantLaunch,
		"wait-process", "wait-job-empty", "release", "close-process",
		"close-desktop", "close-station",
	)
	if !reflect.DeepEqual(api.events, wantAll) {
		t.Fatalf("all events = %v, want %v", api.events, wantAll)
	}
	if !api.released {
		t.Fatal("lease was not released after Job-empty")
	}
	again, err := execution.Wait(context.Background())
	if err != nil || again != 42 || !reflect.DeepEqual(api.events, wantAll) {
		t.Fatalf("idempotent Wait = (%d, %v), events %v", again, err, api.events)
	}
}

func TestElevatedRunnerLaunchRejectsBeforeDesktopAndConsumesToken(t *testing.T) {
	api := &fakeElevatedRunnerAPI{}
	launcher, _ := newElevatedRunnerLauncher(api)
	spec := validElevatedRunnerLaunchForTest(api)
	spec.HostSHA256 = "bad"
	if execution, err := launcher.Launch(spec); err == nil || execution != nil {
		t.Fatal("invalid installed host identity was accepted")
	}
	if want := []string{"close-token"}; !reflect.DeepEqual(api.events, want) {
		t.Fatalf("events = %v, want %v", api.events, want)
	}
}

func TestElevatedRunnerWaitDoesNotReleaseOnUnprovedJobEmpty(t *testing.T) {
	api := &fakeElevatedRunnerAPI{jobWaitErr: errors.New("completion proof unavailable")}
	launcher, _ := newElevatedRunnerLauncher(api)
	execution, err := launcher.Launch(validElevatedRunnerLaunchForTest(api))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := execution.Wait(context.Background()); err == nil {
		t.Fatal("unproved Job emptiness was accepted")
	}
	if api.released {
		t.Fatal("lease released without Job-empty proof")
	}
}

func TestEqualSHA256HexIsExactAndCaseInsensitive(t *testing.T) {
	lower := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	if !equalSHA256Hex(lower, strings.ToUpper(lower)) {
		t.Fatal("equivalent SHA-256 rejected")
	}
	if equalSHA256Hex(lower, lower[:63]+"0") || equalSHA256Hex(lower, lower[:62]) {
		t.Fatal("different SHA-256 accepted")
	}
}
