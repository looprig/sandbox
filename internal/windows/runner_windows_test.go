//go:build windows

package windows

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"

	win "golang.org/x/sys/windows"
)

func TestRunnerRequestProtocolCannotCarryAuthorityHandles(t *testing.T) {
	requestType := reflect.TypeOf(runnerRequest{})
	got := make([]string, requestType.NumField())
	for i := range got {
		got[i] = requestType.Field(i).Name
	}
	if want := []string{"Argv", "CWD", "Desktop", "Nonce"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("request authority surface = %v, want only %v", got, want)
	}
}

func validRunnerRequestForTest() runnerRequest {
	request := runnerRequest{
		Argv:    []string{`C:\Program Files\tool.exe`, "literal arg", `%PATH%!value!`},
		CWD:     `C:\work`,
		Desktop: `sandbox-nonce\default`,
	}
	request.Nonce[0] = 1
	return request
}

func TestRunnerRequestCodecRoundTripIsStrictAndLossless(t *testing.T) {
	want := validRunnerRequestForTest()
	encoded, err := marshalRunnerRequest(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeRunnerRequest(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("request = %#v, want %#v", got, want)
	}
}

func TestRunnerRequestRejectsMalformedOversizedAndTrailingFrames(t *testing.T) {
	valid, err := marshalRunnerRequest(validRunnerRequestForTest())
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"empty":       nil,
		"truncated":   valid[:len(valid)-1],
		"trailing":    append(append([]byte(nil), valid...), 0),
		"oversized":   make([]byte, maxRunnerRequestSize+1),
		"wrong magic": append([]byte("BADMAGIC"), valid[8:]...),
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeRunnerRequest(bytes.NewReader(frame)); err == nil {
				t.Fatal("malformed frame accepted")
			}
		})
	}
}

func TestRunnerRequestRejectsMissingNonceShellsAndUnnormalizedPaths(t *testing.T) {
	for name, mutate := range map[string]func(*runnerRequest){
		"nonce":               func(r *runnerRequest) { r.Nonce = [32]byte{} },
		"relative executable": func(r *runnerRequest) { r.Argv[0] = "tool.exe" },
		"unclean cwd":         func(r *runnerRequest) { r.CWD = `C:\work\..\work` },
		"interactive desktop": func(r *runnerRequest) { r.Desktop = `WinSta0\Default` },
		"batch":               func(r *runnerRequest) { r.Argv[0] = `C:\work\build.cmd` },
	} {
		t.Run(name, func(t *testing.T) {
			request := validRunnerRequestForTest()
			mutate(&request)
			if _, err := marshalRunnerRequest(request); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestRunnerAllowsExplicitShellExecutableWithoutInterpretingItsArguments(t *testing.T) {
	for _, executable := range []string{
		`C:\Windows\System32\cmd.exe`,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		`C:\Program Files\PowerShell\7\pwsh.exe`,
	} {
		request := validRunnerRequestForTest()
		request.Argv = []string{executable, `a&b`, `%PATH%`, `!value!`}
		if _, err := marshalRunnerRequest(request); err != nil {
			t.Fatalf("explicit executable %q rejected: %v", executable, err)
		}
	}
}

type trackingRunnerSource struct {
	*bytes.Reader
	closed bool
}

func (source *trackingRunnerSource) Close() error {
	source.closed = true
	return nil
}

type fakeRunnerLauncher struct {
	source *trackingRunnerSource
	got    runnerLaunch
	code   uint32
	err    error
}

func (launcher *fakeRunnerLauncher) Launch(launch runnerLaunch) (uint32, error) {
	if !launcher.source.closed {
		return 0, errors.New("request source remained open at launch")
	}
	launcher.got = launch
	return launcher.code, launcher.err
}

func TestProtectedRunnerClosesRequestBeforeLaunchAndForwardsExitAndStdio(t *testing.T) {
	request := validRunnerRequestForTest()
	frame, err := marshalRunnerRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	source := &trackingRunnerSource{Reader: bytes.NewReader(frame)}
	launcher := &fakeRunnerLauncher{source: source, code: 37}
	runner := protectedRunner{launcher: launcher, nonce: request.Nonce}
	code, err := runner.Run(source, win.Handle(10), win.Handle(11), win.Handle(12))
	if err != nil {
		t.Fatal(err)
	}
	if code != 37 {
		t.Fatalf("exit code = %d, want 37", code)
	}
	if launcher.got.Stdin != 10 || launcher.got.Stdout != 11 || launcher.got.Stderr != 12 {
		t.Fatalf("stdio handles = %d/%d/%d", launcher.got.Stdin, launcher.got.Stdout, launcher.got.Stderr)
	}
	if !reflect.DeepEqual(launcher.got.Argv, request.Argv) ||
		launcher.got.CWD != request.CWD || launcher.got.Desktop != request.Desktop {
		t.Fatalf("launch = %#v, request = %#v", launcher.got, request)
	}
}

func TestProtectedRunnerNeverLaunchesAfterDecodeOrCloseFailure(t *testing.T) {
	source := &trackingRunnerSource{Reader: bytes.NewReader([]byte("bad"))}
	launcher := &fakeRunnerLauncher{source: source}
	nonce := [32]byte{1}
	if _, err := (&protectedRunner{launcher: launcher, nonce: nonce}).Run(source, 1, 2, 3); err == nil {
		t.Fatal("malformed request launched")
	}
	if launcher.got.Argv != nil {
		t.Fatal("launcher called after malformed request")
	}
}

func TestProtectedRunnerRejectsNonceMismatchAfterClosingRequest(t *testing.T) {
	request := validRunnerRequestForTest()
	frame, err := marshalRunnerRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	source := &trackingRunnerSource{Reader: bytes.NewReader(frame)}
	launcher := &fakeRunnerLauncher{source: source}
	different := request.Nonce
	different[1] = 1
	if _, err := (&protectedRunner{launcher: launcher, nonce: different}).Run(source, 1, 2, 3); err == nil {
		t.Fatal("mismatched nonce accepted")
	}
	if !source.closed || launcher.got.Argv != nil {
		t.Fatalf("nonce failure did not close without launch: closed=%v launch=%#v", source.closed, launcher.got)
	}
}

func TestWindowsCommandLineDoesNotInvokeShellExpansion(t *testing.T) {
	line := windowsCommandLine([]string{`C:\Program Files\tool.exe`, `%PATH%`, `!value!`, `a&b`})
	for _, literal := range []string{`%PATH%`, `!value!`, `a&b`} {
		if !strings.Contains(line, literal) {
			t.Fatalf("command line %q lost literal %q", line, literal)
		}
	}
}
