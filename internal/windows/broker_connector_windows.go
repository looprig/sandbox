//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	win "golang.org/x/sys/windows"
)

var procWaitNamedPipeW = win.NewLazySystemDLL("kernel32.dll").NewProc("WaitNamedPipeW")

type brokerServerIdentityVerifier interface {
	Verify(win.Handle, string) error
}

type win32BrokerServerIdentityVerifier struct{}

func (win32BrokerServerIdentityVerifier) Verify(pipe win.Handle, expectedHostPath string) error {
	if pipe == 0 || pipe == win.InvalidHandle || !normalizedAbsoluteWindowsPath(expectedHostPath) {
		return errors.New("windows sandbox: invalid broker server identity request")
	}
	var pid uint32
	if err := win.GetNamedPipeServerProcessId(pipe, &pid); err != nil || pid == 0 {
		return errors.Join(errors.New("windows sandbox: obtain broker server PID"), err)
	}
	process, err := win.OpenProcess(win.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return fmt.Errorf("open broker server process: %w", err)
	}
	defer win.CloseHandle(process)

	var pidAfterOpen uint32
	if err := win.GetNamedPipeServerProcessId(pipe, &pidAfterOpen); err != nil || pidAfterOpen != pid {
		return errors.Join(errors.New("windows sandbox: broker server identity changed"), err)
	}
	var token win.Token
	err = win.OpenProcessToken(process, win.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("open broker server token: %w", err)
	}
	defer token.Close()
	user, err := token.GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil || !equalSIDText(user.User.Sid.String(), "S-1-5-18") {
		return errors.Join(errors.New("windows sandbox: broker server is not LocalSystem"), err)
	}
	image, err := queryBrokerServerImage(process)
	if err != nil {
		return err
	}
	expected, err := filepath.Abs(expectedHostPath)
	if err != nil || !strings.EqualFold(filepath.Clean(image), filepath.Clean(expected)) {
		return errors.Join(errors.New("windows sandbox: broker server image mismatch"), err)
	}
	return nil
}

func queryBrokerServerImage(process win.Handle) (string, error) {
	size := uint32(32768)
	buffer := make([]uint16, size)
	if err := win.QueryFullProcessImageName(process, 0, &buffer[0], &size); err != nil {
		return "", fmt.Errorf("query broker server image: %w", err)
	}
	if size == 0 || int(size) > len(buffer) {
		return "", errors.New("windows sandbox: invalid broker server image")
	}
	return win.UTF16ToString(buffer[:size]), nil
}

func waitNamedPipe(name *uint16, milliseconds uint32) error {
	result, _, callErr := procWaitNamedPipeW.Call(uintptr(unsafe.Pointer(name)), uintptr(milliseconds))
	if result == 0 {
		if callErr != nil && !errors.Is(callErr, win.ERROR_SUCCESS) {
			return callErr
		}
		return errors.New("windows sandbox: WaitNamedPipeW failed")
	}
	return nil
}

func openLocalBrokerPipe(ctx context.Context, pipeName string) (*os.File, error) {
	if ctx == nil {
		return nil, errors.New("windows sandbox: broker connection context is required")
	}
	if !strings.HasPrefix(strings.ToLower(pipeName), `\\.\pipe\`) ||
		len(pipeName) <= len(`\\.\pipe\`) || strings.IndexByte(pipeName, 0) >= 0 {
		return nil, errors.New("windows sandbox: invalid local broker pipe name")
	}
	name, err := win.UTF16PtrFromString(pipeName)
	if err != nil {
		return nil, err
	}
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		handle, err := win.CreateFile(name, win.GENERIC_READ|win.GENERIC_WRITE, 0, nil, win.OPEN_EXISTING, 0, 0)
		if err == nil {
			var mode uint32 = win.PIPE_READMODE_MESSAGE
			if err := win.SetNamedPipeHandleState(handle, &mode, nil, nil); err != nil {
				_ = win.CloseHandle(handle)
				return nil, fmt.Errorf("set broker pipe message mode: %w", err)
			}
			stream := os.NewFile(uintptr(handle), pipeName)
			if stream == nil {
				_ = win.CloseHandle(handle)
				return nil, errors.New("windows sandbox: wrap broker client pipe")
			}
			return stream, nil
		}
		if !errors.Is(err, win.ERROR_PIPE_BUSY) {
			return nil, fmt.Errorf("open broker pipe: %w", err)
		}
		if waitErr := waitNamedPipe(name, 50); waitErr != nil &&
			!errors.Is(waitErr, win.ERROR_SEM_TIMEOUT) && !errors.Is(waitErr, win.ERROR_FILE_NOT_FOUND) {
			return nil, fmt.Errorf("wait for broker pipe: %w", waitErr)
		}
	}
}

// connectAuthenticatedBrokerClient accepts no nonce or authority-bearing
// identity from a caller. The protected runtime configuration supplies both
// names, Windows authenticates the server process behind the connected pipe,
// and only then is the service-selected connection nonce consumed.
func connectAuthenticatedBrokerClient(ctx context.Context, pipeName, expectedHostPath string) (*brokerClient, *pipeBrokerFrameTransport, error) {
	stream, err := openLocalBrokerPipe(ctx, pipeName)
	if err != nil {
		return nil, nil, err
	}
	if err := (win32BrokerServerIdentityVerifier{}).Verify(win.Handle(stream.Fd()), expectedHostPath); err != nil {
		_ = stream.Close()
		return nil, nil, err
	}
	return newBrokerClientFromAuthenticatedStream(stream)
}
