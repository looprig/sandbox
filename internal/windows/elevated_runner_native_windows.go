//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"unsafe"

	win "golang.org/x/sys/windows"
)

type nativeElevatedRunnerProcessAPI struct{}

func (nativeElevatedRunnerProcessAPI) VerifyHost(path, expected string) error {
	actual, err := hashFile(path)
	if err != nil {
		return err
	}
	if !equalSHA256Hex(actual, expected) {
		return errors.New("installed runner hash mismatch")
	}
	return nil
}

func (nativeElevatedRunnerProcessAPI) VerifyToken(token win.Token) error {
	restricted, err := token.IsRestricted()
	if err != nil || !restricted {
		return errors.Join(errors.New("broker token is not restricted"), err)
	}
	kind, err := tokenUint32Information(token, win.TokenType)
	if err != nil || kind != win.TokenPrimary {
		return errors.Join(errors.New("broker token is not primary"), err)
	}
	return nil
}

func (nativeElevatedRunnerProcessAPI) CreateJob(options JobOptions) (*Job, error) {
	options.Sandboxed = true
	return NewJob(options)
}

func (nativeElevatedRunnerProcessAPI) CreateRequest(request runnerRequest, streams [3]win.Handle) (_ runnerInheritedHandles, err error) {
	frame, err := marshalSealedRunnerRequest(request)
	if err != nil {
		return runnerInheritedHandles{}, err
	}
	var read, write win.Handle
	attributes := win.SecurityAttributes{Length: uint32(unsafe.Sizeof(win.SecurityAttributes{})), InheritHandle: 1}
	if err := win.CreatePipe(&read, &write, &attributes, uint32(len(frame))); err != nil {
		return runnerInheritedHandles{}, err
	}
	defer func() {
		_ = win.CloseHandle(write)
		if err != nil {
			_ = win.CloseHandle(read)
		}
	}()
	if err := win.SetHandleInformation(write, win.HANDLE_FLAG_INHERIT, 0); err != nil {
		return runnerInheritedHandles{}, err
	}
	file := os.NewFile(uintptr(write), "sandbox-runner-request-write")
	if file == nil {
		return runnerInheritedHandles{}, errors.New("wrap runner request write pipe")
	}
	if _, err := io.Copy(file, strings.NewReader(string(frame))); err != nil {
		_ = file.Close()
		write = 0
		return runnerInheritedHandles{}, err
	}
	if err := file.Close(); err != nil {
		write = 0
		return runnerInheritedHandles{}, err
	}
	write = 0

	sources := []struct {
		handle win.Handle
		access uint32
	}{{streams[0], standardInputAccess}, {streams[1], standardOutputAccess}, {streams[2], standardOutputAccess}}
	duplicates := [3]win.Handle{}
	defer func() {
		if err != nil {
			for _, handle := range duplicates {
				if handle != 0 {
					_ = win.CloseHandle(handle)
				}
			}
		}
	}()
	for i, source := range sources {
		if invalidExplicitHandle(source.handle) {
			return runnerInheritedHandles{}, fmt.Errorf("standard handle %d is invalid", i)
		}
		if err := validateStandardHandleObject(([...]string{"stdin", "stdout", "stderr"})[i], source.handle); err != nil {
			return runnerInheritedHandles{}, err
		}
		if err := win.DuplicateHandle(win.CurrentProcess(), source.handle, win.CurrentProcess(), &duplicates[i], source.access, true, 0); err != nil {
			return runnerInheritedHandles{}, err
		}
	}
	result := runnerInheritedHandles{
		Stdin: duplicates[0], Stdout: duplicates[1], Stderr: duplicates[2], Request: read,
	}
	result.close = func() error {
		return errors.Join(win.CloseHandle(result.Stdin), win.CloseHandle(result.Stdout),
			win.CloseHandle(result.Stderr), win.CloseHandle(result.Request))
	}
	return result, nil
}

func (nativeElevatedRunnerProcessAPI) CreateSuspended(token win.Token, host, desktop string, env []string, handles runnerInheritedHandles) (runnerProcessHandles, error) {
	list := []win.Handle{handles.Stdin, handles.Stdout, handles.Stderr, handles.Request}
	for _, handle := range list {
		if invalidExplicitHandle(handle) {
			return runnerProcessHandles{}, errors.New("runner inherited handle list is incomplete")
		}
	}
	attributes, err := win.NewProcThreadAttributeList(1)
	if err != nil {
		return runnerProcessHandles{}, err
	}
	defer attributes.Delete()
	if err := attributes.Update(win.PROC_THREAD_ATTRIBUTE_HANDLE_LIST, unsafe.Pointer(&list[0]), uintptr(len(list))*unsafe.Sizeof(list[0])); err != nil {
		return runnerProcessHandles{}, err
	}
	app, err := win.UTF16PtrFromString(host)
	if err != nil {
		return runnerProcessHandles{}, err
	}
	command, err := win.UTF16PtrFromString(windowsCommandLine([]string{host, "--runner"}))
	if err != nil {
		return runnerProcessHandles{}, err
	}
	desktop16, err := win.UTF16PtrFromString(desktop)
	if err != nil {
		return runnerProcessHandles{}, err
	}
	environment, err := windowsEnvironmentBlock(env)
	if err != nil {
		return runnerProcessHandles{}, err
	}
	startup := win.StartupInfoEx{
		StartupInfo: win.StartupInfo{
			Cb: uint32(unsafe.Sizeof(win.StartupInfoEx{})), Desktop: desktop16,
			Flags: win.STARTF_USESTDHANDLES, StdInput: handles.Stdin,
			StdOutput: handles.Stdout, StdErr: handles.Stderr,
		},
		ProcThreadAttributeList: attributes.List(),
	}
	var process win.ProcessInformation
	err = win.CreateProcessAsUser(token, app, command, nil, nil, true,
		win.CREATE_SUSPENDED|win.CREATE_UNICODE_ENVIRONMENT|win.EXTENDED_STARTUPINFO_PRESENT,
		&environment[0], nil, &startup.StartupInfo, &process)
	if err != nil {
		return runnerProcessHandles{}, err
	}
	return runnerProcessHandles{Process: process.Process, Thread: process.Thread}, nil
}

func windowsEnvironmentBlock(env []string) ([]uint16, error) {
	entries := append([]string(nil), env...)
	seen := make(map[string]struct{}, len(entries))
	for _, entry := range entries {
		name, _, ok := strings.Cut(entry, "=")
		if !ok || name == "" || strings.IndexByte(entry, 0) >= 0 {
			return nil, errors.New("windows sandbox: invalid child environment")
		}
		key := strings.ToLower(name)
		if _, exists := seen[key]; exists {
			return nil, errors.New("windows sandbox: duplicate child environment variable")
		}
		seen[key] = struct{}{}
	}
	slices.SortFunc(entries, func(left, right string) int {
		return strings.Compare(strings.ToLower(left), strings.ToLower(right))
	})
	block := make([]uint16, 0)
	for _, entry := range entries {
		encoded, err := win.UTF16FromString(entry)
		if err != nil {
			return nil, err
		}
		block = append(block, encoded...)
	}
	// CreateProcess requires an additional NUL after the final entry. For an
	// empty environment, retain the canonical double-NUL block.
	block = append(block, 0)
	if len(entries) == 0 {
		block = append(block, 0)
	}
	return block, nil
}

func (nativeElevatedRunnerProcessAPI) Assign(job *Job, process win.Handle) error {
	return job.Assign(process)
}

func (nativeElevatedRunnerProcessAPI) Resume(thread win.Handle) error {
	_, err := win.ResumeThread(thread)
	return err
}

func (nativeElevatedRunnerProcessAPI) WaitProcess(ctx context.Context, process win.Handle) (uint32, error) {
	for {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		status, err := win.WaitForSingleObject(process, 100)
		if err != nil {
			return 0, err
		}
		if status == win.WAIT_OBJECT_0 {
			var code uint32
			err := win.GetExitCodeProcess(process, &code)
			return code, err
		}
	}
}

func (nativeElevatedRunnerProcessAPI) WaitJobEmpty(ctx context.Context, job *Job) error {
	return job.WaitActiveProcessesZero(ctx)
}

func (nativeElevatedRunnerProcessAPI) TerminateProcess(process win.Handle) error {
	if process == 0 {
		return nil
	}
	return win.TerminateProcess(process, 1)
}

func (nativeElevatedRunnerProcessAPI) CloseHandle(handle win.Handle) error {
	if handle == 0 {
		return nil
	}
	return win.CloseHandle(handle)
}

func (nativeElevatedRunnerProcessAPI) CloseToken(token win.Token) error {
	if token == 0 {
		return nil
	}
	return token.Close()
}
