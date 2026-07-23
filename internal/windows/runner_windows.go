//go:build windows

package windows

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unicode/utf8"
	"unsafe"

	win "golang.org/x/sys/windows"
)

const (
	runnerRequestVersion   = uint16(1)
	maxRunnerRequestSize   = 64 << 10
	maxRunnerArgCount      = 256
	maxRunnerStringBytes   = 32 << 10
	objectAttributeInherit = uint32(0x2)
)

var (
	runnerRequestMagic = [8]byte{'S', 'B', 'X', 'R', 'U', 'N', '1', 0}
	errRunnerRequest   = errors.New("windows sandbox: invalid protected runner request")
)

// runnerRequest contains data, not authority. Handles, tokens, Jobs, desktop
// objects and broker state are intentionally unrepresentable in this codec.
type runnerRequest struct {
	Argv    []string
	CWD     string
	Desktop string
	Nonce   [32]byte
}

func marshalRunnerRequest(request runnerRequest) ([]byte, error) {
	if err := validateRunnerRequest(request); err != nil {
		return nil, err
	}
	var payload bytes.Buffer
	payload.Write(runnerRequestMagic[:])
	_ = binary.Write(&payload, binary.LittleEndian, runnerRequestVersion)
	_ = binary.Write(&payload, binary.LittleEndian, uint16(len(request.Argv)))
	if err := writeRunnerString(&payload, request.CWD); err != nil {
		return nil, err
	}
	if err := writeRunnerString(&payload, request.Desktop); err != nil {
		return nil, err
	}
	payload.Write(request.Nonce[:])
	for _, arg := range request.Argv {
		if err := writeRunnerString(&payload, arg); err != nil {
			return nil, err
		}
	}
	if payload.Len() > maxRunnerRequestSize {
		return nil, fmt.Errorf("%w: frame is oversized", errRunnerRequest)
	}
	return payload.Bytes(), nil
}

func marshalSealedRunnerRequest(request runnerRequest) ([]byte, error) {
	frame, err := marshalRunnerRequest(request)
	if err != nil {
		return nil, err
	}
	envelope := make([]byte, 0, len(request.Nonce)+len(frame))
	envelope = append(envelope, request.Nonce[:]...)
	envelope = append(envelope, frame...)
	return envelope, nil
}

func decodeRunnerRequest(source io.Reader) (runnerRequest, error) {
	if source == nil {
		return runnerRequest{}, fmt.Errorf("%w: request source is missing", errRunnerRequest)
	}
	frame, err := io.ReadAll(io.LimitReader(source, maxRunnerRequestSize+1))
	if err != nil {
		return runnerRequest{}, fmt.Errorf("%w: read frame: %v", errRunnerRequest, err)
	}
	if len(frame) > maxRunnerRequestSize {
		return runnerRequest{}, fmt.Errorf("%w: frame is oversized", errRunnerRequest)
	}
	reader := bytes.NewReader(frame)
	var magic [8]byte
	var version, argc uint16
	if _, err := io.ReadFull(reader, magic[:]); err != nil ||
		binary.Read(reader, binary.LittleEndian, &version) != nil ||
		binary.Read(reader, binary.LittleEndian, &argc) != nil ||
		magic != runnerRequestMagic || version != runnerRequestVersion ||
		argc == 0 || int(argc) > maxRunnerArgCount {
		return runnerRequest{}, fmt.Errorf("%w: malformed header", errRunnerRequest)
	}
	request := runnerRequest{}
	if request.CWD, err = readRunnerString(reader); err != nil {
		return runnerRequest{}, err
	}
	if request.Desktop, err = readRunnerString(reader); err != nil {
		return runnerRequest{}, err
	}
	if _, err = io.ReadFull(reader, request.Nonce[:]); err != nil {
		return runnerRequest{}, fmt.Errorf("%w: missing nonce", errRunnerRequest)
	}
	request.Argv = make([]string, argc)
	for i := range request.Argv {
		if request.Argv[i], err = readRunnerString(reader); err != nil {
			return runnerRequest{}, err
		}
	}
	if reader.Len() != 0 {
		return runnerRequest{}, fmt.Errorf("%w: trailing data", errRunnerRequest)
	}
	if err := validateRunnerRequest(request); err != nil {
		return runnerRequest{}, err
	}
	return request, nil
}

func writeRunnerString(writer io.Writer, value string) error {
	if len(value) > maxRunnerStringBytes {
		return fmt.Errorf("%w: string is oversized", errRunnerRequest)
	}
	if err := binary.Write(writer, binary.LittleEndian, uint32(len(value))); err != nil {
		return err
	}
	_, err := io.WriteString(writer, value)
	return err
}

func readRunnerString(reader *bytes.Reader) (string, error) {
	var size uint32
	if err := binary.Read(reader, binary.LittleEndian, &size); err != nil ||
		size > maxRunnerStringBytes || uint64(size) > uint64(reader.Len()) {
		return "", fmt.Errorf("%w: malformed string", errRunnerRequest)
	}
	value := make([]byte, int(size))
	_, _ = io.ReadFull(reader, value)
	if !utf8.Valid(value) {
		return "", fmt.Errorf("%w: string is not UTF-8", errRunnerRequest)
	}
	return string(value), nil
}

func validateRunnerRequest(request runnerRequest) error {
	if len(request.Argv) == 0 || len(request.Argv) > maxRunnerArgCount ||
		nonceIsZero(request.Nonce) || !normalizedAbsoluteWindowsPath(request.CWD) ||
		!validQualifiedDesktop(request.Desktop) {
		return errRunnerRequest
	}
	for _, arg := range request.Argv {
		if len(arg) > maxRunnerStringBytes || strings.IndexByte(arg, 0) >= 0 {
			return errRunnerRequest
		}
	}
	executable := request.Argv[0]
	if !normalizedAbsoluteWindowsPath(executable) {
		return errRunnerRequest
	}
	base := strings.ToLower(filepath.Base(executable))
	ext := strings.ToLower(filepath.Ext(base))
	if ext == ".cmd" || ext == ".bat" {
		return errors.New("windows sandbox: batch files require an implicit shell")
	}
	return nil
}

func nonceIsZero(nonce [32]byte) bool {
	return nonce == [32]byte{}
}

func normalizedAbsoluteWindowsPath(value string) bool {
	return value != "" && len(value) <= maxRunnerStringBytes &&
		strings.IndexByte(value, 0) < 0 && filepath.IsAbs(value) &&
		filepath.Clean(value) == value
}

func validQualifiedDesktop(value string) bool {
	parts := strings.Split(value, `\`)
	return len(parts) == 2 && validDesktopComponent(parts[0]) &&
		validDesktopComponent(parts[1]) && !strings.EqualFold(parts[0], "WinSta0")
}

type runnerRequestSource interface {
	io.Reader
	io.Closer
}

type runnerLaunch struct {
	Argv    []string
	CWD     string
	Desktop string
	Stdin   win.Handle
	Stdout  win.Handle
	Stderr  win.Handle
}

type runnerTargetLauncher interface {
	Launch(runnerLaunch) (uint32, error)
}

type protectedRunner struct {
	launcher runnerTargetLauncher
	nonce    [32]byte
}

// Run consumes and closes the one-shot request source before target creation.
// This ordering makes the request handle unavailable to the target even if a
// launcher implementation is replaced.
func (runner *protectedRunner) Run(source runnerRequestSource, stdin, stdout, stderr win.Handle) (uint32, error) {
	if runner == nil || runner.launcher == nil || source == nil || nonceIsZero(runner.nonce) {
		return 0, errors.New("windows sandbox: protected runner dependencies are incomplete")
	}
	request, decodeErr := decodeRunnerRequest(source)
	closeErr := source.Close()
	if decodeErr != nil || closeErr != nil {
		return 0, errors.Join(decodeErr, closeErr)
	}
	if subtle.ConstantTimeCompare(request.Nonce[:], runner.nonce[:]) != 1 {
		return 0, errors.New("windows sandbox: protected runner nonce mismatch")
	}
	return runner.launcher.Launch(runnerLaunch{
		Argv: append([]string(nil), request.Argv...), CWD: request.CWD,
		Desktop: request.Desktop, Stdin: stdin, Stdout: stdout, Stderr: stderr,
	})
}

type nativeRunnerLauncher struct{}

// RunInstalledProtectedRunner runs the installed host's sealed runner entry
// mode. The entry mode deliberately accepts no handle values, nonces, paths, or
// other authority-bearing inputs through argv or the environment. Its launcher
// must provide exactly the three standard streams and one additional,
// inheritable, read-only anonymous-pipe handle through a Windows
// PROC_THREAD_ATTRIBUTE_HANDLE_LIST.
//
// The sealed pipe starts with a second copy of the request nonce followed by the
// runner request frame. Keeping the envelope nonce outside the frame catches
// truncation and cross-wiring while the inherited pipe remains the capability
// that authorizes this one launch.
func RunInstalledProtectedRunner() (uint32, error) {
	source, err := openSealedRunnerRequest()
	if err != nil {
		return 0, err
	}
	var expectedNonce [32]byte
	if _, err := io.ReadFull(source, expectedNonce[:]); err != nil {
		return 0, errors.Join(
			fmt.Errorf("windows sandbox: read protected runner envelope: %w", err),
			source.Close(),
		)
	}
	if nonceIsZero(expectedNonce) {
		return 0, errors.Join(
			errors.New("windows sandbox: protected runner envelope has an empty nonce"),
			source.Close(),
		)
	}
	return (&protectedRunner{
		launcher: &nativeRunnerLauncher{},
		nonce:    expectedNonce,
	}).Run(source, win.Handle(os.Stdin.Fd()), win.Handle(os.Stdout.Fd()), win.Handle(os.Stderr.Fd()))
}

func openSealedRunnerRequest() (*os.File, error) {
	standard := make(map[uintptr]struct{}, 3)
	for _, id := range []uint32{win.STD_INPUT_HANDLE, win.STD_OUTPUT_HANDLE, win.STD_ERROR_HANDLE} {
		handle, err := win.GetStdHandle(id)
		if err != nil || invalidExplicitHandle(handle) {
			return nil, errors.Join(
				fmt.Errorf("windows sandbox: inspect protected runner standard handle %#x", id),
				err,
			)
		}
		standard[uintptr(handle)] = struct{}{}
	}
	entries, err := currentProcessSystemHandles()
	if err != nil {
		return nil, fmt.Errorf("windows sandbox: enumerate protected runner handles: %w", err)
	}
	var candidate win.Handle
	for _, entry := range entries {
		if entry.HandleAttributes&objectAttributeInherit == 0 {
			continue
		}
		if _, ok := standard[entry.HandleValue]; ok {
			continue
		}
		handle := win.Handle(entry.HandleValue)
		if candidate != 0 || !isSealedRunnerRequestHandle(handle, entry.GrantedAccess) {
			return nil, errors.New("windows sandbox: protected runner inherited handle set is not sealed")
		}
		candidate = handle
	}
	if candidate == 0 {
		return nil, errors.New("windows sandbox: protected runner request handle is missing")
	}
	if err := win.SetHandleInformation(candidate, win.HANDLE_FLAG_INHERIT, 0); err != nil {
		return nil, fmt.Errorf("windows sandbox: make protected runner request non-inheritable: %w", err)
	}
	source := os.NewFile(uintptr(candidate), "sandbox-sealed-runner-request")
	if source == nil {
		_ = win.CloseHandle(candidate)
		return nil, errors.New("windows sandbox: wrap protected runner request handle")
	}
	return source, nil
}

func currentProcessSystemHandles() ([]systemHandleEntry, error) {
	buffer := make([]byte, 64<<10)
	for {
		var needed uint32
		status, _, _ := ntQuerySystemInformation.Call(
			systemExtendedHandleInformation,
			uintptr(unsafe.Pointer(&buffer[0])),
			uintptr(len(buffer)),
			uintptr(unsafe.Pointer(&needed)),
		)
		if uint32(status) == statusInfoLengthMismatch {
			buffer = make([]byte, int(needed)+(64<<10))
			continue
		}
		if status != 0 {
			return nil, fmt.Errorf("NtQuerySystemInformation: NTSTATUS %#x", uint32(status))
		}
		break
	}
	count := *(*uintptr)(unsafe.Pointer(&buffer[0]))
	headerSize := 2 * unsafe.Sizeof(uintptr(0))
	entrySize := unsafe.Sizeof(systemHandleEntry{})
	pid := uintptr(os.Getpid())
	result := make([]systemHandleEntry, 0, 8)
	for i := uintptr(0); i < count; i++ {
		offset := headerSize + i*entrySize
		if offset+entrySize > uintptr(len(buffer)) {
			return nil, errors.New("truncated system handle table")
		}
		entry := *(*systemHandleEntry)(unsafe.Pointer(&buffer[offset]))
		if entry.UniqueProcessID == pid {
			result = append(result, entry)
		}
	}
	return result, nil
}

func isSealedRunnerRequestHandle(handle win.Handle, granted uint32) bool {
	if invalidExplicitHandle(handle) || granted != standardInputAccess {
		return false
	}
	typeName, err := handleObjectType(handle)
	if err != nil || typeName != "File" {
		return false
	}
	fileType, err := win.GetFileType(handle)
	return err == nil && fileType&^win.FILE_TYPE_REMOTE == win.FILE_TYPE_PIPE
}

func (*nativeRunnerLauncher) Launch(launch runnerLaunch) (uint32, error) {
	request := runnerRequest{Argv: launch.Argv, CWD: launch.CWD, Desktop: launch.Desktop, Nonce: [32]byte{1}}
	if err := validateRunnerRequest(request); err != nil {
		return 0, err
	}
	sources := []struct {
		handle win.Handle
		access uint32
	}{
		{launch.Stdin, standardInputAccess},
		{launch.Stdout, standardOutputAccess},
		{launch.Stderr, standardOutputAccess},
	}
	handles := make([]win.Handle, len(sources))
	defer func() {
		for _, handle := range handles {
			if handle != 0 {
				_ = win.CloseHandle(handle)
			}
		}
	}()
	for i, source := range sources {
		if invalidExplicitHandle(source.handle) {
			return 0, fmt.Errorf("windows sandbox: target standard handle %d is invalid", i)
		}
		streamName := [...]string{"stdin", "stdout", "stderr"}[i]
		if err := validateStandardHandleObject(streamName, source.handle); err != nil {
			return 0, err
		}
		granted, err := handleGrantedAccess(source.handle)
		if err != nil {
			return 0, fmt.Errorf("windows sandbox: inspect target standard handle %d: %w", i, err)
		}
		if missing := source.access &^ granted; missing != 0 {
			return 0, fmt.Errorf("windows sandbox: target standard handle %d lacks access %#x", i, missing)
		}
		if err := win.DuplicateHandle(
			win.CurrentProcess(), source.handle, win.CurrentProcess(), &handles[i],
			source.access, true, 0,
		); err != nil {
			return 0, fmt.Errorf("windows sandbox: duplicate target standard handle %d: %w", i, err)
		}
	}
	attributes, err := win.NewProcThreadAttributeList(1)
	if err != nil {
		return 0, err
	}
	defer attributes.Delete()
	if err := attributes.Update(
		win.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&handles[0]),
		uintptr(len(handles))*unsafe.Sizeof(handles[0]),
	); err != nil {
		return 0, err
	}
	executable, err := win.UTF16PtrFromString(launch.Argv[0])
	if err != nil {
		return 0, err
	}
	commandLine, err := win.UTF16PtrFromString(windowsCommandLine(launch.Argv))
	if err != nil {
		return 0, err
	}
	cwd, err := win.UTF16PtrFromString(launch.CWD)
	if err != nil {
		return 0, err
	}
	desktop, err := win.UTF16PtrFromString(launch.Desktop)
	if err != nil {
		return 0, err
	}
	startup := win.StartupInfoEx{
		StartupInfo: win.StartupInfo{
			Cb: uint32(unsafe.Sizeof(win.StartupInfoEx{})), Desktop: desktop,
			Flags: win.STARTF_USESTDHANDLES, StdInput: handles[0],
			StdOutput: handles[1], StdErr: handles[2],
		},
		ProcThreadAttributeList: attributes.List(),
	}
	var process win.ProcessInformation
	err = win.CreateProcess(
		executable, commandLine, nil, nil, true,
		win.CREATE_UNICODE_ENVIRONMENT|win.EXTENDED_STARTUPINFO_PRESENT,
		nil, cwd, &startup.StartupInfo, &process,
	)
	if err != nil {
		return 0, fmt.Errorf("windows sandbox: launch protected target: %w", err)
	}
	_ = win.CloseHandle(process.Thread)
	defer win.CloseHandle(process.Process)
	if _, err := win.WaitForSingleObject(process.Process, win.INFINITE); err != nil {
		return 0, err
	}
	var exitCode uint32
	if err := win.GetExitCodeProcess(process.Process, &exitCode); err != nil {
		return 0, err
	}
	return exitCode, nil
}

func windowsCommandLine(argv []string) string {
	escaped := make([]string, len(argv))
	for i, arg := range argv {
		escaped[i] = syscall.EscapeArg(arg)
	}
	return strings.Join(escaped, " ")
}
