//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	win "golang.org/x/sys/windows"
)

// executeElevatedRunner is the production bridge between executor-owned Go
// streams and the capability-only protected runner launcher. The broker owns
// the named desktop and lease; this process receives only their immutable name
// and a duplicated restricted primary-token handle.
func executeElevatedRunner(request enforce.LaunchRequest, snapshot elevatedSetupSnapshot, issued brokerIssuedToken, limits policy.Limits, releaseLease func() error) (_ int, err error) {
	if request.Context == nil {
		return -1, errors.New("windows sandbox: elevated launch context is required")
	}
	if err := request.Context.Err(); err != nil {
		return -1, err
	}
	if request.Stdin == nil || request.Stdout == nil || request.Stderr == nil {
		return -1, errors.New("windows sandbox: elevated standard streams are required")
	}
	if issued.Handle == 0 || uint64(uintptr(issued.Handle)) != issued.Handle {
		return -1, errors.New("windows sandbox: broker token handle is invalid")
	}
	if !validQualifiedDesktop(issued.Desktop) {
		return -1, errors.New("windows sandbox: broker desktop name is invalid")
	}

	var releaseOnce sync.Once
	var releaseErr error
	release := func() error {
		releaseOnce.Do(func() {
			if releaseLease != nil {
				releaseErr = releaseLease()
			}
		})
		return releaseErr
	}
	ownedByExecution := false
	defer func() {
		if !ownedByExecution {
			err = errors.Join(err, release())
		}
	}()

	bridge, err := newElevatedStdioBridge(request.Context, request.Stdin, request.Stdout, request.Stderr)
	if err != nil {
		return -1, err
	}
	defer func() { err = errors.Join(err, bridge.Close()) }()

	launcher, err := newElevatedRunnerLauncher(nativeElevatedRunnerProcessAPI{})
	if err != nil {
		return -1, err
	}
	execution, err := launcher.Launch(elevatedRunnerLaunch{
		Token:      win.Token(uintptr(issued.Handle)),
		HostPath:   snapshot.HostPath,
		HostSHA256: snapshot.HostSHA256,
		Argv:       append([]string(nil), request.Argv...),
		CWD:        request.Dir,
		Env:        append([]string(nil), request.Env...),
		Desktop:    issued.Desktop,
		Stdin:      win.Handle(bridge.childStdin.Fd()),
		Stdout:     win.Handle(bridge.childStdout.Fd()),
		Stderr:     win.Handle(bridge.childStderr.Fd()),
		Job: JobOptions{
			MaxProcesses: limits.MaxPIDs, MaxMemoryBytes: limits.MaxMemBytes,
			MaxCPUPct: limits.MaxCPUPct,
		},
		ReleaseLease: release,
	})
	if err != nil {
		return -1, err
	}
	ownedByExecution = true
	if err := bridge.CloseChildEnds(); err != nil {
		_, waitErr := execution.Wait(request.Context)
		return -1, errors.Join(err, waitErr)
	}
	code, waitErr := execution.Wait(request.Context)
	copyErr := bridge.WaitOutput()
	return int(code), errors.Join(waitErr, copyErr)
}

type elevatedStdioBridge struct {
	childStdin, childStdout, childStderr *os.File
	stdinWriter                          *os.File
	stdoutReader, stderrReader           *os.File
	outputWG                             sync.WaitGroup
	outputMu                             sync.Mutex
	outputErr                            error
	closeChildOnce                       sync.Once
	closeOnce                            sync.Once
}

func newElevatedStdioBridge(ctx context.Context, stdin io.Reader, stdout, stderr io.Writer) (_ *elevatedStdioBridge, err error) {
	childStdin, stdinWriter, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("windows sandbox: create elevated stdin bridge: %w", err)
	}
	stdoutReader, childStdout, err := os.Pipe()
	if err != nil {
		_ = childStdin.Close()
		_ = stdinWriter.Close()
		return nil, fmt.Errorf("windows sandbox: create elevated stdout bridge: %w", err)
	}
	stderrReader, childStderr, err := os.Pipe()
	if err != nil {
		_ = childStdin.Close()
		_ = stdinWriter.Close()
		_ = stdoutReader.Close()
		_ = childStdout.Close()
		return nil, fmt.Errorf("windows sandbox: create elevated stderr bridge: %w", err)
	}
	bridge := &elevatedStdioBridge{
		childStdin: childStdin, childStdout: childStdout, childStderr: childStderr,
		stdinWriter: stdinWriter, stdoutReader: stdoutReader, stderrReader: stderrReader,
	}
	bridge.outputWG.Add(2)
	go bridge.copyOutput(stdout, stdoutReader, "stdout")
	go bridge.copyOutput(stderr, stderrReader, "stderr")
	go func() {
		_, copyErr := io.Copy(stdinWriter, stdin)
		closeErr := stdinWriter.Close()
		if copyErr != nil && ctx.Err() == nil {
			bridge.recordOutputError(fmt.Errorf("copy elevated stdin: %w", copyErr))
		}
		if closeErr != nil && ctx.Err() == nil {
			bridge.recordOutputError(fmt.Errorf("close elevated stdin: %w", closeErr))
		}
	}()
	return bridge, nil
}

func (bridge *elevatedStdioBridge) copyOutput(destination io.Writer, source *os.File, name string) {
	defer bridge.outputWG.Done()
	if _, err := io.Copy(destination, source); err != nil {
		bridge.recordOutputError(fmt.Errorf("copy elevated %s: %w", name, err))
	}
}

func (bridge *elevatedStdioBridge) recordOutputError(err error) {
	bridge.outputMu.Lock()
	bridge.outputErr = errors.Join(bridge.outputErr, err)
	bridge.outputMu.Unlock()
}

func (bridge *elevatedStdioBridge) CloseChildEnds() (err error) {
	bridge.closeChildOnce.Do(func() {
		err = errors.Join(closeBridgeFile(bridge.childStdin), closeBridgeFile(bridge.childStdout), closeBridgeFile(bridge.childStderr))
	})
	return err
}

func (bridge *elevatedStdioBridge) WaitOutput() error {
	bridge.outputWG.Wait()
	bridge.outputMu.Lock()
	defer bridge.outputMu.Unlock()
	return bridge.outputErr
}

func (bridge *elevatedStdioBridge) Close() (err error) {
	bridge.closeOnce.Do(func() {
		err = errors.Join(bridge.CloseChildEnds(), closeBridgeFile(bridge.stdinWriter),
			closeBridgeFile(bridge.stdoutReader), closeBridgeFile(bridge.stderrReader))
	})
	return err
}

func closeBridgeFile(file *os.File) error {
	if file == nil {
		return nil
	}
	err := file.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}
