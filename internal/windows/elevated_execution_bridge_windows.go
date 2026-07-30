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
//
// executeElevatedRunner itself must return promptly once the launched
// process's Job/process authority has been established — it must never block
// for the process's own lifetime. It calls launcher.Launch (which already
// returns as soon as the runner is Job-assigned and resumed) and, on
// success, hands the resulting *elevatedRunnerExecution* plus the still-open
// stdio bridge to elevatedAsyncExecution. retire is the single combined
// closure (broker lease release plus the compiled spec's active-launch
// registration) threaded through as elevatedRunnerLaunch.ReleaseLease; a
// later call to the returned value's Wait is what actually reaps the
// process, proves the Job is empty, drains the bridge, and retires it (via
// elevatedRunnerExecution.release). On any failure, launcher.Launch itself
// is responsible for retiring the retire obligation on every one of its own
// return paths — synchronously once it has exact Job-empty proof, or by
// quarantining the whole capsule for a later proof — so this function must
// call retire directly only for failures that occur before Launch is ever
// invoked (nothing here has created any OS-level authority yet in that
// case).
func executeElevatedRunner(request enforce.LaunchRequest, snapshot elevatedSetupSnapshot, issued brokerIssuedToken, limits policy.Limits, retire func() error) (enforce.Execution, error) {
	if retire == nil {
		return nil, errors.New("windows sandbox: elevated launch retirement is required")
	}
	if request.Context == nil {
		return nil, errors.Join(errors.New("windows sandbox: elevated launch context is required"), retire())
	}
	if err := request.Context.Err(); err != nil {
		return nil, errors.Join(err, retire())
	}
	if request.Stdin == nil || request.Stdout == nil || request.Stderr == nil {
		return nil, errors.Join(errors.New("windows sandbox: elevated standard streams are required"), retire())
	}
	if issued.Handle == 0 || uint64(uintptr(issued.Handle)) != issued.Handle {
		return nil, errors.Join(errors.New("windows sandbox: broker token handle is invalid"), retire())
	}
	if !validQualifiedDesktop(issued.Desktop) {
		return nil, errors.Join(errors.New("windows sandbox: broker desktop name is invalid"), retire())
	}

	bridge, err := newElevatedStdioBridge(request.Context, request.Stdin, request.Stdout, request.Stderr)
	if err != nil {
		return nil, errors.Join(err, retire())
	}

	launcher, err := newElevatedRunnerLauncher(nativeElevatedRunnerProcessAPI{})
	if err != nil {
		return nil, errors.Join(err, retire(), bridge.Close())
	}

	execution, err := launcher.Launch(elevatedRunnerLaunch{
		Context:    request.Context,
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
			Sandboxed:    true,
			MaxProcesses: limits.MaxPIDs, MaxMemoryBytes: limits.MaxMemBytes,
			MaxCPUPct: limits.MaxCPUPct,
		},
		ReleaseLease: retire,
	})
	// From this point Launch itself owns retiring `retire` on every one of
	// its own outcomes (success transfers it into execution.release; failure
	// retires it directly after proof, or via quarantine): this function must
	// never call retire again below, on either the success or the failure
	// path, to avoid retiring authority before an outstanding Job-empty
	// proof.
	if err != nil {
		return nil, errors.Join(err, bridge.Close())
	}

	// Closing the parent's copies of the child-side descriptors as soon as
	// the child holds its own inherited copies (rather than waiting for
	// Wait) matches the same fd-lifetime discipline process.go's
	// spawnProcess already requires: otherwise a parent-side leak would keep
	// the output-copy goroutines from ever observing EOF. Authority already
	// belongs to execution at this point regardless of whether this close
	// succeeds, so a failure here is folded into the eventual Wait result
	// rather than treated as a launch failure.
	closeErr := bridge.CloseChildEnds()
	return newElevatedAsyncExecution(execution, bridge, closeErr), nil
}

// elevatedAsyncExecution adapts one successfully launched
// *elevatedRunnerExecution* plus its owned stdio bridge into
// enforce.Execution. Bridge child-end descriptors are already closed by the
// time this is constructed (see executeElevatedRunner); Wait only needs to
// reap the process/Job (which also retires the broker lease and the
// compiled spec's active registration — see elevatedRunnerExecution.Wait)
// and drain the remaining output-copy goroutines.
type elevatedAsyncExecution struct {
	execution      *elevatedRunnerExecution
	bridge         *elevatedStdioBridge
	bridgeCloseErr error
}

func newElevatedAsyncExecution(execution *elevatedRunnerExecution, bridge *elevatedStdioBridge, bridgeCloseErr error) *elevatedAsyncExecution {
	return &elevatedAsyncExecution{execution: execution, bridge: bridge, bridgeCloseErr: bridgeCloseErr}
}

func (async *elevatedAsyncExecution) Wait(ctx context.Context) (int, error) {
	if async == nil || async.execution == nil {
		return -1, fmt.Errorf("%w: execution is missing", errElevatedRunnerLaunch)
	}
	code, waitErr := async.execution.Wait(ctx)
	var copyErr error
	if async.bridge != nil {
		copyErr = async.bridge.WaitOutput()
	}
	return code, errors.Join(async.bridgeCloseErr, waitErr, copyErr)
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
