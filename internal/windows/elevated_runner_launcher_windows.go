//go:build windows

package windows

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	win "golang.org/x/sys/windows"
)

var errElevatedRunnerLaunch = errors.New("windows sandbox: elevated runner launch failed")

// elevatedRunnerLaunch contains data and handles already selected by the
// compiler. Token is the restricted primary token duplicated into this process
// by the authenticated broker; ownership transfers to Launch.
type elevatedRunnerLaunch struct {
	Token      win.Token
	HostPath   string
	HostSHA256 string
	Argv       []string
	CWD        string
	Env        []string
	// Desktop is the exact broker-created window-station\desktop name. The
	// launcher may reference it but never creates, opens for mutation, or closes
	// either object; their lifetime remains owned by the broker lease.
	Desktop      string
	Stdin        win.Handle
	Stdout       win.Handle
	Stderr       win.Handle
	Job          JobOptions
	ReleaseLease func() error
}

type elevatedRunnerProcessAPI interface {
	VerifyHost(string, string) error
	VerifyToken(win.Token) error
	CreateJob(JobOptions) (*Job, error)
	CreateRequest(runnerRequest, [3]win.Handle) (runnerInheritedHandles, error)
	CreateSuspended(win.Token, string, string, []string, runnerInheritedHandles) (runnerProcessHandles, error)
	Assign(*Job, win.Handle) error
	Resume(win.Handle) error
	WaitProcess(context.Context, win.Handle) (uint32, error)
	WaitJobEmpty(context.Context, *Job) error
	TerminateProcess(win.Handle) error
	CloseHandle(win.Handle) error
	CloseToken(win.Token) error
}

type runnerInheritedHandles struct {
	Stdin, Stdout, Stderr, Request win.Handle
	close                          func() error
}

func (handles runnerInheritedHandles) Close() error {
	if handles.close == nil {
		return nil
	}
	return handles.close()
}

type runnerProcessHandles struct {
	Process win.Handle
	Thread  win.Handle
}

type elevatedRunnerLauncher struct {
	api elevatedRunnerProcessAPI
}

func newElevatedRunnerLauncher(api elevatedRunnerProcessAPI) (*elevatedRunnerLauncher, error) {
	if api == nil {
		return nil, errors.New("windows sandbox: elevated runner process API is required")
	}
	return &elevatedRunnerLauncher{api: api}, nil
}

// elevatedRunnerExecution owns every launch-time capability until Wait proves
// the Job is empty. Release is deliberately sequenced after that proof.
type elevatedRunnerExecution struct {
	api     elevatedRunnerProcessAPI
	process win.Handle
	job     *Job
	release func() error

	once sync.Once
	code uint32
	err  error
}

func (launcher *elevatedRunnerLauncher) Launch(spec elevatedRunnerLaunch) (_ *elevatedRunnerExecution, err error) {
	if launcher == nil || launcher.api == nil {
		return nil, fmt.Errorf("%w: launcher is incomplete", errElevatedRunnerLaunch)
	}
	api := launcher.api
	token := spec.Token
	spec.Token = 0
	if token == 0 {
		return nil, fmt.Errorf("%w: broker token is missing", errElevatedRunnerLaunch)
	}
	tokenClosed := false
	closeToken := func() error {
		if tokenClosed {
			return nil
		}
		tokenClosed = true
		return api.CloseToken(token)
	}
	defer func() {
		if !tokenClosed {
			err = errors.Join(err, closeToken())
		}
	}()

	if !normalizedAbsoluteWindowsPath(spec.HostPath) || !validSHA256Hex(spec.HostSHA256) {
		return nil, fmt.Errorf("%w: installed runner identity is invalid", errElevatedRunnerLaunch)
	}
	if err := api.VerifyHost(spec.HostPath, spec.HostSHA256); err != nil {
		return nil, fmt.Errorf("%w: verify installed runner: %v", errElevatedRunnerLaunch, err)
	}
	if err := api.VerifyToken(token); err != nil {
		return nil, fmt.Errorf("%w: verify broker token: %v", errElevatedRunnerLaunch, err)
	}
	if !validQualifiedDesktop(spec.Desktop) {
		return nil, fmt.Errorf("%w: broker desktop name is invalid", errElevatedRunnerLaunch)
	}
	spec.Job.Sandboxed = true
	job, err := api.CreateJob(spec.Job)
	if err != nil {
		return nil, fmt.Errorf("%w: create Job: %v", errElevatedRunnerLaunch, err)
	}
	cleanupJob := true
	defer func() {
		if cleanupJob {
			err = errors.Join(err, job.Close())
		}
	}()

	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil || nonceIsZero(nonce) {
		return nil, errors.Join(fmt.Errorf("%w: create runner nonce", errElevatedRunnerLaunch), err)
	}
	request := runnerRequest{
		Argv: append([]string(nil), spec.Argv...), CWD: spec.CWD,
		Desktop: spec.Desktop, Nonce: nonce,
	}
	if _, err := marshalSealedRunnerRequest(request); err != nil {
		return nil, fmt.Errorf("%w: seal runner request: %v", errElevatedRunnerLaunch, err)
	}
	inherited, err := api.CreateRequest(request, [3]win.Handle{spec.Stdin, spec.Stdout, spec.Stderr})
	if err != nil {
		return nil, fmt.Errorf("%w: create sealed runner handles: %v", errElevatedRunnerLaunch, err)
	}
	defer func() { err = errors.Join(err, inherited.Close()) }()
	process, err := api.CreateSuspended(token, spec.HostPath, spec.Desktop, append([]string(nil), spec.Env...), inherited)
	closeTokenErr := closeToken()
	if err != nil || closeTokenErr != nil {
		if process.Process != 0 {
			_ = api.TerminateProcess(process.Process)
		}
		if process.Thread != 0 {
			_ = api.CloseHandle(process.Thread)
		}
		if process.Process != 0 {
			_ = api.CloseHandle(process.Process)
		}
		return nil, errors.Join(fmt.Errorf("%w: create suspended installed runner: %v", errElevatedRunnerLaunch, err), closeTokenErr)
	}
	if err := inherited.Close(); err != nil {
		inherited.close = nil
		_ = api.TerminateProcess(process.Process)
		_ = api.CloseHandle(process.Thread)
		_ = api.CloseHandle(process.Process)
		return nil, fmt.Errorf("%w: close parent runner handles: %v", errElevatedRunnerLaunch, err)
	}
	inherited.close = nil
	processOwned := true
	defer func() {
		if processOwned {
			err = errors.Join(err, api.CloseHandle(process.Thread), api.CloseHandle(process.Process))
		}
	}()
	if err := api.Assign(job, process.Process); err != nil {
		_ = api.TerminateProcess(process.Process)
		return nil, fmt.Errorf("%w: assign runner to Job: %v", errElevatedRunnerLaunch, err)
	}
	if err := api.Resume(process.Thread); err != nil {
		_ = job.Terminate(1)
		return nil, fmt.Errorf("%w: resume Job-assigned runner: %v", errElevatedRunnerLaunch, err)
	}
	if err := api.CloseHandle(process.Thread); err != nil {
		_ = job.Terminate(1)
		return nil, fmt.Errorf("%w: close runner thread: %v", errElevatedRunnerLaunch, err)
	}
	process.Thread = 0

	execution := &elevatedRunnerExecution{
		api: api, process: process.Process, job: job,
		release: spec.ReleaseLease,
	}
	processOwned = false
	cleanupJob = false
	return execution, nil
}

// Wait is idempotent. It does not release ACL or network authority unless Job
// emptiness has been observed. If the process wait is cancelled, the Job is
// terminated and given a separate bounded drain interval before lease release.
func (execution *elevatedRunnerExecution) Wait(ctx context.Context) (uint32, error) {
	if execution == nil {
		return 0, fmt.Errorf("%w: execution is missing", errElevatedRunnerLaunch)
	}
	execution.once.Do(func() {
		execution.code, execution.err = execution.api.WaitProcess(ctx, execution.process)
		firstProofErr := execution.api.WaitJobEmpty(ctx, execution.job)
		proofErr := firstProofErr
		var terminateErr error
		if firstProofErr != nil {
			terminateErr = execution.job.Terminate(1)
			drainCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			proofErr = execution.api.WaitJobEmpty(drainCtx, execution.job)
			cancel()
		}
		var releaseErr error
		if proofErr == nil && execution.release != nil {
			releaseErr = execution.release()
		}
		execution.err = errors.Join(execution.err, firstProofErr, terminateErr, proofErr, releaseErr,
			execution.api.CloseHandle(execution.process),
			execution.job.Close())
		execution.process = 0
	})
	return execution.code, execution.err
}

func validSHA256Hex(value string) bool {
	if len(value) != 64 || strings.TrimSpace(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// Constant-time helper is kept local to make host hash comparison policy
// explicit in the native adapter.
func equalSHA256Hex(left, right string) bool {
	left = strings.ToLower(left)
	right = strings.ToLower(right)
	return len(left) == 64 && len(right) == 64 &&
		subtle.ConstantTimeCompare([]byte(left), []byte(right)) == 1
}
