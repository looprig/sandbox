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
	// Context bounds only the exact Job-empty proof this function attempts
	// before a launch failure may retire ReleaseLease once a Job has been
	// created; it is never used to cancel a process that has already been
	// created (an indeterminate proof is retried under its own bounded
	// background window instead — see settleFailedJobLaunch and
	// reapUnprovedElevatedExecution). A nil Context is treated as
	// context.Background().
	Context    context.Context
	Token      win.Token
	HostPath   string
	HostSHA256 string
	Argv       []string
	CWD        string
	Env        []string
	// Desktop is the exact broker-created window-station\desktop name. The
	// launcher may reference it but never creates, opens for mutation, or closes
	// either object; their lifetime remains owned by the broker lease.
	Desktop string
	Stdin   win.Handle
	Stdout  win.Handle
	Stderr  win.Handle
	Job     JobOptions
	// ReleaseLease retires BOTH the per-execution broker lease and the
	// compiled elevated spec's active-launch registration. It is idempotent
	// and must be retired exactly once across the whole launch: directly by
	// Launch for a failure before any Job exists, directly by Launch after
	// obtaining exact Job-empty proof for a failure once a Job does exist, or
	// otherwise transferred whole (never called early) to the returned
	// execution's Wait on a successful launch, or to the asynchronous
	// quarantine reaper when proof is indeterminate.
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
	code int
	err  error
}

func (launcher *elevatedRunnerLauncher) Launch(spec elevatedRunnerLaunch) (_ *elevatedRunnerExecution, err error) {
	if launcher == nil || launcher.api == nil {
		return nil, fmt.Errorf("%w: launcher is incomplete", errElevatedRunnerLaunch)
	}
	if spec.ReleaseLease == nil {
		return nil, fmt.Errorf("%w: launch retirement is required", errElevatedRunnerLaunch)
	}
	ctx := spec.Context
	if ctx == nil {
		ctx = context.Background()
	}
	api := launcher.api
	token := spec.Token
	spec.Token = 0
	if token == 0 {
		// Nothing was ever acquired beyond the token itself: retire directly,
		// exactly like every other pre-Job failure below.
		return nil, errors.Join(fmt.Errorf("%w: broker token is missing", errElevatedRunnerLaunch), spec.ReleaseLease())
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
		return nil, errors.Join(fmt.Errorf("%w: installed runner identity is invalid", errElevatedRunnerLaunch), spec.ReleaseLease())
	}
	if err := api.VerifyHost(spec.HostPath, spec.HostSHA256); err != nil {
		return nil, errors.Join(fmt.Errorf("%w: verify installed runner: %v", errElevatedRunnerLaunch, err), spec.ReleaseLease())
	}
	if err := api.VerifyToken(token); err != nil {
		return nil, errors.Join(fmt.Errorf("%w: verify broker token: %v", errElevatedRunnerLaunch, err), spec.ReleaseLease())
	}
	if !validQualifiedDesktop(spec.Desktop) {
		return nil, errors.Join(fmt.Errorf("%w: broker desktop name is invalid", errElevatedRunnerLaunch), spec.ReleaseLease())
	}
	spec.Job.Sandboxed = true
	job, err := api.CreateJob(spec.Job)
	if err != nil {
		return nil, errors.Join(fmt.Errorf("%w: create Job: %v", errElevatedRunnerLaunch, err), spec.ReleaseLease())
	}

	// From here a Job exists. Every failure below must obtain exact
	// Job-empty proof before spec.ReleaseLease may retire the broker lease
	// and the compiled spec's active-launch registration — never release
	// that authority while something might still be assigned to job. An
	// indeterminate proof quarantines the whole capsule (job, and process if
	// one was created) to the same asynchronous reaper a post-run proof
	// failure already uses (reapUnprovedElevatedExecution) instead of
	// retiring synchronously; settleFailedJobLaunch owns that decision and
	// is the only thing below permitted to call spec.ReleaseLease.

	var nonce [32]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil || nonceIsZero(nonce) {
		settleErr := settleFailedJobLaunch(ctx, api, job, 0, spec.ReleaseLease)
		return nil, errors.Join(fmt.Errorf("%w: create runner nonce", errElevatedRunnerLaunch), err, settleErr)
	}
	request := runnerRequest{
		Argv: append([]string(nil), spec.Argv...), CWD: spec.CWD,
		Desktop: spec.Desktop, Nonce: nonce,
	}
	if _, err := marshalSealedRunnerRequest(request); err != nil {
		settleErr := settleFailedJobLaunch(ctx, api, job, 0, spec.ReleaseLease)
		return nil, errors.Join(fmt.Errorf("%w: seal runner request: %v", errElevatedRunnerLaunch, err), settleErr)
	}
	inherited, err := api.CreateRequest(request, [3]win.Handle{spec.Stdin, spec.Stdout, spec.Stderr})
	if err != nil {
		settleErr := settleFailedJobLaunch(ctx, api, job, 0, spec.ReleaseLease)
		return nil, errors.Join(fmt.Errorf("%w: create sealed runner handles: %v", errElevatedRunnerLaunch, err), settleErr)
	}
	defer func() { err = errors.Join(err, inherited.Close()) }()
	process, err := api.CreateSuspended(token, spec.HostPath, spec.Desktop, append([]string(nil), spec.Env...), inherited)
	closeTokenErr := closeToken()
	if err != nil || closeTokenErr != nil {
		var threadCloseErr error
		if process.Thread != 0 {
			threadCloseErr = api.CloseHandle(process.Thread)
		}
		settleErr := settleFailedJobLaunch(ctx, api, job, process.Process, spec.ReleaseLease)
		return nil, errors.Join(fmt.Errorf("%w: create suspended installed runner: %v", errElevatedRunnerLaunch, err),
			closeTokenErr, threadCloseErr, settleErr)
	}
	if err := inherited.Close(); err != nil {
		inherited.close = nil
		threadCloseErr := api.CloseHandle(process.Thread)
		settleErr := settleFailedJobLaunch(ctx, api, job, process.Process, spec.ReleaseLease)
		return nil, errors.Join(fmt.Errorf("%w: close parent runner handles: %v", errElevatedRunnerLaunch, err), threadCloseErr, settleErr)
	}
	inherited.close = nil
	if err := api.Assign(job, process.Process); err != nil {
		threadCloseErr := api.CloseHandle(process.Thread)
		settleErr := settleFailedJobLaunch(ctx, api, job, process.Process, spec.ReleaseLease)
		return nil, errors.Join(fmt.Errorf("%w: assign runner to Job: %v", errElevatedRunnerLaunch, err), threadCloseErr, settleErr)
	}
	if err := api.Resume(process.Thread); err != nil {
		threadCloseErr := api.CloseHandle(process.Thread)
		settleErr := settleFailedJobLaunch(ctx, api, job, process.Process, spec.ReleaseLease)
		return nil, errors.Join(fmt.Errorf("%w: resume Job-assigned runner: %v", errElevatedRunnerLaunch, err), threadCloseErr, settleErr)
	}
	if err := api.CloseHandle(process.Thread); err != nil {
		settleErr := settleFailedJobLaunch(ctx, api, job, process.Process, spec.ReleaseLease)
		return nil, errors.Join(fmt.Errorf("%w: close runner thread: %v", errElevatedRunnerLaunch, err), settleErr)
	}
	process.Thread = 0

	// Successful handoff: both retirement obligations (broker lease, active
	// registration) move atomically into execution.release, to be retired
	// only by a later Wait. Neither this function nor its caller retains
	// them.
	execution := &elevatedRunnerExecution{
		api: api, process: process.Process, job: job,
		release: spec.ReleaseLease,
	}
	return execution, nil
}

// settleFailedJobLaunch handles every Launch failure that occurs once job has
// been created. It first terminates whatever might already be assigned
// (process, if one was created, or the whole job otherwise), then requires
// exact Job-empty proof — via the identical first-attempt/terminate/bounded-
// drain-retry discipline proveJobEmptyThenRetire implements for a post-run
// proof — before release may retire the broker lease and the compiled spec's
// active-launch registration. On an indeterminate proof, release is
// deliberately NOT called: the whole capsule is handed to the same
// asynchronous reaper a post-run proof failure already uses, and only that
// reaper's eventual success retires it.
func settleFailedJobLaunch(ctx context.Context, api elevatedRunnerProcessAPI, job *Job, process win.Handle, release func() error) error {
	if process != 0 {
		_ = api.TerminateProcess(process)
	} else {
		_ = job.Terminate(1)
	}
	_, err := proveJobEmptyThenRetire(api, job, process, release, func() error {
		return api.WaitJobEmpty(ctx, job)
	})
	return err
}

// proveJobEmptyThenRetire performs one Job-empty proof attempt via
// firstProof and, on failure, issues a Job-wide terminate followed by one
// retry under a 30-second bounded drain window (mirroring
// elevatedRunnerExecution.Wait's original post-run proof discipline exactly,
// so a launch-time failure and a post-run failure are held to the identical
// guarantee). On success it closes process (if any) and job and retires
// release exactly once; on a still-indeterminate proof it hands job, process,
// and release to the same asynchronous reaper used after a run (
// reapUnprovedElevatedExecution) and deliberately does NOT call release —
// only that reaper's eventual success may retire it.
func proveJobEmptyThenRetire(api elevatedRunnerProcessAPI, job *Job, process win.Handle, release func() error, firstProof func() error) (terminateErr, err error) {
	proofErr := firstProof()
	if proofErr != nil {
		terminateErr = job.Terminate(1)
		drainCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		proofErr = api.WaitJobEmpty(drainCtx, job)
		cancel()
	}
	if proofErr != nil {
		// Ownership moves to a retrying reaper. It deliberately retains the
		// Job and broker lease until a later exact empty proof; closing or
		// retiring either here could revoke authority while a descendant
		// still runs.
		var processCloseErr error
		if process != 0 {
			processCloseErr = api.CloseHandle(process)
		}
		go reapUnprovedElevatedExecution(api, job, release)
		return terminateErr, errors.Join(proofErr, processCloseErr)
	}
	var releaseErr error
	if release != nil {
		releaseErr = release()
	}
	var processCloseErr error
	if process != 0 {
		processCloseErr = api.CloseHandle(process)
	}
	return terminateErr, errors.Join(releaseErr, processCloseErr, job.Close())
}

// Wait is idempotent. It does not release ACL or network authority unless Job
// emptiness has been observed. If the process wait is cancelled, the Job is
// terminated and given a separate bounded drain interval before lease release.
func (execution *elevatedRunnerExecution) Wait(ctx context.Context) (int, error) {
	if execution == nil {
		return 0, fmt.Errorf("%w: execution is missing", errElevatedRunnerLaunch)
	}
	execution.once.Do(func() {
		code, waitErr := execution.api.WaitProcess(ctx, execution.process)
		execution.code, execution.err = int(code), waitErr
		job, process, release := execution.job, execution.process, execution.release
		terminateErr, settleErr := proveJobEmptyThenRetire(execution.api, job, process, release, func() error {
			return execution.api.WaitJobEmpty(ctx, job)
		})
		execution.err = errors.Join(execution.err, terminateErr, settleErr)
		execution.job, execution.release, execution.process = nil, nil, 0
	})
	return execution.code, execution.err
}

func reapUnprovedElevatedExecution(api elevatedRunnerProcessAPI, job *Job, release func() error) {
	if api == nil || job == nil {
		return
	}
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := api.WaitJobEmpty(ctx, job)
		cancel()
		if err == nil {
			if release != nil {
				_ = release()
			}
			_ = job.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
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
