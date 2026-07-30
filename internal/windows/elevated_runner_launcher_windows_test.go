//go:build windows

package windows

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	win "golang.org/x/sys/windows"
)

// fixedExecution is a minimal enforce.Execution whose Wait returns
// immediately with a pre-decided (exitCode, err) pair. It is shared by
// windows package tests that fake elevatedRunnerLaunchFunc directly (i.e.
// tests exercising elevatedBackend.Compile's Launch closure in isolation,
// without driving the real elevatedRunnerLauncher/elevatedRunnerExecution
// machinery) and only need a trivial already-complete handle to return.
type fixedExecution struct {
	code int
	err  error
}

func (execution fixedExecution) Wait(context.Context) (int, error) {
	return execution.code, execution.err
}

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
	jobWaitErrs  []error
	released     bool
	releaseCh    chan struct{}

	createSuspendedErr error
	assignErr          error
	resumeErr          error

	mu sync.Mutex
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
	if api.createSuspendedErr != nil {
		return runnerProcessHandles{}, api.createSuspendedErr
	}
	return runnerProcessHandles{Process: 31, Thread: 32}, nil
}
func (api *fakeElevatedRunnerAPI) Assign(*Job, win.Handle) error {
	api.event("assign")
	return api.assignErr
}
func (api *fakeElevatedRunnerAPI) Resume(win.Handle) error {
	api.event("resume")
	return api.resumeErr
}
func (api *fakeElevatedRunnerAPI) WaitProcess(context.Context, win.Handle) (uint32, error) {
	api.event("wait-process")
	return api.waitCode, api.waitErr
}
func (api *fakeElevatedRunnerAPI) WaitJobEmpty(context.Context, *Job) error {
	api.mu.Lock()
	defer api.mu.Unlock()
	api.event("wait-job-empty")
	if len(api.jobWaitErrs) != 0 {
		err := api.jobWaitErrs[0]
		api.jobWaitErrs = api.jobWaitErrs[1:]
		return err
	}
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

func validElevatedRunnerLaunchForTest(api *fakeElevatedRunnerAPI) elevatedRunnerLaunch {
	return elevatedRunnerLaunch{
		Context: context.Background(),
		Token:   7, HostPath: `C:\ProgramData\Looprig\slots\one\sandbox-host.exe`,
		HostSHA256: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		Argv:       []string{`C:\work\tool.exe`, "arg"}, CWD: `C:\work`,
		Desktop: `SandboxStation\SandboxDesktop`,
		Stdin:   11, Stdout: 12, Stderr: 13,
		Job: JobOptions{MaxProcesses: 4, MaxMemoryBytes: 64 << 20, MaxCPUPct: 25},
		ReleaseLease: func() error {
			api.mu.Lock()
			defer api.mu.Unlock()
			api.event("release")
			api.released = true
			if api.releaseCh != nil {
				close(api.releaseCh)
				api.releaseCh = nil
			}
			return nil
		},
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
		"verify-host", "verify-token", "job", "request",
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
	// No Job was ever created for this failure, so ReleaseLease (which
	// records a "release" event here) must have retired synchronously,
	// before the token is closed by the deferred cleanup.
	if want := []string{"release", "close-token"}; !reflect.DeepEqual(api.events, want) {
		t.Fatalf("events = %v, want %v", api.events, want)
	}
	if !api.released {
		t.Fatal("pre-Job launch failure did not retire the broker lease/active registration")
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

func TestElevatedRunnerQuarantinesAuthorityUntilLaterJobEmptyProof(t *testing.T) {
	proofErr := errors.New("completion proof unavailable")
	released := make(chan struct{})
	api := &fakeElevatedRunnerAPI{
		jobWaitErrs: []error{proofErr, proofErr, nil},
		releaseCh:   released,
	}
	launcher, _ := newElevatedRunnerLauncher(api)
	execution, err := launcher.Launch(validElevatedRunnerLaunchForTest(api))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := execution.Wait(context.Background()); err == nil {
		t.Fatal("initial proof failures were hidden")
	}
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("quarantined broker lease was not released after later exact proof")
	}
}

// TestElevatedAsyncExecutionRetainsBrokerAndSpecActivityUntilJobZero proves
// the launch stack returns control (a live *elevatedRunnerExecution) as soon
// as the runner is Job-assigned and resumed, WITHOUT retiring the broker
// lease/active registration — that only happens once Wait obtains exact
// Job-zero proof. This is the core "genuinely asynchronous, not a goroutine
// wrapping a blocking call" property: Launch itself never blocks for the
// process's own lifetime, and nothing is retired before Launch returns.
func TestElevatedAsyncExecutionRetainsBrokerAndSpecActivityUntilJobZero(t *testing.T) {
	api := &fakeElevatedRunnerAPI{waitCode: 0}
	launcher, err := newElevatedRunnerLauncher(api)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := launcher.Launch(validElevatedRunnerLaunchForTest(api))
	if err != nil {
		t.Fatal(err)
	}
	if api.released {
		t.Fatal("broker lease/active registration retired before Launch's caller ever called Wait")
	}
	if _, err := execution.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !api.released {
		t.Fatal("retirement did not occur after exact Job-zero proof")
	}
}

// TestElevatedAsyncExecutionQuarantineOwnsRetirements proves that when the
// post-run Job-empty proof is indeterminate, Wait itself does NOT retire the
// broker lease/active registration — ownership moves whole to the
// asynchronous quarantine reaper, and only that reaper's own later exact
// proof retires it.
func TestElevatedAsyncExecutionQuarantineOwnsRetirements(t *testing.T) {
	proofErr := errors.New("completion proof unavailable")
	released := make(chan struct{})
	api := &fakeElevatedRunnerAPI{
		// The first two errors are consumed synchronously inside Wait itself
		// (the immediate attempt, then the terminate+drain retry); the third
		// is consumed by the quarantine reaper's own first attempt, so it
		// also observes a failure and sleeps its retry interval before the
		// final nil succeeds — giving the immediate post-Wait check below a
		// reliable (not just fast-goroutine-scheduling-dependent) window in
		// which retirement provably has not happened yet.
		jobWaitErrs: []error{proofErr, proofErr, proofErr, nil},
		releaseCh:   released,
	}
	launcher, err := newElevatedRunnerLauncher(api)
	if err != nil {
		t.Fatal(err)
	}
	execution, err := launcher.Launch(validElevatedRunnerLaunchForTest(api))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := execution.Wait(context.Background()); err == nil {
		t.Fatal("indeterminate proof was hidden from Wait's caller")
	}
	api.mu.Lock()
	releasedImmediately := api.released
	api.mu.Unlock()
	if releasedImmediately {
		t.Fatal("Wait retired authority itself instead of transferring it to quarantine")
	}
	select {
	case <-released:
	case <-time.After(2 * time.Second):
		t.Fatal("quarantine never retired broker lease/active registration after its own later exact proof")
	}
}

// launchThroughFakeAPI adapts elevatedRunnerLauncher (driven by a fake
// elevatedRunnerProcessAPI) into an elevatedRunnerLaunchFunc, so a test can
// exercise elevatedBackend.Compile's full ownership linearization —
// including Spec.Release's active-registration gate — against the exact
// same fake Job/process semantics elevatedRunnerLauncher's own unit tests
// already use, instead of only the trivial fixedExecution stand-in the
// Compile-level tests elsewhere in this package use.
func launchThroughFakeAPI(api elevatedRunnerProcessAPI) elevatedRunnerLaunchFunc {
	return func(request enforce.LaunchRequest, snapshot elevatedSetupSnapshot, issued brokerIssuedToken, _ policy.Limits, retire func() error) (enforce.Execution, error) {
		launcher, err := newElevatedRunnerLauncher(api)
		if err != nil {
			return nil, err
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
			Stdin:      11, Stdout: 12, Stderr: 13,
			ReleaseLease: retire,
		})
		if err != nil {
			return nil, err
		}
		return execution, nil
	}
}

// TestElevatedAsyncExecutionLaunchFailureRetiresAfterProof covers the three
// launch-time failure points named by the plan — suspended-create,
// Job-assignment, and resume — each under both a direct (immediately
// provable) and a quarantined (indeterminate, later proved) Job-empty proof.
// It proves: (1) the broker lease/active registration is never retired
// before proof; (2) it is retired exactly once, whether by the direct proof
// path or by quarantine; and (3) Spec.Release is neither early (it must not
// return before that retirement) nor permanently blocked (it must return
// once retirement has actually happened).
func TestElevatedAsyncExecutionLaunchFailureRetiresAfterProof(t *testing.T) {
	validHash := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	for _, failure := range []struct {
		name    string
		prepare func(*fakeElevatedRunnerAPI)
	}{
		{"suspended-create", func(api *fakeElevatedRunnerAPI) {
			api.createSuspendedErr = errors.New("create suspended failed")
		}},
		{"job-assignment", func(api *fakeElevatedRunnerAPI) {
			api.assignErr = errors.New("assign failed")
		}},
		{"resume", func(api *fakeElevatedRunnerAPI) {
			api.resumeErr = errors.New("resume failed")
		}},
	} {
		for _, proof := range []struct {
			name          string
			indeterminate bool
		}{
			{"direct-proof", false},
			{"quarantined-proof", true},
		} {
			t.Run(failure.name+"/"+proof.name, func(t *testing.T) {
				api := &fakeElevatedRunnerAPI{}
				failure.prepare(api)
				if proof.indeterminate {
					// As in TestElevatedAsyncExecutionQuarantineOwnsRetirements:
					// the first two errors are consumed synchronously inside
					// settleFailedJobLaunch's own attempt+retry, and the third
					// makes the quarantine reaper's own first attempt fail too,
					// so the immediate post-Launch check below has a reliable
					// window before the reaper's retry-interval sleep elapses.
					proofErr := errors.New("completion proof unavailable")
					api.jobWaitErrs = []error{proofErr, proofErr, proofErr, nil}
				}

				snapshot := readyElevatedSnapshot()
				snapshot.HostSHA256 = validHash
				lease := &fakeElevatedLease{}
				backend := &elevatedBackend{deps: elevatedCompileDependencies{
					inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) { return snapshot, nil },
					acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) { return lease, nil },
					launch:  launchThroughFakeAPI(api),
				}}
				spec, _, _, _, err := backend.Compile(policy.Effective{})
				if err != nil {
					t.Fatal(err)
				}

				execution, launchErr := spec.Launch(enforce.LaunchRequest{
					Context: context.Background(), Dir: `C:\work`, Argv: []string{`C:\tool.exe`},
				})
				if launchErr == nil {
					t.Fatalf("%s launch failure was not surfaced", failure.name)
				}
				if execution != nil {
					t.Fatal("a failed launch must not return a live execution")
				}

				lease.mu.Lock()
				releasedImmediately := lease.executionReleases == 1
				lease.mu.Unlock()
				if proof.indeterminate {
					if releasedImmediately {
						t.Fatal("retirement occurred before quarantine's own exact proof")
					}
				} else if !releasedImmediately {
					t.Fatal("direct Job-empty proof succeeded but retirement did not occur synchronously")
				}

				deadline := time.After(2 * time.Second)
				for {
					lease.mu.Lock()
					releases := lease.executionReleases
					lease.mu.Unlock()
					if releases == 1 {
						break
					}
					select {
					case <-deadline:
						t.Fatal("retirement never completed after proof")
					case <-time.After(time.Millisecond):
					}
				}

				releaseDone := make(chan error, 1)
				go func() { releaseDone <- spec.Release() }()
				select {
				case releaseErr := <-releaseDone:
					if releaseErr != nil {
						t.Fatal(releaseErr)
					}
				case <-time.After(2 * time.Second):
					t.Fatal("Spec.Release remained permanently blocked after proof/quarantine completion")
				}

				lease.mu.Lock()
				defer lease.mu.Unlock()
				if lease.executionReleases != 1 || lease.releases != 1 {
					t.Fatalf("retirement counts: execution releases=%d factory releases=%d, want 1/1",
						lease.executionReleases, lease.releases)
				}
			})
		}
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
