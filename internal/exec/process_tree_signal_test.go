package exec

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// This file covers Task 12A: the platform-neutral signal/terminal state
// machine layered onto Process (process.go) — interrupt, terminate/grace/
// escalate, kill, idempotence, and natural-exit races — entirely against a
// fake processSignalTarget and an injectable grace-period channel, with no
// real OS process anywhere. Real Unix/Windows signal delivery is a later
// microtask's scope (12B/12D); this file only proves the state machine
// itself is correct.

// recordingSignaler is a fake processSignalTarget. Each send is recorded in
// call order, and — when onCall is non-nil — also published on it, giving
// tests a deterministic synchronization point instead of a sleep-based poll.
// Send outcomes are scripted per kind via errs.
type recordingSignaler struct {
	mu     sync.Mutex
	calls  []string
	errs   map[string]error
	onCall chan string
}

func (s *recordingSignaler) sendInterrupt() error { return s.record("interrupt") }
func (s *recordingSignaler) sendTerminate() error { return s.record("terminate") }
func (s *recordingSignaler) sendKill() error      { return s.record("kill") }

func (s *recordingSignaler) record(kind string) error {
	s.mu.Lock()
	s.calls = append(s.calls, kind)
	err := s.errs[kind]
	s.mu.Unlock()
	if s.onCall != nil {
		s.onCall <- kind
	}
	return err
}

// snapshot returns a defensive copy of the calls recorded so far.
func (s *recordingSignaler) snapshot() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (s *recordingSignaler) count(kind string) int {
	n := 0
	for _, c := range s.snapshot() {
		if c == kind {
			n++
		}
	}
	return n
}

// newSignalTestProcess builds a minimal, platform-neutral *Process for
// exercising Signal's state machine directly: no *exec.Cmd, no
// enforce.Execution, no real OS process anywhere — only the fields Signal's
// state machine itself depends on. grace, when non-nil, replaces the real
// time.Timer-backed wait a terminate escalation uses so tests can drive
// escalation deterministically.
func newSignalTestProcess(signaler processSignalTarget, grace func(time.Duration) (<-chan time.Time, func())) *Process {
	return &Process{
		done:           make(chan struct{}),
		terminateGrace: resolveProcessTerminateGrace(0),
		signaler:       signaler,
		graceTimer:     grace,
	}
}

// fixedGraceTimer returns a graceTimer func that ignores the requested
// duration and always hands back ch, letting a test fire (or withhold)
// escalation deterministically regardless of Process.terminateGrace.
func fixedGraceTimer(ch <-chan time.Time) func(time.Duration) (<-chan time.Time, func()) {
	return func(time.Duration) (<-chan time.Time, func()) {
		return ch, func() {}
	}
}

func waitForCall(t *testing.T, ch chan string, want string) {
	t.Helper()
	select {
	case got := <-ch:
		if got != want {
			t.Fatalf("delivered signal = %q, want %q", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %q to be delivered", want)
	}
}

func assertNoCallWithin(t *testing.T, ch chan string, d time.Duration) {
	t.Helper()
	select {
	case got := <-ch:
		t.Fatalf("unexpected signal delivered: %q", got)
	case <-time.After(d):
	}
}

// TestProcessSignalInterruptDeliversWithoutDecidingTerminal proves
// ProcessSignalInterrupt delivers exactly once per call and never itself
// marks or treats the process as terminal — only Wait observing an actual
// exit does that (done stays open, and a second Interrupt still delivers).
func TestProcessSignalInterruptDeliversWithoutDecidingTerminal(t *testing.T) {
	fake := &recordingSignaler{onCall: make(chan string, 4)}
	proc := newSignalTestProcess(fake, nil)

	if err := proc.Signal(context.Background(), ProcessSignalInterrupt); err != nil {
		t.Fatalf("Signal(Interrupt): %v", err)
	}
	waitForCall(t, fake.onCall, "interrupt")
	if proc.confirmedTerminal() {
		t.Fatal("Interrupt marked the process terminal by itself")
	}

	if err := proc.Signal(context.Background(), ProcessSignalInterrupt); err != nil {
		t.Fatalf("second Signal(Interrupt): %v", err)
	}
	waitForCall(t, fake.onCall, "interrupt")
	if got := fake.count("interrupt"); got != 2 {
		t.Fatalf("interrupt deliveries = %d, want 2", got)
	}
}

// TestProcessSignalInterruptPropagatesDeliveryError proves a send error from
// the signal target is returned to the caller unmodified.
func TestProcessSignalInterruptPropagatesDeliveryError(t *testing.T) {
	sendErr := errors.New("interrupt delivery failed")
	fake := &recordingSignaler{errs: map[string]error{"interrupt": sendErr}}
	proc := newSignalTestProcess(fake, nil)

	if err := proc.Signal(context.Background(), ProcessSignalInterrupt); !errors.Is(err, sendErr) {
		t.Fatalf("Signal(Interrupt) error = %v, want %v", err, sendErr)
	}
}

// TestProcessSignalKillIsImmediateWithNoGrace proves ProcessSignalKill
// dispatches synchronously, with no waiting on any grace channel: an
// unfired, un-buffered grace channel proves no escalation timer was ever
// consulted.
func TestProcessSignalKillIsImmediateWithNoGrace(t *testing.T) {
	fake := &recordingSignaler{onCall: make(chan string, 1)}
	neverFires := make(chan time.Time) // consulting this would hang forever
	proc := newSignalTestProcess(fake, fixedGraceTimer(neverFires))

	if err := proc.Signal(context.Background(), ProcessSignalKill); err != nil {
		t.Fatalf("Signal(Kill): %v", err)
	}
	waitForCall(t, fake.onCall, "kill")
	if got := fake.count("terminate"); got != 0 {
		t.Fatalf("terminate deliveries = %d, want 0 (Kill must skip terminate)", got)
	}
}

// TestProcessSignalKillIsIdempotent proves repeated (including concurrent)
// Signal(Kill) calls dispatch at most one real kill and all observe the
// identical result.
func TestProcessSignalKillIsIdempotent(t *testing.T) {
	killErr := errors.New("kill failed")
	fake := &recordingSignaler{errs: map[string]error{"kill": killErr}}
	proc := newSignalTestProcess(fake, nil)

	const n = 32
	var wg sync.WaitGroup
	errsCh := make(chan error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errsCh <- proc.Signal(context.Background(), ProcessSignalKill)
		}()
	}
	wg.Wait()
	close(errsCh)
	for err := range errsCh {
		if !errors.Is(err, killErr) {
			t.Fatalf("concurrent Signal(Kill) error = %v, want %v", err, killErr)
		}
	}
	if got := fake.count("kill"); got != 1 {
		t.Fatalf("kill deliveries = %d, want exactly 1", got)
	}
}

// TestProcessSignalTerminateEscalatesToKillAfterGrace proves the documented
// terminate/grace/escalate sequence: terminate is delivered immediately,
// and once the (test-controlled) grace period elapses without a confirmed
// exit, exactly one kill follows.
func TestProcessSignalTerminateEscalatesToKillAfterGrace(t *testing.T) {
	fake := &recordingSignaler{onCall: make(chan string, 4)}
	grace := make(chan time.Time, 1)
	proc := newSignalTestProcess(fake, fixedGraceTimer(grace))

	if err := proc.Signal(context.Background(), ProcessSignalTerminate); err != nil {
		t.Fatalf("Signal(Terminate): %v", err)
	}
	waitForCall(t, fake.onCall, "terminate")

	// Grace period elapses without the process exiting.
	grace <- time.Now()
	waitForCall(t, fake.onCall, "kill")

	if got := fake.count("terminate"); got != 1 {
		t.Fatalf("terminate deliveries = %d, want exactly 1", got)
	}
	if got := fake.count("kill"); got != 1 {
		t.Fatalf("kill deliveries = %d, want exactly 1", got)
	}
}

// TestProcessSignalTerminateNeverEscalatesOnNaturalExitBeforeGrace proves the
// natural-exit race: when the process is confirmed terminal (done closed)
// before the grace period elapses, escalation is skipped entirely — no kill
// is ever dispatched, even if the grace channel later fires.
func TestProcessSignalTerminateNeverEscalatesOnNaturalExitBeforeGrace(t *testing.T) {
	fake := &recordingSignaler{onCall: make(chan string, 4)}
	grace := make(chan time.Time, 1)
	proc := newSignalTestProcess(fake, fixedGraceTimer(grace))

	if err := proc.Signal(context.Background(), ProcessSignalTerminate); err != nil {
		t.Fatalf("Signal(Terminate): %v", err)
	}
	waitForCall(t, fake.onCall, "terminate")

	// The process exits naturally before the grace period elapses.
	close(proc.done)

	// Even though the grace channel later fires, escalateAfterGrace's select
	// must have already taken the done branch and returned without
	// dispatching a kill.
	select {
	case grace <- time.Now():
	default:
	}
	assertNoCallWithin(t, fake.onCall, 100*time.Millisecond)
	if got := fake.count("kill"); got != 0 {
		t.Fatalf("kill deliveries = %d, want 0 (natural exit must win the race)", got)
	}

	// Signal is now a confirmed-terminal no-op regardless of kind.
	for _, kind := range []ProcessSignal{ProcessSignalInterrupt, ProcessSignalTerminate, ProcessSignalKill} {
		if err := proc.Signal(context.Background(), kind); err != nil {
			t.Fatalf("post-terminal Signal(%d): %v", kind, err)
		}
	}
	assertNoCallWithin(t, fake.onCall, 50*time.Millisecond)
}

// TestProcessSignalTerminateEscalatesExactlyOnce proves repeated (including
// concurrent) Signal(Terminate) calls deliver terminate exactly once and
// start exactly one escalation, never re-sending terminate and never
// escalating twice even if the grace channel is signaled repeatedly.
func TestProcessSignalTerminateEscalatesExactlyOnce(t *testing.T) {
	fake := &recordingSignaler{onCall: make(chan string, 64)}
	grace := make(chan time.Time, 8)
	proc := newSignalTestProcess(fake, fixedGraceTimer(grace))

	const n = 16
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := proc.Signal(context.Background(), ProcessSignalTerminate); err != nil {
				t.Errorf("concurrent Signal(Terminate): %v", err)
			}
		}()
	}
	wg.Wait()
	waitForCall(t, fake.onCall, "terminate")

	// A single escalation goroutine exists; feed its grace channel several
	// times (extra sends are simply never read once the goroutine exits
	// after its first select case fires) and confirm exactly one kill.
	grace <- time.Now()
	waitForCall(t, fake.onCall, "kill")
	select {
	case grace <- time.Now():
	default:
	}

	assertNoCallWithin(t, fake.onCall, 100*time.Millisecond)
	if got := fake.count("terminate"); got != 1 {
		t.Fatalf("terminate deliveries = %d, want exactly 1", got)
	}
	if got := fake.count("kill"); got != 1 {
		t.Fatalf("kill deliveries = %d, want exactly 1", got)
	}
}

// TestProcessSignalExplicitKillDuringPendingEscalationDispatchesOnce proves
// an explicit Signal(Kill) issued while a terminate escalation is still
// pending shares the same single kill dispatch: only one kill is ever sent,
// and the later-firing grace channel is a no-op once it happens.
func TestProcessSignalExplicitKillDuringPendingEscalationDispatchesOnce(t *testing.T) {
	fake := &recordingSignaler{onCall: make(chan string, 8)}
	grace := make(chan time.Time, 1)
	proc := newSignalTestProcess(fake, fixedGraceTimer(grace))

	if err := proc.Signal(context.Background(), ProcessSignalTerminate); err != nil {
		t.Fatalf("Signal(Terminate): %v", err)
	}
	waitForCall(t, fake.onCall, "terminate")

	if err := proc.Signal(context.Background(), ProcessSignalKill); err != nil {
		t.Fatalf("Signal(Kill): %v", err)
	}
	waitForCall(t, fake.onCall, "kill")

	// The escalation goroutine is still asleep on the grace channel; firing
	// it now must not produce a second kill (dispatchKill is idempotent).
	grace <- time.Now()
	assertNoCallWithin(t, fake.onCall, 100*time.Millisecond)
	if got := fake.count("kill"); got != 1 {
		t.Fatalf("kill deliveries = %d, want exactly 1", got)
	}
}

// TestProcessSignalTerminateRealGraceEscalates exercises the real, default
// (non-injected) time.Timer path end to end with a short grace period,
// proving realGraceTimer/defaultProcessTerminateGrace wiring actually works
// and not only the injectable seam.
func TestProcessSignalTerminateRealGraceEscalates(t *testing.T) {
	fake := &recordingSignaler{onCall: make(chan string, 4)}
	proc := &Process{
		done:           make(chan struct{}),
		terminateGrace: 20 * time.Millisecond,
		signaler:       fake,
	}
	if err := proc.Signal(context.Background(), ProcessSignalTerminate); err != nil {
		t.Fatalf("Signal(Terminate): %v", err)
	}
	waitForCall(t, fake.onCall, "terminate")
	waitForCall(t, fake.onCall, "kill")
}

// TestProcessSignalIdempotentAfterConfirmedTerminal proves that once a
// process is confirmed terminal (done already closed before any Signal
// call), every signal kind is a safe, error-free no-op that never touches
// the underlying signaler at all.
func TestProcessSignalIdempotentAfterConfirmedTerminal(t *testing.T) {
	fake := &recordingSignaler{onCall: make(chan string, 4)}
	proc := newSignalTestProcess(fake, nil)
	close(proc.done)

	for _, kind := range []ProcessSignal{ProcessSignalInterrupt, ProcessSignalTerminate, ProcessSignalKill} {
		if err := proc.Signal(context.Background(), kind); err != nil {
			t.Fatalf("Signal(%d) on confirmed-terminal process: %v", kind, err)
		}
	}
	assertNoCallWithin(t, fake.onCall, 50*time.Millisecond)
	if got := len(fake.snapshot()); got != 0 {
		t.Fatalf("signaler calls on a confirmed-terminal process = %d, want 0", got)
	}
}

// TestProcessSignalNaturalExitRaceIsRaceFree drives a genuine concurrent race
// between the process becoming terminal and a terminate escalation reaching
// its grace deadline, run under -race, proving the state machine never
// panics, never hangs, and never double-dispatches regardless of which side
// wins.
func TestProcessSignalNaturalExitRaceIsRaceFree(t *testing.T) {
	for i := 0; i < 50; i++ {
		fake := &recordingSignaler{}
		grace := make(chan time.Time, 1)
		proc := newSignalTestProcess(fake, fixedGraceTimer(grace))

		if err := proc.Signal(context.Background(), ProcessSignalTerminate); err != nil {
			t.Fatalf("iteration %d: Signal(Terminate): %v", i, err)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			close(proc.done)
		}()
		go func() {
			defer wg.Done()
			grace <- time.Now()
		}()
		wg.Wait()

		// Whichever side "won" the race inside escalateAfterGrace's select,
		// give its goroutine a bounded window to finish (it does at most one
		// non-blocking dispatchKill call, so this margin is generous), then
		// confirm the outcome is stable: at most one kill, and no further
		// kill arrives later regardless of who won.
		time.Sleep(20 * time.Millisecond)
		firstCount := fake.count("kill")
		if firstCount > 1 {
			t.Fatalf("iteration %d: kill deliveries = %d, want at most 1", i, firstCount)
		}
		time.Sleep(20 * time.Millisecond)
		if got := fake.count("kill"); got != firstCount {
			t.Fatalf("iteration %d: kill deliveries changed after settling: %d -> %d", i, firstCount, got)
		}
		if got := fake.count("terminate"); got != 1 {
			t.Fatalf("iteration %d: terminate deliveries = %d, want exactly 1", i, got)
		}

		// Idempotence still holds post-race regardless of who won.
		if err := proc.Signal(context.Background(), ProcessSignalKill); err != nil {
			t.Fatalf("iteration %d: post-race Signal(Kill): %v", i, err)
		}
	}
}

// TestProcessSignalNilProcessIsClosedError proves Signal on a nil *Process
// (mirroring every other Process method's nil-receiver contract in this
// file) reports ErrProcessClosed rather than panicking.
func TestProcessSignalNilProcessIsClosedError(t *testing.T) {
	var proc *Process
	if err := proc.Signal(context.Background(), ProcessSignalInterrupt); !errors.Is(err, ErrProcessClosed) {
		t.Fatalf("nil Process Signal error = %v, want %v", err, ErrProcessClosed)
	}
}

// TestProcessSignalInvalidKindIsRejected proves an out-of-range ProcessSignal
// is rejected before ever reaching the signaler, and does not require a
// signaler to be present to fail this way.
func TestProcessSignalInvalidKindIsRejected(t *testing.T) {
	proc := newSignalTestProcess(nil, nil)
	for _, kind := range []ProcessSignal{0, ProcessSignalKill + 1, ProcessSignal(255)} {
		if err := proc.Signal(context.Background(), kind); err == nil {
			t.Fatalf("Signal(%d) = nil error, want a validation error", kind)
		}
	}
}

// TestProcessSignalCanceledContextIsRejected proves an already-canceled ctx
// is honored before any signal is delivered.
func TestProcessSignalCanceledContextIsRejected(t *testing.T) {
	fake := &recordingSignaler{}
	proc := newSignalTestProcess(fake, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := proc.Signal(ctx, ProcessSignalInterrupt); !errors.Is(err, context.Canceled) {
		t.Fatalf("Signal with canceled ctx error = %v, want context.Canceled", err)
	}
	if got := len(fake.snapshot()); got != 0 {
		t.Fatalf("signaler calls with a canceled ctx = %d, want 0", got)
	}
}

// TestProcessSignalNilContextDefaultsToBackground proves a nil ctx is
// treated as context.Background, exactly like every other entry point in
// this package.
func TestProcessSignalNilContextDefaultsToBackground(t *testing.T) {
	fake := &recordingSignaler{onCall: make(chan string, 1)}
	proc := newSignalTestProcess(fake, nil)
	//lint:ignore SA1012 exercising the documented nil-context default.
	if err := proc.Signal(nil, ProcessSignalInterrupt); err != nil {
		t.Fatalf("Signal(nil ctx, Interrupt): %v", err)
	}
	waitForCall(t, fake.onCall, "interrupt")
}

// TestProcessSignalUnsupportedWithoutSignaler proves a not-yet-terminal
// Process with no signaler wired (every Process this microtask's own
// production constructors build, until a later microtask wires one) fails
// closed with ErrProcessSignalUnsupported for every signal kind, rather than
// silently succeeding or panicking on a nil interface call.
func TestProcessSignalUnsupportedWithoutSignaler(t *testing.T) {
	for _, kind := range []ProcessSignal{ProcessSignalInterrupt, ProcessSignalTerminate, ProcessSignalKill} {
		proc := newSignalTestProcess(nil, nil)
		if err := proc.Signal(context.Background(), kind); !errors.Is(err, ErrProcessSignalUnsupported) {
			t.Fatalf("Signal(%d) with no signaler = %v, want %v", kind, err, ErrProcessSignalUnsupported)
		}
	}
}

// TestProcessSignalTerminateGraceResolvesDefault proves
// resolveProcessTerminateGrace substitutes defaultProcessTerminateGrace for
// zero/negative input and passes a positive caller-specified value through
// unchanged — the "caller-specified (or default) grace period" contract
// ProcessOptions.TerminateGrace exposes.
func TestProcessSignalTerminateGraceResolvesDefault(t *testing.T) {
	tests := []struct {
		name  string
		input time.Duration
		want  time.Duration
	}{
		{name: "zero selects default", input: 0, want: defaultProcessTerminateGrace},
		{name: "negative selects default", input: -time.Second, want: defaultProcessTerminateGrace},
		{name: "positive value passes through", input: 250 * time.Millisecond, want: 250 * time.Millisecond},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveProcessTerminateGrace(tt.input); got != tt.want {
				t.Fatalf("resolveProcessTerminateGrace(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestProcessSignalCustomTerminateGraceIsUsedByEscalation proves a
// caller-specified ProcessOptions.TerminateGrace (threaded through to
// Process at construction) is the duration actually used to build the real
// grace timer, not silently replaced by the default.
func TestProcessSignalCustomTerminateGraceIsUsedByEscalation(t *testing.T) {
	var got time.Duration
	fake := &recordingSignaler{onCall: make(chan string, 2)}
	proc := &Process{
		done:           make(chan struct{}),
		terminateGrace: resolveProcessTerminateGrace(37 * time.Millisecond),
		signaler:       fake,
		graceTimer: func(d time.Duration) (<-chan time.Time, func()) {
			got = d
			return realGraceTimer(d)
		},
	}
	if err := proc.Signal(context.Background(), ProcessSignalTerminate); err != nil {
		t.Fatalf("Signal(Terminate): %v", err)
	}
	waitForCall(t, fake.onCall, "terminate")
	waitForCall(t, fake.onCall, "kill")
	if got != 37*time.Millisecond {
		t.Fatalf("grace timer duration = %v, want 37ms", got)
	}
}

// TestProcessSignalValidReportsClosedDomain proves ProcessSignal.Valid draws
// the line at exactly the three declared constants.
func TestProcessSignalValidReportsClosedDomain(t *testing.T) {
	tests := []struct {
		kind ProcessSignal
		want bool
	}{
		{0, false},
		{ProcessSignalInterrupt, true},
		{ProcessSignalTerminate, true},
		{ProcessSignalKill, true},
		{ProcessSignalKill + 1, false},
	}
	for _, tt := range tests {
		if got := tt.kind.Valid(); got != tt.want {
			t.Fatalf("ProcessSignal(%d).Valid() = %v, want %v", tt.kind, got, tt.want)
		}
	}
}
