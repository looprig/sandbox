package exec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
)

// This file adds the module's pipe-backed asynchronous process API alongside
// the existing synchronous, already-stabilized RunCommand/RunCommandWithGrants
// machinery in executor.go. It does not replace or duplicate that machinery: a
// later microtask refactors Executor.run onto the primitive defined here.
//
// Sandbox defines its own named types with method shapes that structurally
// match Harness's tool.AsyncProcessRunner/tool.PreparedProcess/tool.Process
// (github.com/looprig/harness/pkg/tool), using only stdlib types, so a
// separate consumer can adapt between the two without this module ever
// importing Harness (SPEC's module-boundary rule).
//
// Scope note: this microtask implements the public types, immutable effective
// access, live pipe streams, cached Wait, and the optional bounded activity
// stream ONLY. It intentionally spawns via a plain, unconfined os/exec.Cmd —
// no policy compilation, no grant/path resource retention (a later microtask
// owns that), and no signal/tree teardown (a later task owns that). TTY
// requests are rejected rather than silently downgraded, because pipe/PTY
// stream-mode fallback must never be silent (mirrors the Harness reference's
// documented contract).

// ProcessOptions describes one asynchronous process admission request.
// Grants are opaque, execution-bound tokens; this microtask does not verify
// them beyond a bare presence check when the executor's command authority is
// Gated; a later microtask consumes and cryptographically verifies them
// before spawn. A zero Deadline means no process-lifetime deadline.
type ProcessOptions struct {
	Directory   string
	Command     string
	ExecutionID string
	Grants      []string
	TTY         bool
	Deadline    time.Time
}

// clone returns a deep copy sharing no slice backing storage with the
// receiver, so a PreparedProcess never aliases the caller's Grants slice.
func (o ProcessOptions) clone() ProcessOptions {
	out := o
	if o.Grants != nil {
		out.Grants = append([]string(nil), o.Grants...)
	}
	return out
}

// ProcessAccessKind classifies the authoritative workspace write access
// reserved for a prepared process. It mirrors, structurally only, Harness's
// tool.WorkspaceAccessKind vocabulary (ReadOnly/ScopedWrite/BroadWrite) so a
// later adapter can translate directly; Sandbox defines its own stdlib-only
// type rather than importing Harness's.
type ProcessAccessKind uint8

const (
	// ProcessAccessReadOnly permits reads but no writes.
	ProcessAccessReadOnly ProcessAccessKind = iota + 1
	// ProcessAccessScopedWrite permits writes only to the paths and trees
	// reserved for this process. Real per-grant path reservation is a later
	// microtask's job; today WritePaths/WriteTrees are always empty.
	ProcessAccessScopedWrite
	// ProcessAccessBroadWrite permits writes anywhere the executor's
	// workspace authority allows.
	ProcessAccessBroadWrite
)

// Valid reports whether k is a recognized process access classification.
func (k ProcessAccessKind) Valid() bool {
	return k >= ProcessAccessReadOnly && k <= ProcessAccessBroadWrite
}

// ProcessAccess is the authoritative, immutable description of a prepared
// process's workspace access, captured once during PrepareProcess.
// WritePaths/WriteTrees return a defensive copy sharing no backing storage
// with the receiver or with any other call, so a caller can never mutate the
// preparation's authoritative state through the returned value.
type ProcessAccess struct {
	Kind       ProcessAccessKind
	writePaths []string
	writeTrees []string
}

// newProcessAccess constructs a ProcessAccess without retaining the caller's
// path slices.
func newProcessAccess(kind ProcessAccessKind, writePaths, writeTrees []string) ProcessAccess {
	return ProcessAccess{
		Kind:       kind,
		writePaths: cloneProcessStrings(writePaths),
		writeTrees: cloneProcessStrings(writeTrees),
	}
}

// WritePaths returns a defensive copy of the canonical individual write
// paths. Meaningful only for ProcessAccessScopedWrite.
func (a ProcessAccess) WritePaths() []string { return cloneProcessStrings(a.writePaths) }

// WriteTrees returns a defensive copy of the canonical write directory
// trees. Meaningful only for ProcessAccessScopedWrite.
func (a ProcessAccess) WriteTrees() []string { return cloneProcessStrings(a.writeTrees) }

func cloneProcessStrings(values []string) []string {
	if values == nil {
		return nil
	}
	out := make([]string, len(values))
	copy(out, values)
	return out
}

// PreparedProcess is a validated, single-use process start. Its effective
// workspace access (EffectiveAccess) is authoritative and immutable for the
// lifetime of the value. Start consumes the preparation at most once; Close
// releases an unstarted preparation and is otherwise idempotent and safe to
// call at any time, including after Start.
type PreparedProcess struct {
	options ProcessOptions
	access  ProcessAccess

	mu      sync.Mutex
	started bool
	closed  bool
}

// PrepareProcess validates opts and reserves this executor's effective
// process access without spawning anything. The executor's command authority
// is checked immediately (Deny always refuses; Gated refuses without at least
// one supplied grant); real per-grant cryptographic verification and
// filesystem-path reservation are a later microtask's job.
func (e *Executor) PrepareProcess(ctx context.Context, opts ProcessOptions) (*PreparedProcess, error) {
	if e == nil {
		return nil, ErrExecutorClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if opts.TTY {
		return nil, ErrProcessTTYUnsupported
	}
	if !validGrantText(opts.Command) {
		return nil, fmt.Errorf("%w: command", ErrGrantMalformed)
	}
	if !validGrantText(opts.ExecutionID) {
		return nil, fmt.Errorf("%w: execution id", ErrGrantMalformed)
	}
	dir, err := canonicalWorkingDirectory(opts.Directory)
	if err != nil {
		return nil, fmt.Errorf("%w: directory: %v", ErrGrantMalformed, err)
	}
	if err := e.processCommandAccess(opts); err != nil {
		return nil, err
	}

	prepared := opts.clone()
	prepared.Directory = dir

	return &PreparedProcess{
		options: prepared,
		access:  e.effectiveProcessAccess(),
	}, nil
}

// processCommandAccess is PrepareProcess's authorization check. It mirrors
// Executor.commandAccess's three-way switch on the profile's command
// authority, with the addition Gated needs here: RunCommand has no grants
// parameter at all, so it always demands a grant; PrepareProcess accepts a
// Grants list and only demands that it be non-empty. Cryptographic
// verification of those grants is a later microtask's job.
func (e *Executor) processCommandAccess(opts ProcessOptions) error {
	e.grantMu.Lock()
	defer e.grantMu.Unlock()
	if e.closed {
		return ErrExecutorClosed
	}
	if e.profile == nil {
		return nil
	}
	switch e.settings.Command {
	case Allow:
		return nil
	case Gated:
		if len(opts.Grants) == 0 {
			return ErrGrantRequired
		}
		return nil
	default:
		return ErrGrantDenied
	}
}

// effectiveProcessAccess derives the authoritative ProcessAccess from the
// same profile.Settings.WorkspaceWrite authority the synchronous path already
// reads for every other authorization decision (see Executor.commandAccess
// and Executor.authorizeGrantScope). Write path/tree resolution from real
// per-grant reservations is a later microtask's job; today the set is always
// empty.
func (e *Executor) effectiveProcessAccess() ProcessAccess {
	kind := ProcessAccessReadOnly
	if e != nil && e.profile != nil {
		switch e.settings.WorkspaceWrite {
		case Allow:
			kind = ProcessAccessBroadWrite
		case Gated:
			kind = ProcessAccessScopedWrite
		default:
			kind = ProcessAccessReadOnly
		}
	}
	return newProcessAccess(kind, nil, nil)
}

// EffectiveAccess returns the authoritative workspace access reserved for
// this preparation. The returned value shares no mutable backing storage
// with the preparation or with any earlier or later call, and never changes
// across the preparation's lifetime (including after Start or Close).
func (p *PreparedProcess) EffectiveAccess() ProcessAccess {
	if p == nil {
		return ProcessAccess{}
	}
	return newProcessAccess(p.access.Kind, p.access.writePaths, p.access.writeTrees)
}

// Start consumes the preparation and spawns the process. A second Start call
// on the same PreparedProcess, or any Start call after Close, fails without
// spawning. A spawn/setup failure (missing directory, binary not found) is
// returned as an error and no Process is returned; a process that
// subsequently runs to a non-zero exit is not an error and is reported
// through Process.Wait's ProcessResult instead.
func (p *PreparedProcess) Start(ctx context.Context) (*Process, error) {
	if p == nil {
		return nil, ErrProcessClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	p.mu.Lock()
	switch {
	case p.closed:
		p.mu.Unlock()
		return nil, ErrProcessClosed
	case p.started:
		p.mu.Unlock()
		return nil, ErrProcessAlreadyStarted
	}
	p.started = true
	p.mu.Unlock()

	return spawnProcess(ctx, p.options)
}

// Close releases an unstarted preparation's reservations and is idempotent.
// Once Start has consumed the preparation, ownership of anything reserved
// has already transferred to the returned Process, so a later Close is a
// harmless no-op rather than an error.
func (p *PreparedProcess) Close() error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.started {
		return nil
	}
	return p.releaseReservations()
}

// releaseReservations is the seam a later microtask extends with real
// grant/path resource release. PrepareProcess reserves nothing beyond
// validating input and snapshotting effective access in this microtask, so
// it is a no-op today.
func (p *PreparedProcess) releaseReservations() error {
	return nil
}

// spawnProcess performs the actual, unconfined OS spawn for one prepared
// request. It is a free function (rather than a PreparedProcess method) so it
// can be exercised directly by tests that need to observe spawn-failure
// behavior independent of PreparedProcess's single-use guard.
//
// ctx governs only the brief setup window up to and including the decision to
// call cmd.Start(): if ctx is already done, the spawn is aborted and no
// Process is ever returned. ctx is deliberately NOT plumbed into cmd (e.g. via
// exec.CommandContext) and is never consulted again once cmd.Start() has been
// called — the returned Process's lifetime (Wait, stream I/O) is intentionally
// independent of ctx, exactly as PreparedProcess.Start's contract promises: a
// caller canceling the ctx it passed to Start after a Process has already been
// handed back must not kill that process. A nil ctx is treated as
// context.Background(), matching every other entry point in this file.
func spawnProcess(ctx context.Context, opts ProcessOptions) (*Process, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	argv := enforce.ShellArgv(opts.Command)
	if len(argv) == 0 {
		return nil, errors.New("sandbox: process argv is empty")
	}

	outR, outW, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		return nil, errors.Join(err, outR.Close(), outW.Close())
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, errors.Join(err, outR.Close(), outW.Close(), errR.Close(), errW.Close())
	}

	// #nosec G204 -- launching a caller-supplied command IS this module's
	// purpose; see the identical justification on Executor.run. This path is
	// deliberately a plain, unconfined os/exec.Cmd: enforcement/confinement
	// wiring for the pipe-backed process is explicitly a later microtask's
	// scope, not this one's.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = opts.Directory
	cmd.Stdout = outW
	cmd.Stderr = errW
	cmd.Stdin = inR

	// Re-check as close to the actual OS spawn as this function gets, so a
	// cancellation that lands after Start's own entry check but before the
	// fork/exec syscall still aborts the handoff instead of racing it.
	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, outR.Close(), outW.Close(), errR.Close(), errW.Close(), inR.Close(), inW.Close())
	}

	startErr := cmd.Start()
	// Whether or not Start succeeded, the parent must drop its own reference
	// to the three child-side descriptors: exec inherits file descriptors
	// into the child without closing the parent's copy, so a parent-side leak
	// here would keep the corresponding reader from ever observing EOF.
	closeErr := errors.Join(outW.Close(), errW.Close(), inR.Close())
	if startErr != nil {
		// A spawn/setup failure is an error, never a Process: the caller must
		// key on err, exactly as the synchronous RunCommand/RunArgv contract
		// already requires (see executor.go's exit-code convention doc).
		return nil, errors.Join(startErr, closeErr, outR.Close(), errR.Close(), inW.Close())
	}
	if closeErr != nil {
		// Extremely unlikely (closing freshly-opened, freshly-inherited
		// descriptors), but a leaked child-side descriptor would silently
		// wedge EOF forever: fail closed rather than return a Process whose
		// streams may never terminate, and reap the child we already started.
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return nil, errors.Join(closeErr, outR.Close(), errR.Close(), inW.Close())
	}

	return &Process{
		cmd:        cmd,
		stdout:     outR,
		stderr:     errR,
		stdin:      newProcessStdin(inW),
		startedAt:  time.Now(),
		activities: make(chan ProcessActivity),
		done:       make(chan struct{}),
	}, nil
}

// Process is a running asynchronous process. Stdout/Stderr/Stdin are real,
// live pipes available immediately after Start — the caller reads and writes
// incrementally, not only after the process exits. Methods other than Wait
// are safe to call concurrently with each other and with stream I/O. Wait is
// cached: every caller (concurrent or sequential) observes the same result,
// and the underlying OS wait happens exactly once. Process deliberately
// exposes no OS process identifier; a model-facing process handle belongs in
// a higher layer, not this one.
type Process struct {
	cmd    *exec.Cmd
	stdout io.ReadCloser
	stderr io.ReadCloser
	stdin  *processStdin

	startedAt time.Time

	// activities is the optional, bounded typed activity stream. Nothing
	// producer-side exists in this microtask, so it is closed as soon as the
	// process reaches a terminal state, which already satisfies "closes
	// before Wait returns" ahead of a later microtask wiring a real producer
	// that sends into it over the process's lifetime.
	activities chan ProcessActivity

	waitStart sync.Once
	done      chan struct{}
	result    ProcessResult
	resultErr error

	closeOnce sync.Once
	closeErr  error
}

// Stdout returns the process's live standard-output pipe.
func (p *Process) Stdout() io.ReadCloser {
	if p == nil {
		return nil
	}
	return p.stdout
}

// Stderr returns the process's live standard-error pipe, distinct from
// Stdout in this pipe-backed mode.
func (p *Process) Stderr() io.ReadCloser {
	if p == nil {
		return nil
	}
	return p.stderr
}

// Stdin returns the process's standard-input pipe. Concurrent Write and
// Close calls are supported; Close is idempotent, delivers EOF to the
// process at most once, and causes later writes to fail with
// ErrProcessStdinClosed.
func (p *Process) Stdin() io.WriteCloser {
	if p == nil {
		return nil
	}
	return p.stdin
}

// Activities returns the optional typed workspace-activity stream. It closes
// before Wait returns to any caller.
func (p *Process) Activities() <-chan ProcessActivity {
	if p == nil {
		return nil
	}
	return p.activities
}

// ProcessResult is the terminal result of an asynchronous process. ExitCode
// is the portable executable exit status. OS process identifiers are
// intentionally excluded. A ran-but-non-zero process is reported here with a
// nil error, exactly like the synchronous RunCommand/RunArgv convention; a
// process that never spawned is reported by PreparedProcess.Start's error
// instead, never through this type.
type ProcessResult struct {
	ExitCode   int
	StartedAt  time.Time
	FinishedAt time.Time
}

// Wait blocks until the process reaches a terminal state or ctx is done,
// whichever comes first. Multiple concurrent (or sequential) callers observe
// the identical result; the real OS wait happens exactly once regardless of
// how many callers or contexts are involved. A ctx that is done before the
// process exits does not stop or kill the process — it only stops this call
// from waiting for it — so a caller with a fresh context can still retrieve
// the eventual result.
func (p *Process) Wait(ctx context.Context) (ProcessResult, error) {
	if p == nil {
		return ProcessResult{}, ErrProcessClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	p.waitStart.Do(func() { go p.runWait() })
	select {
	case <-p.done:
		return p.result, p.resultErr
	case <-ctx.Done():
		return ProcessResult{}, ctx.Err()
	}
}

// runWait performs the single real OS wait for this process. It is started
// by exactly one Wait caller's sync.Once and every other caller (concurrent
// or later) only ever observes its result through the done channel's
// happens-before guarantee.
func (p *Process) runWait() {
	err := p.cmd.Wait()
	finishedAt := time.Now()
	// The activity stream must close before any Wait caller can observe a
	// result; closing here, strictly before result/done, guarantees that
	// ordering for every current and future caller.
	close(p.activities)

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		p.result = ProcessResult{ExitCode: 0, StartedAt: p.startedAt, FinishedAt: finishedAt}
	case errors.As(err, &exitErr):
		// A ran-but-non-zero process is a result, not an error: mirrors the
		// synchronous RunCommand/RunArgv exit-code convention exactly.
		p.result = ProcessResult{ExitCode: exitErr.ExitCode(), StartedAt: p.startedAt, FinishedAt: finishedAt}
	default:
		// A genuine post-spawn failure (e.g. an I/O teardown error): distinct
		// from both a clean exit and a non-zero exit.
		p.resultErr = err
	}
	close(p.done)
}

// Close closes the process's stream handles. It is idempotent. It does not
// signal or wait for the OS process itself — process-tree teardown is a
// later task's scope — so a caller that wants the process to actually exit
// must still arrange that separately (e.g. by closing stdin or waiting for
// natural completion) until that later task lands.
func (p *Process) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	_ = ctx // reserved for the later task that adds signal/teardown semantics
	p.closeOnce.Do(func() {
		var err error
		if p.stdin != nil {
			err = errors.Join(err, p.stdin.Close())
		}
		if p.stdout != nil {
			err = errors.Join(err, p.stdout.Close())
		}
		if p.stderr != nil {
			err = errors.Join(err, p.stderr.Close())
		}
		p.closeErr = err
	})
	return p.closeErr
}

// processStdin wraps the exec.Cmd stdin pipe so Write and Close are safe to
// call concurrently, Close is idempotent and delivers EOF at most once, and a
// write after Close fails instead of racing the underlying *os.File.
type processStdin struct {
	mu     sync.Mutex
	w      io.WriteCloser
	closed bool
}

func newProcessStdin(w io.WriteCloser) *processStdin { return &processStdin{w: w} }

func (s *processStdin) Write(data []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return 0, ErrProcessStdinClosed
	}
	return s.w.Write(data)
}

func (s *processStdin) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return s.w.Close()
}

// ProcessActivityKind classifies process-reported workspace activity.
// Mirrors, structurally only, Harness's tool.WorkspaceActivityKind.
type ProcessActivityKind uint8

const (
	// ProcessActivityWrite reports filesystem activity within the immutable
	// access reserved by the prepared process.
	ProcessActivityWrite ProcessActivityKind = iota + 1
	// ProcessActivityBroadWrite requests conservative broad invalidation.
	ProcessActivityBroadWrite
)

// Valid reports whether k is a recognized process activity kind.
func (k ProcessActivityKind) Valid() bool {
	return k >= ProcessActivityWrite && k <= ProcessActivityBroadWrite
}

// ProcessActivity reports one unit of workspace activity from a running
// process.
type ProcessActivity struct {
	Kind ProcessActivityKind
}

// EffectiveKind returns the conservative activity classification. Invalid
// activity always maps to broad invalidation and can never narrow the
// immutable lifetime workspace access reserved by ProcessAccess.
func (a ProcessActivity) EffectiveKind() ProcessActivityKind {
	if !a.Kind.Valid() {
		return ProcessActivityBroadWrite
	}
	return a.Kind
}
