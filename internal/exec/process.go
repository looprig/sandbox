package exec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
)

// This file adds the module's pipe-backed asynchronous process API alongside
// the existing synchronous, already-stabilized RunCommand/RunCommandWithGrants
// machinery in executor.go. PrepareProcess/Start reuse that machinery's
// lower-level pieces directly (grant validation, path handle acquisition,
// route/proxy authorization, backend compilation, the executionLease/
// quarantinedSpawn ownership primitives, and processTree confinement) rather
// than duplicating a second implementation of any of it; RunCommand/
// RunCommandWithGrants themselves are untouched (their exact synchronous
// behavior stays byte-for-byte the same, as characterized in Task 10C).
//
// Sandbox defines its own named types with method shapes that structurally
// match Harness's tool.AsyncProcessRunner/tool.PreparedProcess/tool.Process
// (github.com/looprig/harness/pkg/tool), using only stdlib types, so a
// separate consumer can adapt between the two without this module ever
// importing Harness (SPEC's module-boundary rule).
//
// PrepareProcess performs one complete grant-redemption-plus-resource-
// reservation transaction (validating and consuming any supplied grants,
// acquiring and retaining path handles, authorizing a route/proxy credential,
// and compiling the confined backend spec) without spawning a child. Start
// atomically transfers everything reserved into a process-owned background
// goroutine that outlives the call, confining the actual spawn through the
// same processTree/backend machinery executor.run already uses. TTY requests
// are honored with a real platform PTY where one exists (Unix, via
// terminal_unix.go) and rejected outright everywhere else
// (ErrProcessTTYUnsupported, terminal_other.go) rather than silently
// downgraded to pipes — pipe/PTY stream-mode fallback must never be silent
// (mirrors the Harness reference's documented contract).

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
	// TerminateGrace bounds how long a terminate signal (see
	// ProcessSignalTerminate) is given to produce a natural exit before
	// Process.Signal escalates to exactly one kill. Zero or negative selects
	// defaultProcessTerminateGrace.
	TerminateGrace time.Duration
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

// defaultProcessTerminateGrace is the terminate-to-kill escalation window a
// ProcessOptions with a zero or negative TerminateGrace resolves to.
const defaultProcessTerminateGrace = 5 * time.Second

// resolveProcessTerminateGrace normalizes a caller-specified terminate grace
// period, substituting defaultProcessTerminateGrace for any non-positive
// value so a Process always carries a usable escalation window.
func resolveProcessTerminateGrace(d time.Duration) time.Duration {
	if d <= 0 {
		return defaultProcessTerminateGrace
	}
	return d
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
	// reserved for this process: WritePaths/WriteTrees report the exact
	// canonical filesystem write grants folded into this preparation.
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
// lifetime of the value. PrepareProcess performs the entire grant-redemption
// and resource-reservation transaction (any supplied grants are validated,
// authenticated, and consumed; retained path handles are borrowed and
// re-acquired; a route/proxy credential is authorized; the confined backend
// spec is compiled) before this value is ever returned, so by the time a
// caller holds a *PreparedProcess every reservation it needs is already
// final and a single-spawn grant can never become replayable regardless of
// whether Start is ever called. Start consumes the preparation at most once,
// atomically transferring every reservation to the spawned Process's
// background supervisor. Close releases an unstarted preparation's
// reservations and is otherwise idempotent and safe to call at any time,
// including after Start (a no-op once Start has consumed it).
type PreparedProcess struct {
	options ProcessOptions
	access  ProcessAccess

	executor *Executor
	lease    *executionLease
	argv     []string
	snapshot snapshot
	// spawn is the single ownership capsule for this preparation, created
	// once PrepareProcess succeeds and reused (never replaced) through Start
	// and terminal cleanup — the same quarantinedSpawn primitive
	// executor.run/runBackendOwned already use for the synchronous path, so
	// there is exactly one cleanup system regardless of how a process was
	// started. Its afterExecution list already carries every grant/path/
	// proxy/compiled-backend release this preparation reserved; releasing it
	// (spawn.release) or quarantining it (spawn.transferTo) is the only way
	// any of that is ever torn down.
	spawn *quarantinedSpawn

	mu      sync.Mutex
	started bool
	closed  bool
}

// PrepareProcess validates opts and performs the complete grant-redemption
// and resource-reservation transaction for this process without spawning
// anything: the executor's command authority is checked (Deny always
// refuses; Gated refuses without at least one supplied grant), any supplied
// grants are cryptographically verified and consumed exactly like
// Executor.RunCommandWithGrants, retained filesystem path handles are
// borrowed and re-acquired, a route/proxy credential is authorized when a
// network grant requires one, and the confined backend spec is compiled. A
// failure at any point releases every partial reservation exactly once and
// leaves nothing consumed that could later replay. Supplying no grants
// resolves the same plain (non-grant) access RunCommand/RunArgv already use.
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
	// ttySupported is true on Unix (terminal_unix.go) and false everywhere
	// else (terminal_other.go, including Windows until a later phase wires
	// ConPTY): a TTY request on a platform with no real PTY primitive is
	// rejected here, before any reservation, exactly like before this
	// package had PTY support at all — never silently downgraded to pipes.
	if opts.TTY && !ttySupported {
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

	argv := enforce.ShellArgv(prepared.Command)
	if len(argv) == 0 {
		return nil, errors.New("sandbox: process argv is empty")
	}

	// lease is deliberately begun with context.Background() as its caller,
	// not ctx: exactly like Start's own ctx, PrepareProcess's ctx must only
	// ever govern this call's own setup window, never the eventual process's
	// lifetime. The lease's ctx is instead cancelled only by explicit session/
	// executor-set close (via the lifecycle.ctx AfterFunc hook) or by this
	// preparation's own ProcessOptions.Deadline once a later task wires it.
	lease, err := e.beginExecution(context.Background())
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			lease.finish()
		}
	}()

	resolved, err := e.resolveProcessResources(ctx, prepared, argv)
	if err != nil {
		return nil, err
	}

	spawn := newQuarantinedSpawn(nil, nil, lease)
	spawn.observe = resolved.observe
	spawn.afterExecution = resolved.releases

	proc := &PreparedProcess{
		options:  prepared,
		access:   resolved.access,
		executor: e,
		lease:    lease,
		argv:     argv,
		snapshot: resolved.snapshot,
		spawn:    spawn,
	}
	transferred = true

	if !lease.lifecycle.registerPrepared(proc) {
		// The executor set began closing between beginExecution and here.
		// Nothing has been handed back to any caller yet, so release the
		// whole transaction immediately rather than returning a live handle
		// admission has already closed against.
		_ = proc.Close()
		return nil, ErrExecutorClosed
	}
	return proc, nil
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

// effectiveProcessAccess derives the base ProcessAccess from the same
// profile.Settings.WorkspaceWrite authority the synchronous path already
// reads for every other authorization decision (see Executor.commandAccess
// and Executor.authorizeGrantScope), with no per-grant deltas folded in. It
// is the whole answer for a grant-free preparation, and the starting point
// resolveGrantedProcessResources widens with approved deltas otherwise.
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

// preparedResourceSet is everything PrepareProcess's grant-redemption and
// resource-reservation transaction produces: the authoritative access, the
// compiled spawn snapshot Start confines through, and the release closures
// (spec release, retained path handle close, proxy credential release) that
// must run exactly once when the eventual process reaches a terminal state —
// on prepare failure, on an unstarted Close, or (transferred whole) after
// Start's spawned process is confirmed gone.
type preparedResourceSet struct {
	access   ProcessAccess
	snapshot snapshot
	releases []func() error
	// observe fires once, immediately after a successful zero proof and
	// before the proxy credential is released, exactly like the synchronous
	// path's denial-observation point (see executor.run/runCommandWithGrants).
	observe func()
}

// resolveProcessResources dispatches PrepareProcess's transaction: a request
// with no grants resolves the same plain (non-grant) access RunCommand/
// RunArgv already use; PrepareProcess's own processCommandAccess check
// already guarantees that reaching this branch with zero grants means the
// executor's command authority is Allow (Gated demands at least one grant,
// Deny always refuses before this point), matching RunCommand's authority
// exactly.
func (e *Executor) resolveProcessResources(ctx context.Context, opts ProcessOptions, argv []string) (preparedResourceSet, error) {
	if len(opts.Grants) == 0 {
		return e.resolvePlainProcessResources()
	}
	return e.resolveGrantedProcessResources(ctx, opts)
}

// resolvePlainProcessResources mirrors RunCommand/RunArgv's own resolve +
// prepareAllowedRoute path: the executor's already-compiled base spec is
// reused as-is (never released per spawn — its lifetime belongs to the
// Executor as a whole, released once via Executor.releaseCompiledSpec), and
// a Network:Allow route/proxy credential is authorized automatically exactly
// like the synchronous path.
func (e *Executor) resolvePlainProcessResources() (preparedResourceSet, error) {
	s, err := e.resolve()
	if err != nil {
		return preparedResourceSet{}, err
	}
	s, executionID, err := e.prepareAllowedRoute(s)
	if err != nil {
		return preparedResourceSet{}, err
	}
	var releases []func() error
	if executionID != "" {
		releases = append(releases, func() error { e.proxy.Release(executionID); return nil })
	}
	return preparedResourceSet{
		access:   e.effectiveProcessAccess(),
		snapshot: s,
		releases: releases,
	}, nil
}

// resolveGrantedProcessResources performs the identical grant-verification,
// path-handle-acquisition, guarantee-recomputation, route-authorization, and
// backend-compilation transaction Executor.runCommandWithGrants already
// performs — reusing the same package-private helpers (authenticateGrant,
// verifyGrantBinding, validateGrantClass, compileBackendWithGrantPaths, the
// retainedGrantPaths borrow/commit machinery, …) rather than a second
// implementation of any of it — but stops short of ever spawning: it commits
// the retained path handles and marks every consumed grant used (so the
// preparation's single-spawn consumption is final regardless of whether
// Start is ever called), then returns the compiled snapshot and every
// release closure the eventual process must run exactly once, instead of
// calling Executor.run.
func (e *Executor) resolveGrantedProcessResources(ctx context.Context, opts ProcessOptions) (preparedResourceSet, error) {
	if err := ctx.Err(); err != nil {
		return preparedResourceSet{}, err
	}
	acquire := grantPathAcquirer(policy.AcquirePathHandle)
	if backend, ok := e.backend.(grantACLPathAcquirer); ok {
		acquire = backend.AcquireGrantPathHandle
	}

	e.grantMu.Lock()
	defer e.grantMu.Unlock()
	if e.closed {
		return preparedResourceSet{}, ErrExecutorClosed
	}
	if e.profile == nil {
		return preparedResourceSet{}, ErrInvalidProfile
	}
	pol := policy.Clone(e.policy)
	now := e.clock()
	e.pruneUsedGrantsLocked(now.UnixMilli())
	e.retainedGrantPaths.prune(now.UnixMilli())
	e.rescheduleRetainedGrantExpiryLocked()
	seen := make(map[[32]byte]int64, len(opts.Grants))
	commandGrant := e.settings.Command == Allow
	expectedGuarantees := e.guaranteeBits
	var proxyTargets []NetworkTarget
	var pendingPaths []pendingGrantPath
	var writePaths, writeTrees []string
	broadWriteGranted := false
	var pathHandles policy.PathHandleSet
	releaseHandlesOnReturn := true
	defer func() {
		if releaseHandlesOnReturn {
			pathHandles.Close()
		}
	}()

	for _, token := range opts.Grants {
		id := grantID(token)
		if _, ok := e.usedGrants[id]; ok {
			return preparedResourceSet{}, ErrGrantReplay
		}
		if _, ok := seen[id]; ok {
			return preparedResourceSet{}, ErrGrantReplay
		}
		seen[id] = 0
		payload, err := authenticateGrant(e.grantKey, token)
		if err != nil {
			return preparedResourceSet{}, err
		}
		if err := verifyGrantBinding(payload, now, opts.ExecutionID, opts.Command, opts.Directory, e.settings.Fingerprint, e.routeFingerprint, e.guaranteeBits); err != nil {
			return preparedResourceSet{}, err
		}
		seen[id] = payload.ExpiryUnixMilli
		delta, requiredBits, err := validateGrantClass(classKind(payload.Class), classScope(payload.Class, payload.Target), payload.Class, payload.Target)
		if err != nil {
			return preparedResourceSet{}, err
		}
		if !e.supportsGrantClass(payload.Class) {
			return preparedResourceSet{}, ErrGrantUnsupported
		}
		if requiredBits != 0 && e.guaranteeBits&requiredBits != requiredBits {
			return preparedResourceSet{}, ErrGrantGuaranteeMismatch
		}
		if delta.entry != nil && filepath.IsAbs(delta.entry.Path) {
			pendingPaths = append(pendingPaths, pendingGrantPath{
				id: id, binding: payload.PathBinding, target: delta.entry.Path,
				exact: delta.entry.Exact, access: delta.entry.Access,
				expiryUnixMilli: payload.ExpiryUnixMilli,
			})
			if delta.entry.Access&policy.WriteAccess != 0 {
				switch {
				case delta.entry.Path == string(filepath.Separator) && !delta.entry.Exact:
					// filesystem.host.write.v1: authority everywhere the
					// executor's workspace authority allows, not one path.
					broadWriteGranted = true
				case delta.entry.Exact:
					writePaths = append(writePaths, delta.entry.Path)
				default:
					writeTrees = append(writeTrees, delta.entry.Path)
				}
			}
		}
		if delta.class == GrantClassCommandStart {
			if payload.Target != opts.Command {
				return preparedResourceSet{}, ErrGrantWrongCommand
			}
			commandGrant = true
		}
		if delta.entry != nil {
			pol.FS = applyFilesystemGrant(pol.FS, *delta.entry)
		}
		dropped := delta.droppedGuarantees
		if dropped&GuaranteeReadBoundary != 0 && policy.IsAccessRestricted(pol.FS, policy.ReadAccess|policy.ExecAccess) {
			dropped &^= GuaranteeReadBoundary
		}
		if dropped&GuaranteeWriteBoundary != 0 && policy.IsAccessRestricted(pol.FS, policy.WriteAccess) {
			dropped &^= GuaranteeWriteBoundary
		}
		expectedGuarantees &^= dropped
		if delta.port != 0 && !policy.ContainsPort(pol.Net.Ports, delta.port) {
			pol.Net.Ports = append(pol.Net.Ports, delta.port)
		}
		pol.Net.DNS = pol.Net.DNS || delta.dns
		if delta.target != nil {
			proxyTargets = append(proxyTargets, *delta.target)
		}
	}
	if e.settings.Command == Deny {
		return preparedResourceSet{}, ErrGrantDenied
	}
	if !commandGrant {
		return preparedResourceSet{}, ErrGrantRequired
	}
	if len(proxyTargets) != 0 {
		if e.proxy == nil {
			return preparedResourceSet{}, ErrGrantUnsupported
		}
		_, portText, err := net.SplitHostPort(e.proxy.Addr())
		if err != nil {
			return preparedResourceSet{}, ErrGrantUnsupported
		}
		port, err := strconv.ParseUint(portText, 10, 16)
		if err != nil || port == 0 {
			return preparedResourceSet{}, ErrGrantUnsupported
		}
		pol.Net = policy.NetPolicy{ProxyPort: uint16(port)}
	}
	for _, pending := range pendingPaths {
		retained, err := e.retainedGrantPaths.borrow(pending.id, pending.binding, pending.target, pending.exact, pending.expiryUnixMilli)
		if err != nil {
			return preparedResourceSet{}, err
		}
		validation, err := acquire(pending.binding, pending.target, pending.exact)
		if err != nil {
			return preparedResourceSet{}, err
		}
		retainedHandle, retainedIsPathHandle := retained.(*policy.PathHandle)
		if retainedIsPathHandle != (validation != nil) ||
			(retainedIsPathHandle && !policy.SamePathHandleIdentity(retainedHandle, validation)) {
			if validation != nil {
				_ = validation.Close()
			}
			return preparedResourceSet{}, ErrGrantTargetChanged
		}
		if validation != nil {
			validation.SetAccess(pending.access)
			if err := pathHandles.Add(validation); err != nil {
				return preparedResourceSet{}, err
			}
		}
	}
	spec, _, _, bits, err := compileBackendWithGrantPaths(e.backend, e.spec.GrantAuthority, e.policy, pol, pathHandles.Sorted())
	if err != nil {
		return preparedResourceSet{}, err
	}
	bits = e.composeRouteGuarantees(bits)
	if bits != expectedGuarantees {
		return preparedResourceSet{}, errors.Join(ErrGrantGuaranteeMismatch, releaseSpec(spec))
	}
	var releases []func() error
	releases = append(releases, func() error { return releaseSpec(spec) })
	var observe func()
	if len(proxyTargets) != 0 {
		credential, err := e.proxy.Authorize(opts.ExecutionID, proxyTargets)
		if err != nil {
			return preparedResourceSet{}, errors.Join(err, releaseSpec(spec))
		}
		proxyURL := e.proxy.URL(opts.ExecutionID, credential)
		applyChildProxyEnv(pol.Env.Set, proxyURL)
		executionID := opts.ExecutionID
		observe = func() { _ = e.proxy.Denial(executionID) }
		releases = append(releases, func() error { e.proxy.Release(executionID); return nil })
	}
	pathIDs := make([][32]byte, len(pendingPaths))
	for i := range pendingPaths {
		pathIDs[i] = pendingPaths[i].id
	}
	retainedHandles, err := e.retainedGrantPaths.commit(pathIDs)
	if err != nil {
		return preparedResourceSet{}, errors.Join(err, releaseSpec(spec))
	}
	var retainedCloseErr error
	for _, handle := range retainedHandles {
		retainedCloseErr = errors.Join(retainedCloseErr, handle.Close())
	}
	if retainedCloseErr != nil {
		return preparedResourceSet{}, errors.Join(retainedCloseErr, releaseSpec(spec))
	}
	for id, expiryUnixMilli := range seen {
		e.usedGrants[id] = expiryUnixMilli
	}
	e.rescheduleRetainedGrantExpiryLocked()

	// Everything below this point is final: the grants are marked used and
	// the retained placeholders are already gone, so ownership of the fresh
	// validation path handles transfers to the returned resource set
	// regardless of what happens next in this function (there is nothing
	// left that can fail).
	releaseHandlesOnReturn = false
	handles := pathHandles
	releases = append(releases, func() error { handles.Close(); return nil })

	access := e.effectiveProcessAccess()
	kind := access.Kind
	switch {
	case broadWriteGranted:
		kind = ProcessAccessBroadWrite
		writePaths, writeTrees = nil, nil
	case len(writePaths) != 0 || len(writeTrees) != 0:
		if kind == ProcessAccessReadOnly {
			kind = ProcessAccessScopedWrite
		}
		if kind != ProcessAccessScopedWrite {
			// Base authority is already BroadWrite: the granular grant paths
			// add nothing EffectiveAccess doesn't already cover.
			writePaths, writeTrees = nil, nil
		}
	}

	return preparedResourceSet{
		access:   newProcessAccess(kind, writePaths, writeTrees),
		snapshot: snapshot{spec: spec, env: assembleEnv(pol), policy: pol},
		releases: releases,
		observe:  observe,
	}, nil
}

// Start consumes the preparation and spawns the process, confining it
// through the identical processTree/backend machinery Executor.run and
// Executor.runBackendOwned already use. A second Start call on the same
// PreparedProcess, or any Start call after Close, fails without spawning. A
// spawn/setup failure (missing directory, binary not found) is returned as
// an error and no Process is returned; a process that subsequently runs to a
// non-zero exit is not an error and is reported through Process.Wait's
// ProcessResult instead. ctx governs only this call's own setup window
// through the decision to hand off — exactly like PrepareProcess's own ctx,
// it never governs the returned Process's lifetime, so a caller canceling
// the ctx it passed to Start after a Process has already been handed back
// must not kill that process. On success, ownership of every reservation
// PrepareProcess made is transferred atomically to a background goroutine
// that outlives this call and guarantees terminal cleanup runs even if the
// caller never calls Process.Wait or Process.Close.
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
	p.lease.lifecycle.unregisterPrepared(p)

	proc, err := p.spawnAndSupervise(ctx)
	if err != nil {
		return nil, err
	}
	return proc, nil
}

// spawnAndSupervise performs the actual confined spawn and, on success,
// starts the background supervisor goroutine that owns terminal cleanup —
// including the case where the caller never calls Process.Wait. On any
// failure it releases the whole preparation's reservation capsule exactly
// once through the same quarantinedSpawn.release the synchronous path uses,
// so a failed Start leaks nothing.
func (p *PreparedProcess) spawnAndSupervise(ctx context.Context) (*Process, error) {
	if err := ctx.Err(); err != nil {
		_ = p.spawn.release(false, false, nil)
		return nil, err
	}
	var proc *Process
	var err error
	if p.snapshot.spec.Launch != nil {
		proc, err = p.startBackendOwned(ctx)
	} else {
		proc, err = p.startConfined(ctx)
	}
	if err != nil {
		_ = p.spawn.release(false, false, err)
		return nil, err
	}
	// supervise deliberately owns no request-scoped context: per Task 10B's
	// setup-vs-lifetime contract, Start's ctx governs the spawn window only,
	// never the returned Process's own lifetime (Wait/stream-draining/
	// terminalization must survive the caller's ctx being canceled right
	// after handoff). supervise's own loop terminates on process exit or
	// executor/session close, so this goroutine is not unbounded.
	go p.supervise(proc) // #nosec G118 -- supervise deliberately outlives the request ctx; see comment above
	return proc, nil
}

// attachLifetime wires a freshly constructed Process's lifetime field to a
// containment answer its caller already resolved. It exists — rather than
// folding lifetime into newPipeProcess/newPTYProcess/newBackendOwnedProcess's
// own struct literals the way streamMode is — because all three of those
// constructors are shared with spawnProcess's plain unconfined free-function
// path (below), which must never receive a lifetime argument of its own; a
// Process attachLifetime is never called for simply keeps the zero value,
// LifetimeContainmentUnspecified, which is already the honest answer for
// that path. This mirrors attachSignaler's identical post-construction
// assignment shape (proc.signaler, lifetime_unix.go/lifetime_other.go/
// process_tree_windows.go) for the same reason and is called once by each of
// startConfined's pipe branch, startConfinedTTY, and startBackendOwned,
// immediately after their own proc := new...Process(...) call.
func attachLifetime(proc *Process, lifetime LifetimeContainment) {
	if proc == nil {
		return
	}
	proc.lifetime = lifetime
}

// startConfined builds and spawns the process-tree-confined child exactly
// like Executor.run does — the same enforce.Spec.Wrap/configure/cleanup,
// processTree, executionLease, and pipe-plumbing machinery — except it
// hands the live Process back to the caller immediately instead of blocking
// for the process's lifetime; the eventual tree.terminateAndWait zero proof
// and resource release happen later, in the background supervisor.
func (p *PreparedProcess) startConfined(ctx context.Context) (*Process, error) {
	e := p.executor
	lease := p.lease
	s := p.snapshot
	dir := p.options.Directory
	argv := p.argv
	spawn := p.spawn

	if s.spec.Wrap == nil {
		return nil, errors.New("sandbox: executor spawn spec not compiled")
	}
	if len(argv) == 0 {
		return nil, errors.New("sandbox: empty argv")
	}

	wrapArgv, configure, cleanup := s.spec.Wrap(dir, argv)
	if cleanup != nil {
		spawn.spawnCleanup = append(spawn.spawnCleanup, func() error { cleanup(); return nil })
	}
	if len(wrapArgv) == 0 {
		return nil, errors.New("sandbox: backend produced an empty argv")
	}

	// #nosec G204 -- wrapArgv is the argument list the selected enforce.Backend
	// produced from the compiled policy, exactly like Executor.run; nothing
	// here is word-split or expanded by a shell.
	cmd := exec.CommandContext(lease.ctx, wrapArgv[0], wrapArgv[1:]...)
	cmd.Dir = dir
	cmd.WaitDelay = spawnWaitGrace
	cmd.Env = s.env
	if cmd.Env == nil {
		cmd.Env = []string{}
	}
	if configure != nil {
		if err := configure(cmd); err != nil {
			return nil, err
		}
	}
	if p.options.TTY {
		// Session/controlling-terminal setup only (Setsid/Setctty on Unix;
		// unreachable everywhere else — see ttySupported in PrepareProcess)
		// — never a PTY device allocation. This must run before e.processTree
		// below so newProcessTree (process_tree_unix.go) can see Setsid
		// already requested and skip layering its own Setpgid on top of it
		// (POSIX forbids setpgid on a session leader), and it must run after
		// configure above so a backend that builds cmd.SysProcAttr from
		// scratch there (e.g. the Linux backend's namespace cloneflags)
		// never clobbers it.
		prepareTerminalSysProcAttr(cmd)
	}
	tree, err := e.processTree(cmd, processTreeOptions{
		Sandboxed: s.policy.Isolation != Unconfined,
		Limits:    s.policy.Limits,
		// This is the pipe-backed asynchronous Process path: its lifetime is
		// tracked independently of this call (Wait/Signal are driven by a
		// caller, or by the background supervisor below, long after Start
		// returns), so it requires the mandatory exact containment proof a
		// Supervised spawn needs (SPEC Task 12b) rather than the synchronous
		// RunCommand/RunArgv path's unchanged process-group behavior.
		Supervised: true,
		Backend:    e.backend,
	})
	if err != nil {
		return nil, err
	}
	spawn.prover = tree
	spawn.cmd = cmd

	// Computed once here, before the TTY branch below, rather than separately
	// in each branch: both startConfined's own pipe path and
	// startConfinedTTY (which this function hands tree to directly) confine
	// through this exact tree, so there is exactly one containment answer for
	// this spawn, not two independently-derived ones. tree is a
	// processTreeBoundary; the type assertion below never widens that
	// interface (see lifetimeReporter's own doc, lifetime_containment.go) —
	// it mirrors attachSignaler's identical type-assertion idiom against
	// processSignalTarget, just above.
	lifetime := LifetimeContainmentUnspecified
	if reporter, ok := tree.(lifetimeReporter); ok {
		lifetime = reporter.lifetimeContainment()
	}

	if p.options.TTY {
		return p.startConfinedTTY(ctx, cmd, tree, lifetime)
	}

	outR, outW, errR, errW, err := wireOutputPipes(cmd)
	if err != nil {
		return nil, err
	}
	handleCleanup, err := configureChildHandleList(cmd)
	if err != nil {
		_ = errors.Join(outR.Close(), outW.Close(), errR.Close(), errW.Close())
		return nil, err
	}
	spawn.spawnCleanup = append([]func() error{func() error { handleCleanup(); return nil }}, spawn.spawnCleanup...)

	inR, inW, err := os.Pipe()
	if err != nil {
		_ = errors.Join(outR.Close(), outW.Close(), errR.Close(), errW.Close())
		return nil, err
	}
	cmd.Stdin = inR

	// Re-check as close to the actual OS spawn as this function gets, so a
	// cancellation that lands after Start's own entry check but before the
	// fork/exec syscall still aborts the handoff instead of racing it.
	if err := ctx.Err(); err != nil {
		_ = errors.Join(outR.Close(), outW.Close(), errR.Close(), errW.Close(), inR.Close(), inW.Close())
		return nil, err
	}

	if err := lease.start(cmd, tree); err != nil {
		_ = errors.Join(outR.Close(), outW.Close(), errR.Close(), errW.Close(), inR.Close(), inW.Close())
		return nil, err
	}
	// The child now holds its own inherited copies of the write ends and
	// stdin's read end; the parent must drop its own copies so the read ends
	// this Process exposes can ever observe EOF (the same fd-lifetime
	// discipline spawnProcess already requires). A failure here is folded
	// into terminal cleanup instead of failing Start: the process is already
	// running under confinement, so it must not be abandoned mid-handoff.
	if closeErr := errors.Join(outW.Close(), errW.Close(), inR.Close()); closeErr != nil {
		spawn.spawnCleanup = append(spawn.spawnCleanup, func() error { return closeErr })
	}
	proc := newPipeProcess(cmd, outR, errR, newProcessStdin(inW), p.options.TerminateGrace)
	attachLifetime(proc, lifetime)
	// Wires Process.Signal to real Unix signal delivery on this run's process
	// tree (Task 12A left this seam nil/unwired). tree is a
	// processTreeBoundary; on darwin/linux the concrete *processTree
	// implements processSignalTarget (lifetime_unix.go) and attachSignaler
	// sets it, so Signal actually delivers instead of failing closed with
	// ErrProcessSignalUnsupported. On platforms with no such implementation
	// yet (Windows/other), attachSignaler is a no-op and signaler stays nil,
	// matching the pre-12B fail-closed default exactly.
	attachSignaler(proc, tree)
	return proc, nil
}

// processTreeTerminalOpener is an optional seam a platform's process tree can
// implement when a terminal-backed launch cannot be composed the same way
// the plain cmd.Start()-driven path already is (openProcessTerminal,
// prepareTerminalSysProcAttr, then lease.start's own tree.start(cmd)) — see
// process_tree_windows.go's own processTree.openTerminal doc comment for
// exactly why Windows's ConPTY-backed launch is this case (Go's os/exec has
// no extensibility point for attaching PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE),
// and therefore why the real suspended-create must happen inside tree.start
// itself instead. Mirrors the identical optional-interface-plus-type-
// assertion idiom attachSignaler already uses against processSignalTarget,
// below. Only Windows's own *processTree implements this; every Unix tree
// never does, so openConfinedTerminal's fallback to the existing per-platform
// openProcessTerminal free function is exercised on every other platform
// exactly as before this interface existed.
type processTreeTerminalOpener interface {
	openTerminal(cmd *exec.Cmd) (processTerminal, func() error, error)
}

// openConfinedTerminal opens the terminal endpoint startConfinedTTY attaches
// to a confined spawn, preferring tree's own openTerminal (Windows's ConPTY
// composition, see processTreeTerminalOpener) when tree implements it, and
// falling back to the existing per-platform openProcessTerminal free
// function (terminal_unix.go, terminal_other.go) otherwise — unchanged
// behavior for every platform that predates this seam.
func openConfinedTerminal(cmd *exec.Cmd, tree processTreeBoundary) (processTerminal, func() error, error) {
	if opener, ok := tree.(processTreeTerminalOpener); ok {
		return opener.openTerminal(cmd)
	}
	return openProcessTerminal(cmd)
}

// startConfinedTTY is startConfined's PTY branch: reached only when
// p.options.TTY is true, and only after e.processTree (called by
// startConfined just before this method) has already succeeded. The
// mandatory Supervised containment proof (Task 12b/12c) is exactly as
// required for a PTY spawn as for the pipe-backed one, and Darwin's
// fail-closed Seatbelt rejection there (process_tree_darwin.go) already runs
// strictly before this method is ever entered — so no PTY device is ever
// allocated and no child is ever spawned on a platform/backend combination
// that cannot supervise it (see process_pty_integration_unix_test.go's
// TestIntegrationProcessPTYDarwinLifetimeUnavailable). tree is accepted as a
// parameter (not re-derived) so this method shares the identical containment
// decision startConfined already made; it never calls e.processTree itself.
// lifetime is likewise accepted rather than recomputed: it is startConfined's
// own lifetimeReporter answer for this same tree, computed once before the
// TTY/pipe branch split.
func (p *PreparedProcess) startConfinedTTY(ctx context.Context, cmd *exec.Cmd, tree processTreeBoundary, lifetime LifetimeContainment) (*Process, error) {
	lease := p.lease
	spawn := p.spawn

	terminal, closeSlave, err := openConfinedTerminal(cmd, tree)
	if err != nil {
		return nil, err
	}

	// pumpR/pumpW back newPTYProcess's output-draining pump goroutine (see its
	// own doc comment): Process.Stdout() reads from pumpR, never from the
	// master directly, so the master is drained continuously for the whole
	// life of the process regardless of whether/when a caller reads Stdout —
	// otherwise an undrained PTY output queue blocks the child's own exit()
	// indefinitely on Darwin (Task 21's confirmed PTY hang). Created here,
	// before lease.start, exactly like startConfined's own outR/outW/inR/inW:
	// a failure this early must abort the spawn before any child exists, not
	// leak an already-running one.
	pumpR, pumpW, err := os.Pipe()
	if err != nil {
		_ = errors.Join(terminal.Close(), closeSlave())
		return nil, err
	}

	// Re-check as close to the actual OS spawn as this function gets, so a
	// cancellation that lands after Start's own entry check but before the
	// fork/exec syscall still aborts the handoff instead of racing it —
	// exactly like startConfined's own pipe-path recheck.
	if err := ctx.Err(); err != nil {
		_ = errors.Join(terminal.Close(), closeSlave(), pumpR.Close(), pumpW.Close())
		return nil, err
	}

	if err := lease.start(cmd, tree); err != nil {
		_ = errors.Join(terminal.Close(), closeSlave(), pumpR.Close(), pumpW.Close())
		return nil, err
	}
	// The child now holds its own inherited copy of the slave (dup'd onto
	// its stdin/stdout/stderr alike); the parent must drop its own reference
	// so the master this Process retains can ever observe the child's exit
	// as EOF/EIO (mirrors startConfined's identical outW/errW/inR closure
	// for the pipe-backed path exactly). A failure here is folded into
	// terminal cleanup instead of failing Start: the process is already
	// running under confinement, so it must not be abandoned mid-handoff.
	if closeErr := closeSlave(); closeErr != nil {
		spawn.spawnCleanup = append(spawn.spawnCleanup, func() error { return closeErr })
	}
	proc := newPTYProcess(cmd, terminal, pumpR, pumpW, p.options.TerminateGrace)
	attachLifetime(proc, lifetime)
	// Wires Process.Signal to real Unix signal delivery on this run's process
	// tree, exactly like startConfined's pipe-backed path: a PTY spawn's
	// process group id equals cmd.Process.Pid either way (see
	// prepareTerminalSysProcAttr's doc, terminal_unix.go), so the identical
	// signalGroup-based delivery lifetime_unix.go already provides needs no
	// PTY-specific variant.
	attachSignaler(proc, tree)
	return proc, nil
}

// startBackendOwned launches the process through the backend's own
// authority-establishing Launch (enforce.Spec.Launch) exactly like
// Executor.runBackendOwned does, except it never calls Wait itself: Launch
// already returns as soon as the launched process's OS-level authority is
// established, and the backend's own Execution.Wait (invoked lazily by
// Process.Wait, including from the background supervisor) is what proves
// and retires that authority. Unlike runBackendOwned's single combined
// output buffer (built for RunCommand's whole-output contract), this wires
// real live pipes so Stdout/Stderr/Stdin behave identically to the
// process-tree-confined path.
//
// p.options.TTY is rejected here, first, before anything else: this path is
// reached only when the compiled spec sets Launch (spawnAndSupervise's own
// dispatch, above) — today that means exactly one thing on exactly one
// platform, the Windows elevated/broker backend
// (internal/windows/elevated_backend_windows.go) — and it has no ConPTY (or
// equivalent) wiring of its own. ttySupported (terminal_unix.go,
// terminal_windows.go, terminal_other.go) is a platform-wide constant
// PrepareProcess checks before Start has even decided which of these two
// dispatch branches it will take (that split only happens here, at Start
// time, via p.snapshot.spec.Launch), so PrepareProcess admitting
// ProcessOptions.TTY == true on a platform where ttySupported is true says
// nothing about whether THIS SPECIFIC backend can honor it. Without this
// check, a TTY request that resolves to this path would silently come back
// as a plain pipe-backed Process — exactly the silent pipe/PTY fallback this
// package's own top-of-file doc comment (above) says must never happen.
// Real ConPTY support for the elevated/broker backend is a later task's
// scope, not this one's; this keeps the gap fail-closed in the meantime.
func (p *PreparedProcess) startBackendOwned(ctx context.Context) (*Process, error) {
	if p.options.TTY {
		return nil, ErrProcessTTYUnsupported
	}

	lease := p.lease
	s := p.snapshot
	dir := p.options.Directory
	argv := p.argv
	spawn := p.spawn

	if len(argv) == 0 {
		return nil, errors.New("sandbox: empty argv")
	}
	if err := lease.authorizeBackendStart(); err != nil {
		return nil, err
	}
	env := append([]string(nil), s.env...)
	if env == nil {
		env = []string{}
	}

	outR, outW, errR, errW, err := newStdoutStderrPipes()
	if err != nil {
		return nil, err
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, errors.Join(err, outR.Close(), outW.Close(), errR.Close(), errW.Close())
	}

	if err := ctx.Err(); err != nil {
		return nil, errors.Join(err, outR.Close(), outW.Close(), errR.Close(), errW.Close(), inR.Close(), inW.Close())
	}

	execution, err := s.spec.Launch(enforce.LaunchRequest{
		Context: lease.ctx,
		Dir:     dir,
		Argv:    append([]string(nil), argv...),
		Env:     env,
		Stdin:   inR,
		Stdout:  outW,
		Stderr:  errW,
	})
	if err != nil {
		return nil, errors.Join(err, outR.Close(), outW.Close(), errR.Close(), errW.Close(), inR.Close(), inW.Close())
	}

	// The backend's own bridge copies between (inR, outW, errW) and the real
	// child for as long as the process runs; it never closes our copies, so
	// they must stay open until the process's authority is fully retired
	// (spawn.release, below, runs this once the background supervisor's
	// Process.Wait confirms the backend's own Execution.Wait has returned) —
	// closing them any earlier would sever the bridge mid-stream, and never
	// closing them would leave every reader of this Process's Stdout/Stderr
	// blocked forever instead of observing EOF.
	spawn.spawnCleanup = append(spawn.spawnCleanup, func() error {
		return errors.Join(outW.Close(), errW.Close(), inR.Close())
	})
	proc := newBackendOwnedProcess(execution, outR, errR, newProcessStdin(inW), p.options.TerminateGrace)
	// Enforced, unconditionally: this path is reached only for the Windows
	// elevated/broker backend (see this method's own doc comment above), whose
	// Job object is kernel-enforced teardown by construction — there is no
	// tree/proof to ask, unlike the confined path's lifetimeReporter seam.
	attachLifetime(proc, LifetimeContainmentEnforced)
	// Wires Process.Signal to real signal delivery when the backend's own
	// Execution value implements processSignalTarget — e.g. the Windows
	// elevated runner's *elevatedAsyncExecution (internal/windows), which
	// structurally satisfies this package-local interface without either
	// package importing the other's signal vocabulary: execution's static
	// type here is only enforce.Execution, and the assertion below is
	// against its dynamic (concrete backend) type, exactly like
	// attachSignaler does for a processTreeBoundary on the confined path.
	// A backend whose Execution does not implement all three methods
	// leaves signaler nil, keeping Signal's pre-12D fail-closed default
	// (ErrProcessSignalUnsupported) exactly as it was.
	if signaler, ok := execution.(processSignalTarget); ok {
		proc.signaler = signaler
	}
	return proc, nil
}

// supervise is the background goroutine Start hands ownership to on a
// successful spawn. It guarantees terminal cleanup runs exactly once
// regardless of whether or when (or whether at all) the caller ever calls
// Process.Wait: it always calls Wait itself, which is safe and cheap
// because Process.Wait is cached and its real OS/backend wait happens
// exactly once no matter how many callers (this goroutine included) invoke
// it. For a process-tree-confined Process it then performs the identical
// tree.terminateAndWait zero proof Executor.run performs after the process
// exits, releasing the whole reservation capsule on success or transferring
// it whole to the existing quarantine/retry path on an uncertain proof. For
// a backend-owned Process, the backend's own Execution.Wait has already
// proved and retired its own OS-level authority (e.g. the Windows elevated
// broker lease, Job, and compiled spec's active-launch registration) by the
// time Wait returns, so only the grant/path/proxy/compiled-backend release
// closures and both executor lifecycle barriers remain to run here.
func (p *PreparedProcess) supervise(proc *Process) {
	_, _ = proc.Wait(context.Background())
	spawn := p.spawn
	if spawn.prover != nil {
		terminateErr, proofErr := spawn.prover.terminateAndWait()
		if proofErr != nil {
			spawn.transferTo(p.executor.quarantine)
			return
		}
		_ = spawn.release(true, false, terminateErr)
		return
	}
	_ = spawn.release(true, false, nil)
}

// Close releases an unstarted preparation's reservations and is idempotent.
// Once Start has consumed the preparation, ownership of anything reserved
// has already transferred to the returned Process's background supervisor,
// so a later Close is a harmless no-op rather than an error.
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
	if p.lease != nil {
		p.lease.lifecycle.unregisterPrepared(p)
	}
	if p.spawn == nil {
		if p.lease != nil {
			p.lease.finish()
		}
		return nil
	}
	return p.spawn.release(false, false, nil)
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

	// #nosec G204 -- launching a caller-supplied command IS this module's
	// purpose; see the identical justification on Executor.run. This path is
	// deliberately a plain, unconfined os/exec.Cmd: enforcement/confinement
	// wiring for the pipe-backed process is explicitly a later microtask's
	// scope, not this one's.
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = opts.Directory

	outR, outW, errR, errW, err := wireOutputPipes(cmd)
	if err != nil {
		return nil, err
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		return nil, errors.Join(err, outR.Close(), outW.Close(), errR.Close(), errW.Close())
	}
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

	return newPipeProcess(cmd, outR, errR, newProcessStdin(inW), opts.TerminateGrace), nil
}

// wireOutputPipes creates dedicated stdout/stderr pipes and wires their write
// ends onto cmd (without starting anything), returning both ends of each pipe
// so the caller can hand the read ends to a Process and later release its own
// copies of the write ends once the child holds its inherited copies.
//
// It is the low-level OS-pipe-plumbing primitive shared by every process
// spawn path in this package: spawnProcess above (the unconfined asynchronous
// entry point, which additionally wires its own stdin pipe before starting)
// and Executor.run's confined synchronous path (executor.go), which builds
// and fully confines cmd itself — argv, working directory, environment,
// SysProcAttr, and the backend's enforce.Spec confinement — before ever
// reaching here, and starts it through its own confinement-aware start
// function (recording a process-group id, etc.) rather than calling
// cmd.Start() directly.
func wireOutputPipes(cmd *exec.Cmd) (outR, outW, errR, errW *os.File, err error) {
	outR, outW, errR, errW, err = newStdoutStderrPipes()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	cmd.Stdout = outW
	cmd.Stderr = errW
	return outR, outW, errR, errW, nil
}

// newStdoutStderrPipes creates the two dedicated os.Pipe pairs every spawn
// path in this package wires stdout/stderr through, without binding them to
// an *exec.Cmd: wireOutputPipes (above) is the *exec.Cmd-wiring wrapper a
// process-tree-confined spawn uses; startBackendOwned wires these same two
// pairs directly into an enforce.LaunchRequest instead, since a backend-owned
// spawn has no *exec.Cmd of its own.
func newStdoutStderrPipes() (outR, outW, errR, errW *os.File, err error) {
	outR, outW, err = os.Pipe()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	errR, errW, err = os.Pipe()
	if err != nil {
		return nil, nil, nil, nil, errors.Join(err, outR.Close(), outW.Close())
	}
	return outR, outW, errR, errW, nil
}

// newPipeProcess constructs a *Process around already-wired, already-started
// stdout/stderr pipe read ends and an optional stdin. stdin is nil when the
// caller has no stdin to offer — e.g. Executor.run's synchronous path, which
// leaves cmd.Stdin exactly as it always has: unset, so os/exec connects the
// child to the null device — in which case Process.Close and Process.Stdin
// already treat a nil stdin as a no-op/harmless zero value.
func newPipeProcess(cmd *exec.Cmd, stdout, stderr io.ReadCloser, stdin *processStdin, terminateGrace time.Duration) *Process {
	return &Process{
		cmd:            cmd,
		stdout:         stdout,
		stderr:         stderr,
		stdin:          stdin,
		streamMode:     ProcessStreamModePipes,
		startedAt:      time.Now(),
		activities:     make(chan ProcessActivity),
		done:           make(chan struct{}),
		terminateGrace: resolveProcessTerminateGrace(terminateGrace),
	}
}

// newPTYProcess constructs a *Process around an already-opened, already-
// attached PTY terminal endpoint (see openProcessTerminal, terminal_unix.go)
// whose slave half the parent has already dropped its own reference to
// (mirrors newPipeProcess's outR/errR/inW: only the ends the Process itself
// needs are ever retained past Start), and pumpR/pumpW — a dedicated
// os.Pipe pair the caller (startConfinedTTY) created before the child was
// even spawned, exactly like the pipe-backed path's own outR/outW.
//
// Stdout is deliberately NOT the master directly: this starts a background
// pump goroutine (pumpPTYOutput) that continuously copies terminal -> pumpW
// for as long as the terminal produces output, independent of whether or
// when a caller ever reads Stdout, and Stdout() returns pumpR instead. This
// is Task 21's fix for the confirmed PTY hang: on Darwin, a session leader
// with ANY undrained output sitting in the PTY's kernel queue blocks in
// exit() until the master is drained (or closed/revoked), so without this
// pump, Process.Wait's runWait — which blocks in a raw wait4 on the child —
// would deadlock forever whenever nothing has drained the master (including
// when nobody has even called Wait yet — see supervise, which always calls
// Wait itself even if no other caller ever does). The pump owns pumpW for
// its whole lifetime and is the only thing that ever closes it (see
// pumpPTYOutput's own doc); a slow Stdout() reader only backs up pumpR/
// pumpW's own ~64KB pipe buffer, identical to the pipe-backed path's
// existing backpressure — it can never re-block the master drain that
// already happened at the kernel level the moment the pump's Read call
// returned.
//
// Stdin wraps the SAME terminal endpoint through terminalStdin (terminal.go),
// not the master directly: closing Stdin must deliver EOF in-band (the VEOF
// control byte) rather than tearing down the whole terminal — see
// terminalStdin's own doc comment. terminalCloser separately retains the
// master itself so Process.Close can still hang it up for real — that,
// exclusively, is what actually closes the master (which ends the pump,
// which then closes pumpW so Stdout() readers observe EOF).
//
// Stderr is the synthetic, permanently-empty, already-closed reader
// ProcessStreamModePTY's contract requires (see closedEmptyReadCloser): a
// PTY-backed Process never silently falls back to a second real pipe.
func newPTYProcess(cmd *exec.Cmd, terminal processTerminal, pumpR, pumpW *os.File, terminateGrace time.Duration) *Process {
	go pumpPTYOutput(pumpW, terminal)
	return &Process{
		cmd:            cmd,
		stdout:         pumpR,
		stderr:         closedEmptyReadCloser{},
		stdin:          newProcessStdin(newTerminalStdin(terminal)),
		streamMode:     ProcessStreamModePTY,
		resizer:        terminal,
		terminalCloser: terminal,
		startedAt:      time.Now(),
		activities:     make(chan ProcessActivity),
		done:           make(chan struct{}),
		terminateGrace: resolveProcessTerminateGrace(terminateGrace),
	}
}

// pumpPTYOutput continuously drains terminal (a PTY-backed Process's master)
// into pumpW. It mirrors drainCombinedOutput's (executor.go) read-loop shape
// exactly — the same 32KB buffer, the same "return on any read error"
// termination — except it copies into a live pipe instead of a
// mutex-guarded buffer, since a PTY Process's Stdout is itself a live stream,
// not a captured result collected after the fact.
//
// It owns pumpW for its entire lifetime and is the only goroutine that ever
// closes it (deferred, so it runs on every exit path), which is what makes
// Stdout() readers observe EOF: draining ends either because terminal.Read
// returned its already-normalized io.EOF (the child exited and this
// package's own parent-side slave reference was already dropped — see
// openProcessTerminal's doc, terminal_unix.go), because Process.Close closed
// the master out from under an in-flight Read (see terminalCloser,
// process.go), or because nobody drained Stdout() and pumpW's write blocked
// against a full, undrained pipe until Process.Close's unconditional
// p.stdout.Close() severed the read end out from under it. Every one of
// those paths returns from this function, so the goroutine never leaks
// regardless of which one fires.
func pumpPTYOutput(pumpW *os.File, terminal processTerminal) {
	defer pumpW.Close()
	buf := make([]byte, 32*1024)
	for {
		n, readErr := terminal.Read(buf)
		if n > 0 {
			if _, writeErr := pumpW.Write(buf[:n]); writeErr != nil {
				return
			}
		}
		if readErr != nil {
			return
		}
	}
}

// newBackendOwnedProcess adapts a backend-owned enforce.Execution — the
// handle a compiled enforce.Spec.Launch returns once it has already
// established the launched process's OS-level authority (e.g. a Windows
// elevated Job with the target assigned and resumed) — into the same
// asynchronous Process shape newPipeProcess produces from a plain os/exec.Cmd,
// so a future caller preparing a backend-confined process never needs a
// second, parallel asynchronous execution model: Wait, Close, Activities, and
// stream access all behave identically regardless of which constructor built
// the Process.
//
// stdout/stderr/stdin are the caller-facing pipe ends; how a specific backend
// produces the OTHER ends and copies between them and the real OS process is
// entirely that backend's concern (see the Windows elevated stdio bridge) —
// this constructor only needs the already-live caller-facing ends. execution
// supplies the terminal result in place of cmd.Wait/exec.ExitError; a
// backend-owned Process has no *exec.Cmd for this package to reap, so
// Process.cmd stays nil and runWait must not dereference it in that case.
func newBackendOwnedProcess(execution enforce.Execution, stdout, stderr io.ReadCloser, stdin *processStdin, terminateGrace time.Duration) *Process {
	return &Process{
		execution:      execution,
		stdout:         stdout,
		stderr:         stderr,
		stdin:          stdin,
		streamMode:     ProcessStreamModePipes,
		startedAt:      time.Now(),
		activities:     make(chan ProcessActivity),
		done:           make(chan struct{}),
		terminateGrace: resolveProcessTerminateGrace(terminateGrace),
	}
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
	// cmd is set by newPipeProcess (a plain, unconfined os/exec.Cmd spawn)
	// and nil for a backend-owned construction (newBackendOwnedProcess),
	// which sets execution instead; exactly one of the two is ever non-nil,
	// and runWait branches on execution to decide which one to reap.
	cmd       *exec.Cmd
	execution enforce.Execution
	stdout    io.ReadCloser
	stderr    io.ReadCloser
	stdin     *processStdin

	// streamMode reports which of Stdout/Stderr's two topologies this
	// Process was constructed with (see ProcessStreamMode, terminal.go).
	// Every constructor in this package sets it explicitly; there is no
	// implicit zero-value default.
	streamMode ProcessStreamMode

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

	// Signal state machine (see Signal, below). signaler is the narrow seam
	// a later microtask (the Unix lifetime shim, the Windows Job signal
	// mapping) wires to a real OS/backend signal-delivery implementation;
	// every Process this microtask constructs leaves it nil, so Signal fails
	// closed with ErrProcessSignalUnsupported for a not-yet-terminal process
	// instead of silently succeeding. terminateGrace is resolved (never
	// zero/negative) once at construction from ProcessOptions.TerminateGrace.
	// graceTimer, when non-nil, replaces the real time.Timer-backed wait a
	// terminate escalation uses; only tests set it, to drive escalation
	// deterministically without a real sleep.
	signaler       processSignalTarget
	terminateGrace time.Duration
	graceTimer     func(time.Duration) (<-chan time.Time, func())

	terminateOnce sync.Once
	terminateErr  error
	killOnce      sync.Once
	killErr       error

	// resizer is the narrow seam Resize (below) drives to actually change a
	// PTY's window size, exactly like signaler is Signal's seam onto real OS
	// signal delivery. Only newPTYProcess ever sets this; every pipe-backed
	// Process leaves it nil, so Resize fails closed with
	// ErrProcessResizeUnsupported instead of silently succeeding.
	resizer processTerminalTarget

	// terminalCloser is the narrow seam Close (below) drives to actually hang
	// up a PTY-backed Process's real terminal master. It is deliberately
	// distinct from stdin's Close (terminalStdin, terminal.go, writes the
	// in-band VEOF byte instead of touching this) and from stdout's Close
	// (closes only the output-draining pump's pipe read end, never the
	// master — see newPTYProcess, above): a real master close is a genuine
	// hangup — SIGHUP delivered to the terminal's whole foreground process
	// group, plus losing whatever output is still buffered there — and
	// Process exposes exactly one path to it. Only newPTYProcess ever sets
	// this; every pipe-backed Process leaves it nil.
	terminalCloser io.Closer

	// lifetime is this spawn's actually-achieved process-tree teardown
	// contract (see LifetimeContainment, lifetime_containment.go). Unlike
	// streamMode above, it is NOT set inside the constructor's own struct
	// literal: it is assigned exactly once, via attachLifetime immediately
	// after construction, and never mutated again afterward. attachLifetime
	// exists (rather than a constructor parameter) because newPipeProcess/
	// newPTYProcess/newBackendOwnedProcess are shared with spawnProcess's
	// plain unconfined path, which must never receive a lifetime argument of
	// its own — see attachLifetime's own doc, just above startConfined.
	// startConfined/startConfinedTTY attach the processTree's own
	// lifetimeReporter answer (Unspecified when the tree carries no proof at
	// all, e.g. an Unconfined/null-backend spawn); startBackendOwned attaches
	// Enforced unconditionally (the Windows elevated broker's Job is
	// kernel-enforced by construction, with no tree/proof of its own to ask).
	// The zero value (LifetimeContainmentUnspecified) already matches
	// spawnProcess's unconfined free-function path, which never calls
	// attachLifetime for its own construction.
	lifetime LifetimeContainment
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

// StreamMode reports this Process's stream topology: distinct pipes
// (ProcessStreamModePipes, every Process this package constructed before PTY
// support existed and every pipe-backed Process since) or one combined PTY
// stream (ProcessStreamModePTY, newPTYProcess). A nil Process reports
// ProcessStreamModePipes, matching every other nil-receiver accessor on this
// type returning its harmless zero value.
func (p *Process) StreamMode() ProcessStreamMode {
	if p == nil {
		return ProcessStreamModePipes
	}
	return p.streamMode
}

// LifetimeContainment reports the process-tree teardown contract this spawn
// actually received: Enforced (Linux namespace/cgroup, Windows Job),
// BestEffort (Darwin Seatbelt — see docs/lifetime-containment.md), or
// Unspecified (an Unconfined/null-backend spawn making no claim). A nil
// Process reports Unspecified, matching every other nil-receiver accessor on
// this type returning its harmless zero value.
func (p *Process) LifetimeContainment() LifetimeContainment {
	if p == nil {
		return LifetimeContainmentUnspecified
	}
	return p.lifetime
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

// runWait performs the single real terminal wait for this process — either
// reaping p.cmd directly, or (for a backend-owned construction) delegating to
// p.execution.Wait, which itself blocks until the backend's own OS-level
// authority (e.g. a Windows Job) is proven empty. It is started by exactly
// one Wait caller's sync.Once and every other caller (concurrent or later)
// only ever observes its result through the done channel's happens-before
// guarantee.
//
// Like p.cmd.Wait() below, p.execution.Wait is deliberately called with
// context.Background() rather than any individual caller's ctx: Process.Wait
// already guarantees that a caller's context cancellation only stops that
// call from waiting, never the process/authority itself, and runWait runs
// exactly once regardless of how many callers or contexts are involved.
func (p *Process) runWait() {
	var exitCode int
	var err error
	if p.execution != nil {
		exitCode, err = p.execution.Wait(context.Background())
	} else {
		err = p.cmd.Wait()
	}
	finishedAt := time.Now()
	// The activity stream must close before any Wait caller can observe a
	// result; closing here, strictly before result/done, guarantees that
	// ordering for every current and future caller.
	close(p.activities)

	var exitErr *exec.ExitError
	switch {
	case err == nil:
		// For p.cmd, a nil Wait error always means a clean exit 0 (exitCode's
		// zero value already matches); for p.execution, a nil error already
		// carries the real portable exit code (an enforce.Execution's Wait
		// reports a ran-but-nonzero process this way, with a nil error,
		// exactly like this package's own Process.Wait convention).
		p.result = ProcessResult{ExitCode: exitCode, StartedAt: p.startedAt, FinishedAt: finishedAt}
	case errors.As(err, &exitErr):
		// A ran-but-non-zero *exec.Cmd process is a result, not an error:
		// mirrors the synchronous RunCommand/RunArgv exit-code convention
		// exactly. This case is unreachable for a backend-owned execution,
		// whose Wait never produces an *exec.Cmd-shaped error.
		p.result = ProcessResult{ExitCode: exitErr.ExitCode(), StartedAt: p.startedAt, FinishedAt: finishedAt}
	default:
		// A genuine post-spawn failure (e.g. an I/O teardown error, or a
		// backend's own authority-proof failure): distinct from both a clean
		// exit and a non-zero exit.
		p.resultErr = err
	}
	close(p.done)
}

// Close closes the process's stream handles. It is idempotent. It does not
// itself signal or wait for the OS process — use Signal to request
// interrupt/terminate/kill, and Wait to observe the eventual exit — so a
// caller that wants the process to actually stop must still arrange that
// separately (e.g. via Signal, closing stdin, or waiting for natural
// completion). For a PTY-backed Process this additionally closes the real
// terminal master (terminalCloser) — a genuine hangup, delivering SIGHUP to
// the terminal's whole foreground process group — which is deliberately
// distinct from Stdin().Close() (delivers EOF in-band as the VEOF byte
// instead; see terminalStdin, terminal.go) and ends the output-draining pump
// (pumpPTYOutput, above), which in turn closes Stdout's pipe so any blocked
// reader observes EOF.
func (p *Process) Close(ctx context.Context) error {
	if p == nil {
		return nil
	}
	_ = ctx // reserved for the later task that adds confirmed teardown semantics
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
		if p.terminalCloser != nil {
			err = errors.Join(err, p.terminalCloser.Close())
		}
		p.closeErr = err
	})
	return p.closeErr
}

// ProcessSignal is a portable process-tree signal request. Mirrors,
// structurally only, Harness's tool.ProcessSignal vocabulary
// (ProcessSignalInterrupt/ProcessSignalTerminate/ProcessSignalKill) so a
// later adapter can translate directly; Sandbox defines its own stdlib-only
// type rather than importing Harness's.
type ProcessSignal uint8

const (
	// ProcessSignalInterrupt requests cooperative interruption. It never by
	// itself decides the process is terminal — only an actual exit, observed
	// through Wait, does that.
	ProcessSignalInterrupt ProcessSignal = iota + 1
	// ProcessSignalTerminate requests cooperative termination, escalating to
	// exactly one ProcessSignalKill if the process has not exited by the end
	// of its resolved terminate grace period (ProcessOptions.TerminateGrace).
	ProcessSignalTerminate
	// ProcessSignalKill force-terminates immediately, with no grace period.
	ProcessSignalKill
)

// Valid reports whether s is a recognized portable process signal.
func (s ProcessSignal) Valid() bool {
	return s >= ProcessSignalInterrupt && s <= ProcessSignalKill
}

// processSignalTarget is the narrow seam Process.Signal drives to actually
// deliver a portable interrupt/terminate/kill request. It intentionally
// exposes raw, fire-and-forget delivery only — never a wait/proof method —
// so this microtask's state machine can be exercised deterministically
// against a fake without any real OS process; a later microtask wires
// production Process values to a real implementation built on the same
// processTree/Job authority terminateAndWait already confines.
type processSignalTarget interface {
	// sendInterrupt asks the boundary to request cooperative interruption.
	sendInterrupt() error
	// sendTerminate asks the boundary to request cooperative termination.
	sendTerminate() error
	// sendKill asks the boundary to force-terminate immediately.
	sendKill() error
}

// realGraceTimer is the production Process.graceTimer: a real time.Timer.
func realGraceTimer(d time.Duration) (<-chan time.Time, func()) {
	timer := time.NewTimer(d)
	return timer.C, func() { timer.Stop() }
}

// Signal delivers a portable interrupt/terminate/kill request. It is safe to
// call concurrently with itself and with every other Process method.
//
// ProcessSignalInterrupt delivers immediately and never decides the process
// is terminal by itself — only an actual exit, observed through Wait, does
// that. ProcessSignalKill idempotently dispatches at most one kill for this
// Process's entire lifetime, immediately, with no grace period.
// ProcessSignalTerminate delivers at most one terminate signal — its first
// call only; later Terminate calls are no-ops that return the identical
// result — and, on that same first call, starts a background escalation that
// dispatches at most one kill once the terminate grace period elapses
// without a confirmed natural exit; it never re-sends terminate and never
// escalates more than once, and the eventual kill (whether from escalation
// or from a later explicit Signal(ProcessSignalKill) call) is the same
// single dispatch either path can trigger.
//
// A concurrent natural exit — observed by Wait's runWait closing p.done,
// which every PreparedProcess.Start spawn's background supervisor already
// guarantees happens by calling Wait itself even if no other caller ever
// does — always wins over a pending or in-flight signal: once the process is
// confirmed terminal, Signal is a safe no-op for every kind, and a pending
// terminate escalation is skipped rather than delivered to a process that is
// already gone.
//
// ctx governs only this call's own validation; it is never consulted again
// once delivery has started, so a ctx canceled after a Terminate call
// returns does not stop that call's already-started background escalation.
func (p *Process) Signal(ctx context.Context, kind ProcessSignal) error {
	if p == nil {
		return ErrProcessClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !kind.Valid() {
		return fmt.Errorf("sandbox: invalid process signal: %d", kind)
	}
	if p.confirmedTerminal() {
		return nil
	}
	switch kind {
	case ProcessSignalInterrupt:
		if p.signaler == nil {
			return ErrProcessSignalUnsupported
		}
		return p.signaler.sendInterrupt()
	case ProcessSignalKill:
		return p.dispatchKill()
	default: // ProcessSignalTerminate
		return p.dispatchTerminate()
	}
}

// Resize changes a PTY-backed Process's terminal window size. It is a no-op
// (nil error) once the process is confirmed terminal, exactly like Signal's
// identical treatment of a concurrent natural exit — a resize request racing
// the process's own exit is not itself an error. A pipe-backed Process (or a
// PTY-backed one on a platform whose terminal has no resize primitive wired)
// has no resizer and fails closed with ErrProcessResizeUnsupported instead of
// silently succeeding, exactly like Signal's own fail-closed default for an
// unwired signaler.
func (p *Process) Resize(ctx context.Context, rows, cols uint16) error {
	if p == nil {
		return ErrProcessClosed
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if p.confirmedTerminal() {
		return nil
	}
	if p.resizer == nil {
		return ErrProcessResizeUnsupported
	}
	return p.resizer.resize(rows, cols)
}

// confirmedTerminal reports whether this Process's terminal wait (runWait,
// started by exactly one Wait caller — including the background supervisor
// every PreparedProcess.Start spawn already starts) has already closed done.
// It never itself starts that wait: Signal only ever observes a terminal
// state some other caller already established, exactly like this method's
// doc contract requires.
func (p *Process) confirmedTerminal() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

// dispatchKill idempotently sends at most one kill for this Process's entire
// lifetime, regardless of whether it is reached through an explicit
// Signal(ProcessSignalKill) call or a terminate escalation, and regardless of
// how many times either path is entered concurrently. A process already
// confirmed terminal is a no-op rather than a signal delivered to a reaped
// process.
func (p *Process) dispatchKill() error {
	if p.confirmedTerminal() {
		return nil
	}
	p.killOnce.Do(func() {
		if p.signaler == nil {
			p.killErr = ErrProcessSignalUnsupported
			return
		}
		p.killErr = p.signaler.sendKill()
	})
	return p.killErr
}

// dispatchTerminate delivers at most one terminate signal for this Process's
// entire lifetime and, on that same first call only, starts the background
// escalation goroutine that dispatches at most one kill once the terminate
// grace period elapses without a confirmed natural exit. Every later
// Terminate call, concurrent or sequential, observes the identical result
// without re-sending anything or starting a second escalation.
func (p *Process) dispatchTerminate() error {
	p.terminateOnce.Do(func() {
		if p.signaler == nil {
			p.terminateErr = ErrProcessSignalUnsupported
			return
		}
		p.terminateErr = p.signaler.sendTerminate()
		go p.escalateAfterGrace()
	})
	return p.terminateErr
}

// escalateAfterGrace waits for this Process's resolved terminate grace
// period (or, in a test, whatever graceTimer substitutes for it), honoring a
// concurrent natural exit over the timer: if done closes first, no kill is
// ever dispatched. Otherwise it dispatches exactly one kill through the same
// idempotent dispatchKill path an explicit Signal(ProcessSignalKill) call
// uses, so the two can never race into a double send.
func (p *Process) escalateAfterGrace() {
	newTimer := p.graceTimer
	if newTimer == nil {
		newTimer = realGraceTimer
	}
	graceCh, stop := newTimer(p.terminateGrace)
	defer stop()
	select {
	case <-p.done:
		return
	case <-graceCh:
		_ = p.dispatchKill()
	}
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
