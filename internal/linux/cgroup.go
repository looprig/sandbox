//go:build linux

package linux

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// DefaultMaxPIDs is the pids.max applied when a policy does not set an explicit
// policy.Limits.MaxPIDs (SPEC §7.4). It is the load-bearing fork-bomb cap: a fork bomb
// grows until it hits pids.max, so ANY finite cap stops it — the value only
// needs to sit above real toolchain fan-out and below runaway growth.
//
// Headroom reasoning: pids.max counts THREADS as well as processes across the
// whole scope, so the budget must cover every OS thread of every process a real
// spawn creates. A parallel build (make -jN, cargo, a Go toolchain) spawns on
// the order of dozens to low hundreds of concurrent tasks; 512 leaves comfortable
// headroom over that while remaining far below the exponential growth of a fork
// bomb (which reaches thousands almost immediately). Small enough to stop the
// bomb, large enough that a legitimate build never trips it.
const DefaultMaxPIDs int64 = 512

// CgroupScopePrefix names every transient scope this backend creates. The
// no-dangling-cgroup Teardown test and any operator inspection key on it; the
// remainder of the name is crypto/rand entropy (transientScopeName).
const CgroupScopePrefix = "lrsb-"

// cpuMaxPeriodUsec is the cgroup v2 cpu.max accounting period (microseconds).
// cpu.max is "<quota> <period>"; a MaxCPUPct of 100 maps to quota == period
// (one full core), 200 to twice the period, and so on.
const cpuMaxPeriodUsec = 100000

// cgroup Teardown drain tuning: after cgroup.kill the kernel needs a moment to
// reap the scope's tasks before rmdir stops returning EBUSY. These bound the
// best-effort poll; they gate nothing an assertion observes.
const (
	cgroupDrainTries    = 100
	cgroupDrainInterval = 10 * time.Millisecond
)

// CompiledCgroup is the resolved, per-executor cgroup v2 resource-limit plan
// (SPEC §7.4). It is compiled once from the policy's policy.Limits plus the backend's
// probed delegated pids Ancestor, then consumed by each spawn's configure to
// build a transient scope. An empty Ancestor means NO limits are applied
// (delegation unavailable or policy.Limits.Disabled) — the fail-secure default.
type CompiledCgroup struct {
	// Ancestor is the writable cgroup v2 node distributing the pids controller
	// under which each spawn's transient scope is created. "" ⇒ apply no limits.
	Ancestor string
	// PidsMax is the mandatory fork-bomb cap written to pids.max. It is > 0
	// whenever Ancestor is non-empty.
	PidsMax int64
	// MemMax is memory.max in bytes; 0 ⇒ do not set (optional cost limit).
	MemMax int64
	// CPUPct is cpu.max as a percentage of one core; 0 ⇒ do not set (optional).
	CPUPct int
	// Disabled records an explicit policy.Limits.Disabled opt-out (vs delegation absent)
	// so the compile report can distinguish the two when Ancestor is "".
	Disabled bool
}

// Enforced reports whether this plan will create a transient scope (and thus
// whether the ResourceLimits guarantee holds). It is the single fail-secure gate:
// no Ancestor ⇒ no limits ⇒ no guarantee.
func (c CompiledCgroup) Enforced() bool { return c.Ancestor != "" }

// CompileCgroupPolicy resolves a policy.Limits policy against the probed delegated pids
// Ancestor into a CompiledCgroup (SPEC §7.4). Fail-secure: an empty Ancestor (no
// cgroup v2 pids delegation) or policy.Limits.Disabled yields a plan that applies NO
// limits (Enforced() == false). Otherwise pids.max is the mandatory cap
// (policy.Limits.MaxPIDs when > 0, else DefaultMaxPIDs); memory.max and cpu.max are
// carried only when explicitly set (> 0).
func CompileCgroupPolicy(l policy.Limits, Ancestor string) CompiledCgroup {
	if l.Disabled {
		return CompiledCgroup{Disabled: true}
	}
	if Ancestor == "" {
		return CompiledCgroup{}
	}
	PidsMax := DefaultMaxPIDs
	if l.MaxPIDs > 0 {
		PidsMax = int64(l.MaxPIDs)
	}
	cg := CompiledCgroup{Ancestor: Ancestor, PidsMax: PidsMax}
	if l.MaxMemBytes > 0 {
		cg.MemMax = l.MaxMemBytes
	}
	if l.MaxCPUPct > 0 {
		cg.CPUPct = l.MaxCPUPct
	}
	return cg
}

// CgroupCompileReport records how the cgroup v2 resource-limit axis compiled
// (SPEC §7.4, §7.5). When a transient scope will be created it is Enforced;
// otherwise it is unenforced, distinguishing an explicit policy opt-out
// (policy.Limits.Disabled) from absent cgroup v2 pids delegation. Resource limits never
// change the isolation Level — they are containment-of-cost, not authority.
func CgroupCompileReport(cg CompiledCgroup) profile.ReportEntry {
	if cg.Enforced() {
		detail := fmt.Sprintf("stage-2 child joins a transient cgroup v2 scope with pids.max=%d (fork-bomb cap) via CLONE_INTO_CGROUP; scope killed and removed on spawn Teardown (§7.4)", cg.PidsMax)
		if cg.MemMax > 0 {
			detail += fmt.Sprintf("; memory.max=%d bytes", cg.MemMax)
		}
		if cg.CPUPct > 0 {
			detail += fmt.Sprintf("; cpu.max=%d%% of one core (best-effort — cpu controller may be undelegated)", cg.CPUPct)
		}
		return profile.ReportEntry{Feature: "resource-limits", Status: "Enforced", Detail: detail}
	}
	if cg.Disabled {
		return profile.ReportEntry{
			Feature: "resource-limits",
			Status:  "unenforced",
			Detail:  "resource limits Disabled by policy (policy.Limits.Disabled); no cgroup scope applied (§7.4)",
		}
	}
	return profile.ReportEntry{
		Feature: "resource-limits",
		Status:  "unenforced",
		Detail:  "cgroup v2 pids delegation absent (no writable Ancestor distributes the pids controller); fork-bomb cap unenforced and guarantee cleared (fail-secure, §7.4)",
	}
}

// cgroupError is a typed cgroup-setup failure (SPEC §7.4). Resource limits are
// containment-of-cost, not containment-of-authority: a spawn whose transient
// scope cannot be created runs WITHOUT limits (best-effort) rather than failing,
// so the caller records this rather than propagating it to fail the spawn.
type cgroupError struct {
	Op  string // the failing step, e.g. "mkdir", "write pids.max"
	Err error  // the wrapped underlying cause
}

func (e *cgroupError) Error() string { return "sandbox: cgroup: " + e.Op + ": " + e.Err.Error() }
func (e *cgroupError) Unwrap() error { return e.Err }

// transientCgroup is one spawn's freshly-created cgroup v2 scope: its own
// directory under the delegated Ancestor and an open O_DIRECTORY fd used to join
// the stage-2 child at clone time via CLONE_INTO_CGROUP (SysProcAttr.UseCgroupFD).
// It is created by CreateTransientCgroup and unconditionally torn down by
// Teardown. It only ever refers to a directory THIS backend created.
type transientCgroup struct {
	dir string
	fd  int // join fd; -1 when not (yet) open
}

// CreateTransientCgroup builds this spawn's transient scope: mkdir a uniquely
// named child under cg.Ancestor, apply the limits (pids.max mandatory, memory/cpu
// optional), and open the directory fd used to join the stage-2 child at clone.
// It returns (nil, nil) when cg applies no limits (Enforced() == false), so the
// caller simply spawns without a cgroup. On any failure it tears down whatever it
// created and returns a *cgroupError — best-effort at the call site (§7.4), never
// fatal to the spawn.
func CreateTransientCgroup(cg CompiledCgroup) (*transientCgroup, error) {
	if !cg.Enforced() {
		return nil, nil
	}
	name, err := transientScopeName()
	if err != nil {
		return nil, &cgroupError{Op: "scope name", Err: err}
	}
	dir := filepath.Join(cg.Ancestor, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, &cgroupError{Op: "mkdir " + dir, Err: err}
	}
	// From here every failure must tear down the directory we just created.
	tc := &transientCgroup{dir: dir, fd: -1}
	if err := applyCgroupLimits(dir, cg); err != nil {
		tc.Teardown()
		return nil, err
	}
	// O_CLOEXEC: the fd is consumed by the parent at clone3 time (CLONE_INTO_CGROUP)
	// and must not survive into the execve'd target. The parent still holds it until
	// Teardown closes it — CLOEXEC only affects the child post-exec.
	fd, err := unix.Open(dir, unix.O_DIRECTORY|unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		tc.Teardown()
		return nil, &cgroupError{Op: "open " + dir, Err: err}
	}
	tc.fd = fd
	return tc, nil
}

// applyCgroupLimits writes the resolved limits into the transient scope. pids.max
// is MANDATORY and is written-then-read-back: a cgroupfs that silently ignores
// the write, or a scope created where pids is not actually distributed, must
// fail-secure here rather than run believing a cap is in force (this is also the
// guard against a kernel that silently ignores the join). memory.max and cpu.max
// are OPTIONAL cost limits applied only when set; a failed write (e.g. the cpu
// controller is not delegated on this host) is narrowed to best-effort — never
// fatal — because they are not the load-bearing fork-bomb cap.
func applyCgroupLimits(dir string, cg CompiledCgroup) error {
	want := strconv.FormatInt(cg.PidsMax, 10)
	if err := writeCgroupFile(dir, "pids.max", want); err != nil {
		return &cgroupError{Op: "write pids.max", Err: err}
	}
	got, err := os.ReadFile(filepath.Join(dir, "pids.max"))
	if err != nil {
		return &cgroupError{Op: "read pids.max", Err: err}
	}
	if g := strings.TrimSpace(string(got)); g != want {
		return &cgroupError{Op: "verify pids.max", Err: fmt.Errorf("readback %q != configured %q", g, want)}
	}
	if cg.MemMax > 0 {
		// Best-effort optional cost limit; the memory controller is delegated here
		// but a failure must not sink the spawn (§7.4). Recorded at compile.
		_ = writeCgroupFile(dir, "memory.max", strconv.FormatInt(cg.MemMax, 10))
	}
	if cg.CPUPct > 0 {
		// Best-effort optional cost limit; the cpu controller is frequently NOT
		// delegated (this host distributes only memory+pids), so this write may fail
		// with ENOENT/EACCES — narrowed, never fatal (§7.4). Recorded at compile.
		_ = writeCgroupFile(dir, "cpu.max", FormatCPUMax(cg.CPUPct))
	}
	return nil
}

// Teardown unconditionally destroys the transient scope (SPEC §7.4). It is safe
// on a partially-constructed cgroup and only ever touches THIS scope's own
// directory. It closes the join fd, kills every process in the scope via
// cgroup.kill (a cgroup v2 feature — no by-pid SIGKILL, so no pid-reuse race),
// polls cgroup.procs until the kernel has drained the scope, then rmdir's it. All
// errors are best-effort: Teardown of a throwaway cgroup has nothing downstream
// depending on it; the sole goal is to leave no dangling cgroup and no processes
// we spawned.
func (tc *transientCgroup) Teardown() {
	if tc == nil {
		return
	}
	if tc.fd >= 0 {
		_ = unix.Close(tc.fd) // best-effort: release our own join fd
		tc.fd = -1
	}
	if tc.dir == "" {
		return
	}
	// Recursive kill of the whole subtree at once (cgroup v2). Preferred over
	// re-reading cgroup.procs and SIGKILL-ing by pid, which races pid reuse.
	_ = writeCgroupFile(tc.dir, "cgroup.kill", "1") // best-effort recursive kill
	for i := 0; i < cgroupDrainTries; i++ {
		if cgroupProcsEmpty(tc.dir) {
			if err := os.Remove(tc.dir); err == nil || errors.Is(err, os.ErrNotExist) {
				return
			}
			// EBUSY: tasks still draining from the kernel's view; retry after a wait.
		}
		time.Sleep(cgroupDrainInterval) // drain wait; not part of any assertion
	}
	_ = os.Remove(tc.dir) // final best-effort
}

// writeCgroupFile writes a single cgroup control value. cgroup files ignore the
// mode on an existing file, so 0 is passed for perm.
func writeCgroupFile(dir, name, val string) error {
	return os.WriteFile(filepath.Join(dir, name), []byte(val), 0)
}

// cgroupProcsEmpty reports whether dir/cgroup.procs lists no pids. An unreadable
// or absent file reads as empty — nothing left for us to kill. This is the
// pre-existing BEST-EFFORT reading used by Teardown (the optional
// resource-limit cgroup, never a lifetime guarantee): losing the ability to
// read cgroup.procs there must not wedge a throwaway scope's cleanup forever.
// KillAndWait (below), by contrast, is the MANDATORY lifetime-containment
// proof and never treats a read failure as empty — see cgroupProcsEmptyChecked.
func cgroupProcsEmpty(dir string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return true
	}
	return len(strings.Fields(string(b))) == 0
}

// cgroupProcsEmptyChecked is cgroupProcsEmpty's result-bearing counterpart for
// KillAndWait's mandatory proof (SPEC Task 12b): unlike cgroupProcsEmpty, a
// read failure is reported as an error, never coerced to "empty". Proving
// zero descendants requires a SUCCESSFUL read that says so — an absent file
// read as empty by omission would be exactly the fail-open bug this
// microtask exists to close.
func cgroupProcsEmptyChecked(dir string) (bool, error) {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return false, err
	}
	return len(strings.Fields(string(b))) == 0, nil
}

// CgroupProofError is a typed, retryable lifetime-containment proof failure
// (SPEC Task 12b): a cgroup.kill error, a cgroup.procs read/open error, a
// context timeout while waiting for the scope to drain, or a removal error.
// Op names the failing phase; Err wraps the underlying cause for
// errors.Is/errors.As. It never fires for the pre-existing best-effort
// resource-limit cgroup path (Teardown), which stays void/best-effort by
// design.
type CgroupProofError struct {
	Op  string
	Err error
}

func (e *CgroupProofError) Error() string {
	return "sandbox: cgroup proof: " + e.Op + ": " + e.Err.Error()
}
func (e *CgroupProofError) Unwrap() error { return e.Err }

// cgroupProofPollInterval bounds how often KillAndWait re-reads cgroup.procs
// while waiting for the kernel to finish draining a killed scope.
const cgroupProofPollInterval = 5 * time.Millisecond

// KillAndWait is the MANDATORY, result-bearing lifetime-containment proof a
// supervised spawn's teardown depends on (SPEC Task 12b) — the counterpart to
// Teardown's void/best-effort resource-limit cleanup, which this method does
// NOT replace (Teardown is unchanged and keeps its own callers). A nil return
// means: cgroup.kill succeeded or the scope was already gone (ENOENT reads as
// "nothing left to kill", not a failure — the scope cannot hold a descendant
// it no longer has), a SUCCESSFUL read then proved cgroup.procs empty, and
// this scope's owned cleanup (join fd close, rmdir) completed. Any other
// outcome — a cgroup.kill error, ctx expiring before the scope drains, a
// cgroup.procs read/open error, or a removal error — returns a
// *CgroupProofError and leaves the scope's directory and join fd untouched
// (retained) so a caller can retry the identical call later: the scope must
// never be treated as torn down, and its resources must never be released,
// until this returns nil. A read failure is never treated as empty.
//
// KillAndWait is idempotent and safe to call more than once (a caller that
// retries after a failed/indeterminate proof, e.g. this module's process
// quarantine, calls it again with the same receiver); calling it after a
// successful return is a harmless no-op (tc.dir is already "").
func (tc *transientCgroup) KillAndWait(ctx context.Context) error {
	if tc == nil || tc.dir == "" {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := writeCgroupFile(tc.dir, "cgroup.kill", "1"); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// The scope itself is gone: there is nothing left it could hold, so
			// this is the empty proof, not a failure.
			return tc.finishRemoval()
		}
		return &CgroupProofError{Op: "cgroup.kill", Err: err}
	}
	for {
		empty, err := cgroupProcsEmptyChecked(tc.dir)
		switch {
		case err != nil && errors.Is(err, os.ErrNotExist):
			// Removed out from under us between the kill and this read (e.g. a
			// concurrent Teardown/removal) — that is still an empty proof.
			return tc.finishRemoval()
		case err != nil:
			return &CgroupProofError{Op: "read cgroup.procs", Err: err}
		case empty:
			return tc.finishRemoval()
		}
		select {
		case <-ctx.Done():
			return &CgroupProofError{Op: "timeout", Err: ctx.Err()}
		case <-time.After(cgroupProofPollInterval):
		}
	}
}

// finishRemoval releases this scope's join fd and removes its directory. It
// is reached only once KillAndWait has an EMPTY proof in hand (a successful
// read of zero pids, or ENOENT — both mean nothing remains to hold the join
// fd or occupy the directory), so it is the single place tc's retained state
// is actually cleared; every failure branch above returns before reaching it,
// leaving tc.dir/tc.fd exactly as they were for a later retry.
func (tc *transientCgroup) finishRemoval() error {
	if tc.fd >= 0 {
		_ = unix.Close(tc.fd) // best-effort: our own fd, nothing else references it
		tc.fd = -1
	}
	dir := tc.dir
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return &CgroupProofError{Op: "rmdir " + dir, Err: err}
	}
	tc.dir = ""
	return nil
}

// Join wires this scope onto attr so the NEXT clone3(CLONE_INTO_CGROUP)
// places the spawned child directly inside it — the same UseCgroupFD/CgroupFD
// mechanism the optional resource-limit cgroup already uses (linuxWrap), but
// this scope's own fd, taking priority over any resource-limit scope's fd
// already set on attr: a supervised spawn's lifetime-containment join always
// wins the single available join slot (SPEC Task 12b — resource limiting is
// containment-of-cost, not a lifetime guarantee, and the two are mutually
// exclusive at this one kernel join point for a given spawn).
func (tc *transientCgroup) Join(attr *syscall.SysProcAttr) {
	if tc == nil || attr == nil || tc.fd < 0 {
		return
	}
	attr.UseCgroupFD = true
	attr.CgroupFD = tc.fd
}

// LifetimeScope is a delegated cgroup v2 scope created purely for exact
// process-tree containment (SPEC Task 12b) — independent of, and never
// conflated with, any policy.Limits resource-limit configuration. Join wires
// it onto a spawn's SysProcAttr before Start; KillAndWait is the mandatory,
// result-bearing zero-proof a supervised spawn's confirmed teardown depends
// on. It is the Rung-2 counterpart to Rung 1's PID-namespace containment
// (which needs no cgroup at all: the kernel's own namespace-teardown-on-init-
// exit guarantee is exact by construction).
type LifetimeScope interface {
	Join(attr *syscall.SysProcAttr)
	KillAndWait(ctx context.Context) error
}

// NewLifetimeScope creates one supervised spawn's dedicated lifetime cgroup
// under ancestor — the backend's already-probed delegated pids Ancestor
// (Backend.CgroupPids). It applies only the load-bearing pids.max safety cap
// (DefaultMaxPIDs), never a caller-tunable resource limit: this scope's sole
// purpose is an exact cgroup.kill + cgroup.procs-empty containment proof, not
// cost control (the separate, policy-driven, best-effort resource-limit
// cgroup is CompiledCgroup/CreateTransientCgroup, unchanged by this
// function). ancestor == "" (no delegation) fails closed with
// enforce.ErrLifetimeContainmentUnavailable — there is no best-effort
// fallback for a supervised Rung-2 spawn's containment (SPEC Task 12b).
func NewLifetimeScope(ancestor string) (LifetimeScope, error) {
	if ancestor == "" {
		return nil, enforce.ErrLifetimeContainmentUnavailable
	}
	tc, err := CreateTransientCgroup(CompiledCgroup{Ancestor: ancestor, PidsMax: DefaultMaxPIDs})
	if err != nil {
		return nil, errors.Join(enforce.ErrLifetimeContainmentUnavailable, err)
	}
	if tc == nil {
		// Unreachable given a non-empty Ancestor above (Enforced() is then
		// always true), but guarded rather than assumed.
		return nil, enforce.ErrLifetimeContainmentUnavailable
	}
	return tc, nil
}

// FormatCPUMax renders a MaxCPUPct as a cgroup v2 cpu.max value ("<quota>
// <period>", microseconds). 100% ⇒ one full core (quota == period); values above
// 100 permit more than one core's worth on a multi-core host.
func FormatCPUMax(pct int) string {
	quota := pct * cpuMaxPeriodUsec / 100
	return strconv.Itoa(quota) + " " + strconv.Itoa(cpuMaxPeriodUsec)
}

// transientScopeName returns a cgroup directory name with crypto/rand entropy
// BEYOND the pid: under `-count=N` or after a crashed prior run, a pid-named dir
// can already exist and make Mkdir fail EEXIST. crypto/rand here is name entropy,
// not a security decision and not an assertion input, so it is the right source
// (math/rand is banned). rand.Read never fails on modern Go; the error is handled
// for completeness.
func transientScopeName() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return CgroupScopePrefix + hex.EncodeToString(b[:]), nil
}
