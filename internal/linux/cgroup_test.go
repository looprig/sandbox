//go:build linux

package linux

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
)

// This file covers Task 12b's mandatory, result-bearing lifetime-containment
// cgroup proof (KillAndWait), distinct from the pre-existing best-effort
// resource-limit cgroup (CompiledCgroup/CreateTransientCgroup/Teardown,
// cgroup.go, unit-tested elsewhere and unchanged by this microtask). These
// tests need real cgroup v2 pids delegation and RUN FOR REAL on a host that
// has it (requireLifetimeCgroup skips, rather than silently passing, on one
// that does not).

// requireLifetimeCgroup skips a test on a host without cgroup v2 pids
// delegation — the same fail-secure skip discipline
// internal/exec's requireCgroupPids already uses for the resource-limit
// suite.
func requireLifetimeCgroup(t *testing.T) string {
	t.Helper()
	anc := ProbeDelegatedPidsAncestor()
	if anc == "" {
		t.Skip("cgroup v2 pids delegation unavailable on this host; lifetime-containment cgroup tests cannot run")
	}
	return anc
}

// newLifetimeScopeForTest creates a real scope and registers cleanup that
// removes it even if the test's own KillAndWait call fails/leaves it
// retained, so a failing test never leaks a dangling lrsb-* directory.
func newLifetimeScopeForTest(t *testing.T, ancestor string) LifetimeScope {
	t.Helper()
	scope, err := NewLifetimeScope(ancestor)
	if err != nil {
		t.Fatalf("NewLifetimeScope: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = scope.KillAndWait(ctx) // best-effort final cleanup
	})
	return scope
}

// scopeDir recovers a *transientCgroup's directory for test assertions. It is
// package-internal (this file lives in package linux), so it can reach the
// unexported field directly rather than needing an exported accessor whose
// only purpose would be testing.
func scopeDir(t *testing.T, scope LifetimeScope) string {
	t.Helper()
	tc, ok := scope.(*transientCgroup)
	if !ok {
		t.Fatalf("scope is %T, want *transientCgroup", scope)
	}
	return tc.dir
}

// joinRealProcess starts `sleep 30` and moves it into scope's cgroup by
// writing its pid to cgroup.procs directly — the same effect
// SysProcAttr.UseCgroupFD/CgroupFD (Join) has at clone time, but usable here
// without wiring a full confined spawn, so this file can test KillAndWait in
// isolation. t.Cleanup guarantees the suite never leaks a live sleep even if
// the test's own kill/reap path fails.
//
// Some hosts' cgroup v2 delegation rejects populating a freshly created
// child cgroup at all (EOPNOTSUPP from the kernel, on both a cgroup.procs
// migration and a clone3(CLONE_INTO_CGROUP) join alike) — a host-level cgroup
// v2 delegation limitation, reproducible with this package's PRE-EXISTING,
// unmodified CreateTransientCgroup/resource-limit path too, so it is not
// specific to KillAndWait. requireLifetimeCgroup only proves pids
// delegation and a writable Ancestor exist; it cannot also prove population
// works without actually trying, so that skip is applied here, at the one
// call site that actually populates a scope, rather than widening
// requireLifetimeCgroup itself.
func joinRealProcess(t *testing.T, dir string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	pid := strconv.Itoa(cmd.Process.Pid)
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte(pid), 0); err != nil {
		if errors.Is(err, syscall.EOPNOTSUPP) {
			t.Skipf("this host's cgroup v2 delegation rejects populating a freshly created child cgroup (EOPNOTSUPP), independent of this package's code: %v", err)
		}
		t.Fatalf("join cgroup.procs: %v", err)
	}
	return cmd
}

// TestCgroupLifetimeKillAndWait proves the mandatory proof end to end: a real
// live process joined into the scope is killed and reaped, KillAndWait
// returns nil, and the scope's directory is gone (owned cleanup completed) —
// the exact contract Wait/quarantine depend on before treating a supervised
// spawn's teardown as confirmed.
func TestCgroupLifetimeKillAndWait(t *testing.T) {
	ancestor := requireLifetimeCgroup(t)
	scope := newLifetimeScopeForTest(t, ancestor)
	dir := scopeDir(t, scope)
	cmd := joinRealProcess(t, dir)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := scope.KillAndWait(ctx); err != nil {
		t.Fatalf("KillAndWait = %v, want nil", err)
	}

	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("scope directory %s still exists after a nil KillAndWait: err=%v", dir, err)
	}
	// The joined process was recursively killed by cgroup.kill; reap it so the
	// test does not leak a zombie (cmd.Wait after an external kill returns a
	// *exec.ExitError, which is the expected/only possible outcome here).
	err := cmd.Wait()
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) {
		t.Fatalf("Wait on cgroup-killed process: %v", err)
	}
}

// TestCgroupLifetimeReadFailureIndeterminate proves a cgroup.procs read
// failure is reported as a typed, non-empty proof — NEVER coerced to "empty"
// — and that the scope is retained (not torn down) so a caller can retry: it
// makes cgroup.kill succeed (no live process needed for a kill to "succeed or
// be unnecessary") but then removes read permission on the scope directory,
// so the subsequent cgroup.procs read fails with a permission error distinct
// from ENOENT ("already gone", which IS a valid empty proof and must not be
// confused with this case). Retrying after permissions are restored succeeds.
func TestCgroupLifetimeReadFailureIndeterminate(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: directory permissions cannot deny root a read, so this failure mode cannot be induced")
	}
	ancestor := requireLifetimeCgroup(t)
	scope := newLifetimeScopeForTest(t, ancestor)
	dir := scopeDir(t, scope)

	if err := os.Chmod(dir, 0); err != nil {
		t.Fatalf("chmod 0 %s: %v", dir, err)
	}
	restored := false
	restore := func() {
		if restored {
			return
		}
		restored = true
		_ = os.Chmod(dir, 0o700)
	}
	defer restore()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := scope.KillAndWait(ctx)
	if err == nil {
		t.Fatal("KillAndWait succeeded despite an unreadable cgroup.procs; want a typed indeterminate proof error")
	}
	var proofErr *CgroupProofError
	if !errors.As(err, &proofErr) {
		t.Fatalf("KillAndWait error = %v (%T), want *CgroupProofError", err, err)
	}
	if proofErr.Op != "read cgroup.procs" && proofErr.Op != "cgroup.kill" {
		t.Errorf("CgroupProofError.Op = %q, want a kill or read-cgroup.procs phase (the induced failure is a permission error on the directory itself)", proofErr.Op)
	}
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("KillAndWait error does not unwrap to a permission error: %v", err)
	}

	// Retained, not torn down: the directory must still exist.
	restore()
	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("scope directory missing after an indeterminate proof (should be retained): %v", statErr)
	}

	// A retry with permissions restored succeeds and completes teardown.
	if err := scope.KillAndWait(context.Background()); err != nil {
		t.Fatalf("retry KillAndWait after restoring permissions = %v, want nil", err)
	}
	if _, statErr := os.Stat(dir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("scope directory still exists after a successful retry: err=%v", statErr)
	}
}

// TestCgroupLifetimeRetainsOnUnprovedEmpty proves that ANY failed/
// indeterminate proof — not just a read failure — leaves the scope's
// directory (and thus its join fd, which nothing has closed) fully intact
// for a retry: an already-expired context guarantees the poll loop's very
// first ctx.Done() check fires before any read can prove emptiness, against
// a scope that genuinely still holds a live process.
func TestCgroupLifetimeRetainsOnUnprovedEmpty(t *testing.T) {
	ancestor := requireLifetimeCgroup(t)
	scope := newLifetimeScopeForTest(t, ancestor)
	dir := scopeDir(t, scope)
	joinRealProcess(t, dir)

	expired, cancel := context.WithTimeout(context.Background(), 0)
	defer cancel()
	<-expired.Done() // guarantee the deadline has already passed

	err := scope.KillAndWait(expired)
	if err == nil {
		t.Fatal("KillAndWait succeeded against an already-expired context; want a typed timeout proof error")
	}
	var proofErr *CgroupProofError
	if !errors.As(err, &proofErr) {
		t.Fatalf("KillAndWait error = %v (%T), want *CgroupProofError", err, err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("KillAndWait error does not unwrap to context.DeadlineExceeded: %v", err)
	}

	if _, statErr := os.Stat(dir); statErr != nil {
		t.Fatalf("scope directory missing after an unproved-empty (timeout) proof; want retained: %v", statErr)
	}
	// A retry with ample time succeeds: the process is real and cgroup.kill
	// (already issued once above, idempotent to repeat) finishes it off.
	ctx, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if err := scope.KillAndWait(ctx); err != nil {
		t.Fatalf("retry KillAndWait with ample time = %v, want nil", err)
	}
	if _, statErr := os.Stat(dir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("scope directory still exists after a successful retry: err=%v", statErr)
	}
}

// TestNewLifetimeScopeFailsClosedWithoutDelegation proves the fail-closed
// contract on the no-delegation branch (independent of host cgroup
// availability): an empty ancestor never returns a usable scope.
func TestNewLifetimeScopeFailsClosedWithoutDelegation(t *testing.T) {
	t.Parallel()
	scope, err := NewLifetimeScope("")
	if err == nil {
		t.Fatal("NewLifetimeScope(\"\") succeeded; want a fail-closed error")
	}
	if scope != nil {
		t.Fatalf("NewLifetimeScope(\"\") returned a non-nil scope alongside an error: %v", scope)
	}
	if !errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
		t.Errorf("error = %v, want it to wrap enforce.ErrLifetimeContainmentUnavailable", err)
	}
}

// TestLifetimeScopeJoinSetsCgroupFD proves Join wires UseCgroupFD/CgroupFD
// onto a SysProcAttr, overriding any prior cgroup fd already set there (the
// documented priority: a supervised spawn's lifetime join always wins the
// single clone3 CLONE_INTO_CGROUP slot over a best-effort resource-limit
// cgroup's own join).
func TestLifetimeScopeJoinSetsCgroupFD(t *testing.T) {
	ancestor := requireLifetimeCgroup(t)
	scope := newLifetimeScopeForTest(t, ancestor)

	attr := &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: 999999}
	scope.Join(attr)
	if !attr.UseCgroupFD {
		t.Fatal("Join did not set UseCgroupFD")
	}
	if attr.CgroupFD == 999999 {
		t.Fatal("Join did not override the pre-existing CgroupFD")
	}
	if attr.CgroupFD < 0 {
		t.Fatalf("Join set an invalid CgroupFD = %d", attr.CgroupFD)
	}
}

// TestCgroupLifetimeKillAndWaitAlreadyGoneIsEmptyProof proves that a scope
// whose directory has already been removed out from under it (e.g. a
// concurrent Teardown, or a prior successful KillAndWait) reads as an empty
// proof (nil), not a failure — cgroup.kill's ENOENT on an absent scope means
// there is nothing left it could hold.
func TestCgroupLifetimeKillAndWaitAlreadyGoneIsEmptyProof(t *testing.T) {
	ancestor := requireLifetimeCgroup(t)
	scope := newLifetimeScopeForTest(t, ancestor)
	dir := scopeDir(t, scope)

	// Remove the directory out from under the scope directly (bypassing
	// KillAndWait/Teardown), simulating "already gone".
	if err := os.RemoveAll(dir); err != nil {
		t.Fatalf("RemoveAll %s: %v", dir, err)
	}

	if err := scope.KillAndWait(context.Background()); err != nil {
		t.Fatalf("KillAndWait on an already-removed scope = %v, want nil (empty proof)", err)
	}
}

// TestCompileCgroupPolicyNeverConflatesWithLifetimeScope is a documentation-
// level guard: the best-effort resource-limit compile path
// (CompileCgroupPolicy) and the mandatory lifetime path (NewLifetimeScope)
// are independent — a Disabled resource-limit policy must not prevent
// lifetime containment, since the two serve different guarantees (SPEC Task
// 12b: "the existing optional/best-effort resource-cgroup behavior is not a
// lifetime guarantee").
func TestCompileCgroupPolicyNeverConflatesWithLifetimeScope(t *testing.T) {
	ancestor := requireLifetimeCgroup(t)
	cg := CompileCgroupPolicy(policy.Limits{Disabled: true}, ancestor)
	if cg.Enforced() {
		t.Fatal("Disabled resource-limit policy unexpectedly reports Enforced")
	}
	// A lifetime scope must still be obtainable regardless.
	scope := newLifetimeScopeForTest(t, ancestor)
	if err := scope.KillAndWait(context.Background()); err != nil {
		t.Fatalf("lifetime scope unaffected by a Disabled resource-limit policy still failed: %v", err)
	}
}
