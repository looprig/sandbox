//go:build linux

package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// requireLandlockV4 skips a test on a host without Landlock ABI v4 (rung 2). This
// host has v4, so these tests RUN for real; the skip keeps the suite honest on
// weaker kernels rather than silently passing an unenforced sandbox.
func requireLandlockV4(t *testing.T) {
	t.Helper()
	if abi := probeLandlockABI(); abi < 4 {
		t.Skipf("landlock ABI v4 unavailable: kernel reports ABI v%d; rung-2 FS confinement cannot run", abi)
	}
}

// newFSExecutor builds an executor pinned to the rung-2 linux backend.
func newFSExecutor(t *testing.T, p Policy) *Executor {
	t.Helper()
	e, err := NewExecutor(p, withBackend(newLinuxBackend()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	return e
}

// shq single-quotes a filesystem path for embedding in a /bin/sh command. Test
// paths (temp dirs, home) never contain single quotes, so this is sufficient.
func shq(p string) string { return "'" + p + "'" }

// tryWrite runs `: > path` under the sandbox: the shell opens path for
// write (O_CREAT|O_TRUNC) via the `:` builtin and a redirect — no external
// binary — so the exit code reflects exactly whether Landlock permitted the
// write. code 0 == permitted, non-zero == denied.
func tryWrite(t *testing.T, e *Executor, ws, path string) int {
	t.Helper()
	_, code, err := e.RunCommand(context.Background(), ws, ": > "+shq(path))
	if err != nil {
		t.Fatalf("RunCommand(write %s): %v", path, err)
	}
	return code
}

// tryRead runs `: < path` under the sandbox: the shell opens path for read. The
// path must pre-exist so a non-zero code means "read denied", not "missing".
func tryRead(t *testing.T, e *Executor, ws, path string) int {
	t.Helper()
	_, code, err := e.RunCommand(context.Background(), ws, ": < "+shq(path))
	if err != nil {
		t.Fatalf("RunCommand(read %s): %v", path, err)
	}
	return code
}

// TestLinuxFSWriteBoundary is the headline anti-fail-open proof: a write INSIDE
// the workspace succeeds while a write OUTSIDE it (under the read-only home) is
// denied by Landlock. BOTH halves matter — a blanket deny that fails every write
// would satisfy the negative half alone but would (correctly) fail the positive
// half here, so it cannot masquerade as a working write boundary.
func TestLinuxFSWriteBoundary(t *testing.T) {
	requireLandlockV4(t)
	ws := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	// A path under the (read-only) home that we never create; the write must be
	// denied, so nothing is written. Cleanup removes it defensively in case a
	// regression let the write through.
	outside := filepath.Join(home, ".lrsandbox-writeboundary-should-not-exist")
	t.Cleanup(func() { _ = os.Remove(outside) })

	e := newFSExecutor(t, PolicyFor(Write, ws))

	inside := filepath.Join(ws, "inside.txt")
	if code := tryWrite(t, e, ws, inside); code != 0 {
		t.Errorf("write INSIDE workspace denied (exit %d), want permitted — write boundary too tight", code)
	}
	if _, err := os.Stat(inside); err != nil {
		t.Errorf("inside file not created despite exit 0: %v", err)
	}

	if code := tryWrite(t, e, ws, outside); code == 0 {
		t.Errorf("write OUTSIDE workspace (%s) succeeded — FAIL-OPEN: the write boundary leaked", outside)
	}
	if _, err := os.Stat(outside); err == nil {
		t.Errorf("outside file was created — FAIL-OPEN: Landlock did not confine the write")
	}
}

// TestLinuxFSTmpWritable proves /tmp is writable under the Write policy (TMPDIR
// is forced to /tmp, so tools must be able to write there).
func TestLinuxFSTmpWritable(t *testing.T) {
	requireLandlockV4(t)
	ws := t.TempDir()
	e := newFSExecutor(t, PolicyFor(Write, ws))

	tmpFile := filepath.Join("/tmp", ".lrsandbox-tmp-writable-test")
	t.Cleanup(func() { _ = os.Remove(tmpFile) })
	if code := tryWrite(t, e, ws, tmpFile); code != 0 {
		t.Errorf("write under /tmp denied (exit %d), want permitted", code)
	}
	if _, err := os.Stat(tmpFile); err != nil {
		t.Errorf("/tmp file not created despite exit 0: %v", err)
	}
}

// TestLinuxFSGitCarveout proves the .git read-only carveout via ENUMERATED
// SIBLING ALLOWS (§7.5): with a pre-existing .git, the workspace becomes
// RW-except-.git. The command can READ .git/config but WRITING into .git is
// denied, while writing a pre-existing sibling dir (src) still succeeds — proving
// the carve is a scoped sibling enumeration, not a blanket workspace deny.
func TestLinuxFSGitCarveout(t *testing.T) {
	requireLandlockV4(t)
	ws := t.TempDir()
	gitDir := filepath.Join(ws, ".git")
	if err := os.Mkdir(gitDir, 0o700); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	gitConfig := filepath.Join(gitDir, "config")
	if err := os.WriteFile(gitConfig, []byte("[core]\n"), 0o600); err != nil {
		t.Fatalf("seed .git/config: %v", err)
	}
	srcDir := filepath.Join(ws, "src")
	if err := os.Mkdir(srcDir, 0o700); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	e := newFSExecutor(t, PolicyFor(Write, ws))

	// Positive: .git/config is readable, and the pre-existing src sibling is
	// writable.
	if code := tryRead(t, e, ws, gitConfig); code != 0 {
		t.Errorf("read .git/config denied (exit %d), want permitted (carveout is read-only, not no-access)", code)
	}
	if code := tryWrite(t, e, ws, filepath.Join(srcDir, "x")); code != 0 {
		t.Errorf("write src/x denied (exit %d), want permitted (pre-existing writable sibling) — sibling enumeration failed", code)
	}
	// Negative: writing into .git is denied (read-only carveout).
	gitWrite := filepath.Join(gitDir, "x")
	if code := tryWrite(t, e, ws, gitWrite); code == 0 {
		t.Errorf("write into .git succeeded — FAIL-OPEN: the read-only carveout leaked write access")
	}
	if _, err := os.Stat(gitWrite); err == nil {
		t.Errorf(".git/x was created — FAIL-OPEN: carveout not enforced")
	}
}

// TestLinuxFSSecretDeny proves a fixed-path secret deny is enforced by enumerated
// allows: the denied file cannot be read, while an allowed sibling and an allowed
// system path (/etc/hostname) remain readable. Positive + negative halves.
func TestLinuxFSSecretDeny(t *testing.T) {
	requireLandlockV4(t)
	ws := t.TempDir()
	secret := filepath.Join(ws, "secret.txt")
	if err := os.WriteFile(secret, []byte("token"), 0o600); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	allowed := filepath.Join(ws, "allowed.txt")
	if err := os.WriteFile(allowed, []byte("public"), 0o600); err != nil {
		t.Fatalf("seed allowed: %v", err)
	}

	e := newFSExecutor(t, PolicyFor(Write, ws, WithDenyRead(secret)))

	// Negative: the secret is unreadable (denied out of BOTH the workspace RW and
	// the broad "/" read via enumerated sibling allows).
	if code := tryRead(t, e, ws, secret); code == 0 {
		t.Errorf("read of denied secret succeeded — FAIL-OPEN: fixed-path deny leaked")
	}
	// Positive: an allowed sibling and a system path stay readable (proves the
	// deny is scoped, not a blanket read-deny).
	if code := tryRead(t, e, ws, allowed); code != 0 {
		t.Errorf("read allowed sibling denied (exit %d), want permitted — deny over-broad", code)
	}
	if _, err := os.Stat("/etc/hostname"); err == nil {
		if code := tryRead(t, e, ws, "/etc/hostname"); code != 0 {
			t.Errorf("read /etc/hostname denied (exit %d), want permitted (system read)", code)
		}
	}
}

// TestLinuxFSSnapshotSemantics asserts the documented §7.5 snapshot behavior: a
// carved workspace (its writable root is enumerated, not granted whole) permits
// writes to a PRE-EXISTING subdirectory but denies a NEW top-level file — the
// narrow direction §7.5 explicitly accepts. It also asserts the CompileReport
// records the carveout narrowing.
func TestLinuxFSSnapshotSemantics(t *testing.T) {
	requireLandlockV4(t)
	ws := t.TempDir()
	// A pre-existing .git forces the workspace to be carved (RW-except-.git), so
	// the root is enumerated rather than granted whole.
	if err := os.Mkdir(filepath.Join(ws, ".git"), 0o700); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	work := filepath.Join(ws, "work")
	if err := os.Mkdir(work, 0o700); err != nil {
		t.Fatalf("mkdir work: %v", err)
	}

	e := newFSExecutor(t, PolicyFor(Write, ws))

	// Pre-existing subdir: writable.
	if code := tryWrite(t, e, ws, filepath.Join(work, "x")); code != 0 {
		t.Errorf("write pre-existing work/x denied (exit %d), want permitted", code)
	}
	// New top-level file at the carved root: inaccessible (snapshot semantics).
	newTop := filepath.Join(ws, "newtop.txt")
	if code := tryWrite(t, e, ws, newTop); code == 0 {
		t.Errorf("write new top-level file at carved root succeeded (exit 0); §7.5 snapshot semantics require it be inaccessible")
	}

	// The report must record the carveout narrowing.
	if !reportHas(e.Report(), "carveout", "narrowed") {
		t.Errorf("CompileReport missing carveout/narrowed entry; report=%+v", e.Report())
	}
}

// TestLinuxFSGuarantees asserts the rung-2 FS level/guarantee posture (§6, §7.5):
// write boundary + fixed read-denies + env scrub enforced; process/network/
// address/resource guarantees NOT claimed; level is Degraded.
func TestLinuxFSGuarantees(t *testing.T) {
	requireLandlockV4(t)
	ws := t.TempDir()
	e := newFSExecutor(t, PolicyFor(Write, ws))

	g := e.Guarantees()
	trueBits := []struct {
		name string
		got  bool
	}{
		{"WriteBoundary", g.WriteBoundary},
		{"ReadDenies", g.ReadDenies},
		{"EnvScrub", g.EnvScrub},
		// NetworkBoundary is earned by 12c: PolicyFor(Write) is net-confined (Net{}
		// compiles to an empty TCP allowlist = all TCP denied), so the port-level
		// network boundary holds. AddressNetwork stays false — rung 2 cannot
		// address-scope.
		{"NetworkBoundary", g.NetworkBoundary},
	}
	for _, b := range trueBits {
		if !b.got {
			t.Errorf("Guarantees().%s = false, want true", b.name)
		}
	}
	falseBits := []struct {
		name string
		got  bool
	}{
		{"ProcessBoundary", g.ProcessBoundary},
		{"AddressNetwork", g.AddressNetwork},
		{"ResourceLimits", g.ResourceLimits},
	}
	for _, b := range falseBits {
		if b.got {
			t.Errorf("Guarantees().%s = true, want false (not enforced at rung 2)", b.name)
		}
	}
	if lvl := e.Level(); lvl != LevelDegraded {
		t.Errorf("Level() = %d, want LevelDegraded (%d)", lvl, LevelDegraded)
	}
}

// TestLinuxFSFailsClosedOnUnexecutableTarget proves the confinement fails CLOSED:
// a policy so tight that the target binary is not granted execute (no system
// read) makes the stage-2 child unable to execve it, so the spawn exits non-zero
// and the target never runs unconfined — rather than falling through to run it.
func TestLinuxFSFailsClosedOnUnexecutableTarget(t *testing.T) {
	requireLandlockV4(t)
	ws := t.TempDir()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}
	_ = home
	// Only the workspace is granted; NOTHING under /usr or /lib, so /bin/echo and
	// its loader cannot be opened for exec.
	p := Policy{
		Workspace: ws,
		FS:        []FSEntry{{Path: ws, Access: ReadAccess | WriteAccess | ExecAccess}},
		Env:       EnvPolicy{Set: map[string]string{"TMPDIR": "/tmp"}},
	}
	e := newFSExecutor(t, p)

	out, code, err := e.RunArgv(context.Background(), ws, []string{"/bin/echo", "confined"})
	if err != nil {
		// A spawn/setup error is also an acceptable fail-closed outcome; either way
		// the target did not run.
		if string(out) == "confined\n" {
			t.Fatalf("target produced output despite error — FAIL-OPEN: %v", err)
		}
		return
	}
	if code == 0 {
		t.Errorf("over-restrictive FS spawn exited 0 — FAIL-OPEN: target ran unconfined; out=%q", out)
	}
	if string(out) == "confined\n" {
		t.Errorf("target echoed its output — FAIL-OPEN: it executed despite no exec grant; out=%q", out)
	}
}

// reportHas reports whether the report contains an entry with the given feature
// and status.
func reportHas(r CompileReport, feature, status string) bool {
	for _, e := range r.Entries {
		if e.Feature == feature && e.Status == status {
			return true
		}
	}
	return false
}

// --- Pure enumeration unit tests (no Landlock; fast) ------------------------
// These directly exercise the security-critical carve logic — an off-by-one here
// that grants a deny's parent is a secret-leak fail-open, so it is tested in
// isolation from the kernel.

func TestPathUnder(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		parent string
		path   string
		want   bool
	}{
		{"child of root", "/", "/home", true},
		{"root under root is not strict", "/", "/", false},
		{"nested under dir", "/a/b", "/a/b/c", true},
		{"equal is not strict", "/a/b", "/a/b", false},
		{"sibling prefix is not under", "/a/b", "/a/bc", false},
		{"unrelated", "/a/b", "/x/y", false},
		{"deep nested", "/a", "/a/b/c/d", true},
		{"parent of parent is not under", "/a/b/c", "/a/b", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := pathUnder(tt.parent, tt.path); got != tt.want {
				t.Errorf("pathUnder(%q, %q) = %v, want %v", tt.parent, tt.path, got, tt.want)
			}
		})
	}
}

// TestEnumerateFSRules builds a real temp tree and asserts the enumerated rule
// set carves correctly: denied and read-only-carveout subtrees are excluded, the
// covering writable root is NOT granted whole (so new root files are excluded),
// and every unaffected sibling is granted with the covering access.
func TestEnumerateFSRules(t *testing.T) {
	// Build: root/{a,b,secret,.git}/ each a dir with a file.
	root := t.TempDir()
	for _, name := range []string{"a", "b", "secret", ".git"} {
		d := filepath.Join(root, name)
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
		if err := os.WriteFile(filepath.Join(d, "f"), []byte("x"), 0o600); err != nil {
			t.Fatalf("seed %s/f: %v", d, err)
		}
	}

	access := func(rules []fsRule, path string) (FSAccess, bool) {
		for _, r := range rules {
			if r.Path == path {
				return r.Access, true
			}
		}
		return 0, false
	}

	t.Run("no excludes grants the root whole", func(t *testing.T) {
		cfs := compiledFS{allows: []fsAllow{{path: root, access: ReadAccess | WriteAccess | ExecAccess}}}
		rules := enumerateFSRules(cfs)
		if acc, ok := access(rules, root); !ok || acc&WriteAccess == 0 {
			t.Errorf("root should be granted RW whole when nothing is carved; rules=%+v", rules)
		}
	})

	t.Run("deny is carved out of the writable root", func(t *testing.T) {
		secret := filepath.Join(root, "secret")
		cfs := compiledFS{
			allows: []fsAllow{{path: root, access: ReadAccess | WriteAccess | ExecAccess}},
			denies: []string{secret},
		}
		rules := enumerateFSRules(cfs)
		if _, ok := access(rules, secret); ok {
			t.Errorf("FAIL-OPEN: denied path %q was granted; rules=%+v", secret, rules)
		}
		if _, ok := access(rules, root); ok {
			t.Errorf("carved root %q must NOT be granted whole (would re-include the deny); rules=%+v", root, rules)
		}
		for _, sib := range []string{"a", "b", ".git"} {
			p := filepath.Join(root, sib)
			if acc, ok := access(rules, p); !ok || acc&WriteAccess == 0 {
				t.Errorf("sibling %q of the deny should be granted RW; rules=%+v", p, rules)
			}
		}
	})

	t.Run("read-only carveout under a writable root", func(t *testing.T) {
		gitDir := filepath.Join(root, ".git")
		cfs := compiledFS{allows: []fsAllow{
			{path: root, access: ReadAccess | WriteAccess | ExecAccess},
			{path: gitDir, access: ReadAccess},
		}}
		rules := enumerateFSRules(cfs)
		// .git present as a read-only rule (from its own allow), never writable.
		if acc, ok := access(rules, gitDir); !ok {
			t.Errorf(".git should be granted read-only; rules=%+v", rules)
		} else if acc&WriteAccess != 0 {
			t.Errorf("FAIL-OPEN: .git carveout granted write access %b; rules=%+v", acc, rules)
		}
		// Root not granted whole; siblings writable.
		if _, ok := access(rules, root); ok {
			t.Errorf("carved root must not be granted whole; rules=%+v", rules)
		}
		for _, sib := range []string{"a", "b", "secret"} {
			p := filepath.Join(root, sib)
			if acc, ok := access(rules, p); !ok || acc&WriteAccess == 0 {
				t.Errorf("sibling %q should be granted RW; rules=%+v", p, rules)
			}
		}
	})

	t.Run("nonexistent deny does not carve (existence-gated)", func(t *testing.T) {
		cfs := compiledFS{
			allows: []fsAllow{{path: root, access: ReadAccess | WriteAccess | ExecAccess}},
			denies: []string{filepath.Join(root, "does-not-exist")},
		}
		rules := enumerateFSRules(cfs)
		if acc, ok := access(rules, root); !ok || acc&WriteAccess == 0 {
			t.Errorf("a nonexistent deny must not force carving; root should be granted whole; rules=%+v", rules)
		}
	})
}

// TestEnumerateDenyOverridesAllow proves the review's Finding 1 fix: an ALLOW
// whose path is at-or-under a literal DENY is dropped (deny is a hard override,
// SPEC §5.1) — no emitted rule covers the denied subtree. Covers both deny==allow
// and deny-is-ancestor-of-allow.
func TestEnumerateDenyOverridesAllow(t *testing.T) {
	root := t.TempDir()
	mk := func(p string) string {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(full, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", full, err)
		}
		return full
	}
	foo := mk("foo")
	abchild := mk("a/b")
	a := filepath.Dir(abchild)

	tests := []struct {
		name   string
		cfs    compiledFS
		denied string // no emitted rule may be at-or-under this path
	}{
		{
			name:   "deny equals allow",
			cfs:    compiledFS{allows: []fsAllow{{path: foo, access: ReadAccess | WriteAccess | ExecAccess}}, denies: []string{foo}},
			denied: foo,
		},
		{
			name:   "deny is ancestor of allow",
			cfs:    compiledFS{allows: []fsAllow{{path: abchild, access: ReadAccess | WriteAccess | ExecAccess}}, denies: []string{a}},
			denied: abchild,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := enumerateFSRules(tt.cfs)
			for _, r := range rules {
				// No emitted rule may be the denied path itself or an ancestor of it
				// (an ancestor rule would grant the denied subtree recursively).
				if r.Path == tt.denied || pathUnder(r.Path, tt.denied) {
					t.Errorf("emitted rule %q covers denied path %q (fail-open)", r.Path, tt.denied)
				}
			}
		})
	}
}

// TestLinuxFSDenyEqualsAllowIsDenied is the end-to-end proof of Finding 1 through
// the public API: a path that is BOTH WithWritable and WithDenyRead must resolve
// to denied (deny wins), so a spawned command cannot read it.
func TestLinuxFSDenyEqualsAllowIsDenied(t *testing.T) {
	requireLandlockV4(t)
	ws := t.TempDir()
	secretDir := t.TempDir()
	secret := filepath.Join(secretDir, "secret.txt")
	if err := os.WriteFile(secret, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatalf("seed secret: %v", err)
	}

	e, err := NewExecutor(PolicyFor(Write, ws, WithWritable(secretDir), WithDenyRead(secretDir)), withBackend(newLinuxBackend()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	// The command tries to read the deny==allow path; it must be blocked.
	out, code, err := e.RunArgv(context.Background(), ws, []string{"cat", secret})
	if err != nil {
		t.Fatalf("RunArgv(cat secret): unexpected spawn error: %v (out=%q)", err, out)
	}
	if code == 0 {
		t.Errorf("read of a deny==allow path SUCCEEDED (fail-open): code=%d out=%q", code, out)
	}
}

// TestLandlockAccessSetHonorsBits proves Finding 2: each of Read/Exec/Write maps
// to its own Landlock rights and no others — a read-only entry grants NO execute
// (the RODirs-bundles-execute over-grant is closed).
func TestLandlockAccessSetHonorsBits(t *testing.T) {
	tests := []struct {
		name     string
		access   FSAccess
		isDir    bool
		wantExec bool
		wantRead bool
		wantWr   bool
	}{
		{"read-only dir grants no execute", ReadAccess, true, false, true, false},
		{"read+exec dir grants execute", ReadAccess | ExecAccess, true, true, true, false},
		{"read|write|exec dir grants all", ReadAccess | WriteAccess | ExecAccess, true, true, true, true},
		{"read-only file grants no execute", ReadAccess, false, false, true, false},
		{"exec-only grants execute, no read", ExecAccess, false, true, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			set := landlockAccessSet(tt.access, tt.isDir)
			if got := set&llsys.AccessFSExecute != 0; got != tt.wantExec {
				t.Errorf("execute bit = %v, want %v (set=%#x)", got, tt.wantExec, set)
			}
			if got := set&llsys.AccessFSReadFile != 0; got != tt.wantRead {
				t.Errorf("read-file bit = %v, want %v (set=%#x)", got, tt.wantRead, set)
			}
			if got := set&llsys.AccessFSWriteFile != 0; got != tt.wantWr {
				t.Errorf("write-file bit = %v, want %v (set=%#x)", got, tt.wantWr, set)
			}
		})
	}
}
