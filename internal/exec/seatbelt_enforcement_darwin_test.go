//go:build darwin

package exec

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/looprig/sandbox/pkg/profile"
)

// This suite lives with the executor rather than with the Seatbelt backend in
// internal/darwin. It constructs REAL executors and runs commands through
// /usr/bin/sandbox-exec, so it needs the executor — and internal/darwin cannot
// import the executor, because the platform selector already points the other
// way. The pure SBPL-generation tests stayed in internal/darwin.

// --- Real sandbox-exec enforcement ---
//
// These tests construct a REAL Seatbelt executor (newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
// is Seatbelt on darwin, once platformBackend() selects it) and actually run
// commands through /usr/bin/sandbox-exec, asserting the OS backend ENFORCES the
// generated SBPL. They are the answer to the reviewer's I2: the goldens only prove
// the generator emits byte-equal SBPL for the Go/RE2 glob translation; only a real
// exec proves SBPL's (older, different) engine matches the FILE rules the same way.
//
// They REQUIRE the darwin Seatbelt backend. Under the null backend (before
// platformBackend flips) the deny/boundary assertions FAIL by construction — null
// enforces nothing, so a "write outside ws" or "cat ~/.ssh" succeeds — which is the
// intended RED state proving the tests measure real enforcement, not passthrough.
//
// KEY macOS behaviour (SPEC §7.1): Seatbelt matches subpath/regex rules against the
// CANONICAL (symlink-resolved) path. macOS symlinks the very roots a policy names —
// /tmp→/Private/tmp, /etc→/Private/etc, /var→/Private/var (so t.TempDir workspaces
// under /var/folders resolve into /Private). The generator therefore canonicalizes
// every emitted FS path (compileSBPL → canonPath); these tests deliberately pass a
// RAW t.TempDir() (symlinked under /var/folders) and rely on the backend to resolve
// it — which is itself part of what they verify, alongside the $TMPDIR write row.

// requireSandboxExec capability-skips (with a recorded reason) when
// /usr/bin/sandbox-exec is absent or not runnable here (e.g. a CI that forbids
// nested sandboxing), so a locked-down environment yields a skip, not a false
// failure. These tests are meaningless without a working sandbox-exec.
func requireSandboxExec(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skipf("sandbox-exec not available: %v", err)
	}
	if err := exec.Command("/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true").Run(); err != nil {
		t.Skipf("sandbox-exec present but not runnable here: %v", err)
	}
}

// TestSeatbeltEnforceWriteBoundary proves an in-workspace
// write succeeds and lands; a write to a sibling dir that is neither the workspace
// nor /tmp is denied (nonzero exit, file not created). The deny only holds under
// real Seatbelt — under null the write would succeed.
func TestSeatbeltEnforceWriteBoundary(t *testing.T) {
	requireSandboxExec(t)
	// RAW t.TempDir() (symlinked under /var/folders → /Private/var). Passing it
	// straight to the effective-policy fixture proves the generator canonicalizes
	// the workspace: without canonPath the emitted (subpath "/var/…") never matches the kernel's /Private/…
	// resolution and even this in-workspace write would be denied.
	ws := t.TempDir()
	outside := t.TempDir() // a sibling temp dir: NOT ws, NOT /tmp
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}
	ctx := context.Background()

	// Write inside ws succeeds and the file lands.
	inside := filepath.Join(ws, "f")
	out, code, err := e.RunCommand(ctx, ws, "echo hi > "+inside)
	if err != nil {
		t.Fatalf("write inside ws: unexpected spawn err %v (out=%s)", err, out)
	}
	if code != 0 {
		t.Fatalf("write inside ws: exit %d, want 0 (out=%s)", code, out)
	}
	if b, rerr := os.ReadFile(inside); rerr != nil || !strings.Contains(string(b), "hi") {
		t.Errorf("write inside ws: file %s = %q err=%v, want to contain 'hi'", inside, b, rerr)
	}

	// Write to a sibling dir outside ws (and not /tmp) is denied: nonzero exit and no
	// file. This asserts the OS write boundary, which the null backend cannot provide.
	target := filepath.Join(outside, "f")
	out, code, err = e.RunCommand(ctx, ws, "echo hi > "+target)
	if err != nil {
		t.Fatalf("write outside ws: unexpected spawn err %v", err)
	}
	if code == 0 {
		t.Errorf("write outside ws: exit 0, want nonzero (denied). Requires the darwin Seatbelt backend; out=%s", out)
	}
	if _, serr := os.Stat(target); serr == nil {
		t.Errorf("write outside ws: file %s exists, want denied/not created", target)
	}
}

// TestSeatbeltEnforceTmpWrite is the $TMPDIR-write payoff of the path-canonicalize
// fix. §5.5/decision 1 forces TMPDIR=/tmp, and write mode grants write to /tmp. On
// macOS /tmp is a symlink to /Private/tmp, so the raw (subpath "/tmp") grant matched
// NOTHING — every $TMPDIR write was DENIED, making the Seatbelt backend unusable for
// tools that write to their temp dir. With canonPath the grant is (subpath
// "/Private/tmp") and the write succeeds. This test FAILS without the fix.
func TestSeatbeltEnforceTmpWrite(t *testing.T) {
	requireSandboxExec(t)
	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}

	name := fmt.Sprintf("lrsb-tmpwrite-%d", time.Now().UnixNano())
	target := filepath.Join("/tmp", name)
	t.Cleanup(func() {
		os.Remove(target)
		os.Remove(filepath.Join("/Private/tmp", name))
	})

	// The child's TMPDIR is the forced /tmp; write through $TMPDIR as a real tool would.
	out, code, err := e.RunCommand(context.Background(), ws, `echo hi > "$TMPDIR/`+name+`"`)
	if err != nil {
		t.Fatalf("$TMPDIR write: spawn err %v (out=%s)", err, out)
	}
	if code != 0 {
		t.Errorf("$TMPDIR (/tmp) write: exit %d, want 0 (grant must canonicalize to /Private/tmp); out=%s", code, out)
	}
	if _, serr := os.Stat(target); serr != nil {
		t.Errorf("$TMPDIR write: %s not created (%v); the /tmp grant did not enforce as /Private/tmp", target, serr)
	}
}

// TestSeatbeltEnforceNullDevice proves Confined commands can open /dev/null
// read-write. Git does this during startup even for read-only commands such as
// `git status`; denying the null device therefore makes an otherwise available
// tool fail before it can inspect the repository.
func TestSeatbeltEnforceNullDevice(t *testing.T) {
	requireSandboxExec(t)
	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}

	out, code, err := e.RunCommand(context.Background(), ws, "exec 3<>/dev/null")
	if err != nil {
		t.Fatalf("open /dev/null read-write: spawn err %v (out=%s)", err, out)
	}
	if code != 0 {
		t.Errorf("open /dev/null read-write: exit %d, want 0; out=%s", code, out)
	}
}

// TestSeatbeltEnforceGitCarveout proves a sandboxed write
// into ws/.git is DENIED while a sandboxed read of an existing ws/.git file is
// ALLOWED. This verifies the read-allow + write-deny-LAST ordering enforces under
// real SBPL last-match-wins, not just in byte-equal goldens.
func TestSeatbeltEnforceGitCarveout(t *testing.T) {
	requireSandboxExec(t)
	ws := t.TempDir()
	// As the test (unsandboxed) set up .git with an existing file to read back.
	if err := os.MkdirAll(filepath.Join(ws, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(ws, ".git", "config")
	if err := os.WriteFile(cfg, []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}
	ctx := context.Background()

	// Write into .git is denied (carveout write-deny after the ws write allow wins).
	x := filepath.Join(ws, ".git", "x")
	out, code, err := e.RunCommand(ctx, ws, "echo hi > "+x)
	if err != nil {
		t.Fatalf(".git write: spawn err %v", err)
	}
	if code == 0 {
		t.Errorf(".git write: exit 0, want nonzero (carveout denies write); out=%s", out)
	}
	if _, serr := os.Stat(x); serr == nil {
		t.Errorf(".git write: %s created, want denied", x)
	}

	// Read from .git is allowed: the carveout removes write only, not read.
	out, code, err = e.RunCommand(ctx, ws, "cat "+cfg)
	if err != nil {
		t.Fatalf(".git read: spawn err %v", err)
	}
	if code != 0 {
		t.Errorf(".git read: exit %d, want 0 (read allowed); out=%s", code, out)
	}
	if !strings.Contains(string(out), "[core]") {
		t.Errorf(".git read: out=%q, want the file contents", out)
	}
}

// TestSeatbeltEnforceSSHDeny proves a sandboxed read of a file
// under $HOME/.ssh is DENIED. HOME is set to a temp home BEFORE NewExecutor so
// defaultSecretDenials compiles that home's ~/.ssh (subpath) deny into the profile.
// Verifies the §5.3 (subpath …) secret deny enforces under real SBPL.
func TestSeatbeltEnforceSSHDeny(t *testing.T) {
	requireSandboxExec(t)
	home := t.TempDir()
	t.Setenv("HOME", home) // BEFORE newExecutor: anchors ~/.ssh secret deny under this home
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(home, ".ssh", "id")
	if err := os.WriteFile(secret, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}

	out, code, err := e.RunCommand(context.Background(), ws, "cat "+secret)
	if err != nil {
		t.Fatalf("~/.ssh read: spawn err %v", err)
	}
	if code == 0 {
		t.Errorf("~/.ssh read: exit 0, want nonzero (secret deny); out=%s", out)
	}
	if strings.Contains(string(out), "PRIVATE KEY") {
		t.Errorf("~/.ssh read leaked the secret: %s", out)
	}
}

// TestSeatbeltEnforceCarveoutNotPreCreated guards the C1 fail-open: a .git/.looprig
// carveout whose target does NOT exist at NewExecutor (compile) time. On an ephemeral
// /var/folders workspace (symlinked into /Private), a raw-Clean canonPath left the
// carveout write-deny UNRESOLVED so it never matched the kernel's resolved path — the
// write fell through to the workspace ALLOW (fail OPEN, .git/.looprig writable). The
// deepest-existing-Ancestor resolution fixes it. The carveout dir is created AFTER
// compile (so the write itself would succeed if not for the deny), which is exactly
// the compile-time-nonexistent / runtime-existent case the old code got wrong.
func TestSeatbeltEnforceCarveoutNotPreCreated(t *testing.T) {
	requireSandboxExec(t)
	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws)) // .looprig does NOT exist yet
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}
	// Create the carveout dir only now (post-compile) so a plain write would land.
	if err := os.MkdirAll(filepath.Join(ws, ".looprig"), 0o755); err != nil {
		t.Fatal(err)
	}
	x := filepath.Join(ws, ".looprig", "x")
	out, code, err := e.RunCommand(context.Background(), ws, "echo hi > "+x)
	if err != nil {
		t.Fatalf(".looprig write: spawn err %v", err)
	}
	if code == 0 {
		t.Errorf(".looprig write: exit 0, want nonzero — carveout deny must hold even though .looprig did not exist at compile time (fail-open regression); out=%s", out)
	}
	if _, serr := os.Stat(x); serr == nil {
		t.Errorf(".looprig write: %s created, want denied (fail-open regression)", x)
	}
}

// TestSeatbeltEnforceSecretDenyCreatedAfter guards the same C1 fail-open on the
// secret-deny side: under a symlinked temp HOME, ~/.ssh does not exist at compile
// time and the secret is created only afterward. The §5.3 secret deny must still fire.
func TestSeatbeltEnforceSecretDenyCreatedAfter(t *testing.T) {
	requireSandboxExec(t)
	home := t.TempDir()
	t.Setenv("HOME", home) // BEFORE NewExecutor; ~/.ssh does NOT exist yet
	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}
	// Create the secret only now (post-compile), under the symlinked home.
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(home, ".ssh", "id")
	if err := os.WriteFile(secret, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code, err := e.RunCommand(context.Background(), ws, "cat "+secret)
	if err != nil {
		t.Fatalf("secret read: spawn err %v", err)
	}
	if code == 0 || strings.Contains(string(out), "PRIVATE KEY") {
		t.Errorf("secret created after compile was readable (fail-open regression): code=%d out=%s", code, out)
	}
}

// TestSeatbeltEnforceEnvGlobDeny proves that
// a sandboxed read of ws/.env is DENIED — showing the (regex #"^.*/\.env[^/]*$")
// deny actually MATCHES under SBPL's regex engine, not merely byte-equal to Go's
// RE2 translation — while ws/notenv (ends in "env" but has no leading dot) is
// READABLE, proving the glob does not over-match.
func TestSeatbeltEnforceEnvGlobDeny(t *testing.T) {
	requireSandboxExec(t)
	ws := t.TempDir()
	envFile := filepath.Join(ws, ".env")
	if err := os.WriteFile(envFile, []byte("TOKEN=secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	notEnv := filepath.Join(ws, "notenv")
	if err := os.WriteFile(notEnv, []byte("visible"), 0o644); err != nil {
		t.Fatal(err)
	}

	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}
	ctx := context.Background()

	// ws/.env read is denied: the regex deny MATCHES under SBPL's engine (I2 proof).
	out, code, err := e.RunCommand(ctx, ws, "cat "+envFile)
	if err != nil {
		t.Fatalf(".env read: spawn err %v", err)
	}
	if code == 0 {
		t.Errorf(".env read: exit 0, want nonzero (regex secret deny must MATCH); out=%s", out)
	}
	if strings.Contains(string(out), "secret") {
		t.Errorf(".env read leaked: %s", out)
	}

	// ws/notenv read is allowed: the glob must not over-match a name lacking the
	// leading dot (real-exec confirmation the regex is anchored to /\.env).
	out, code, err = e.RunCommand(ctx, ws, "cat "+notEnv)
	if err != nil {
		t.Fatalf("notenv read: spawn err %v", err)
	}
	if code != 0 {
		t.Errorf("notenv read: exit %d, want 0 (glob must not over-match); out=%s", code, out)
	}
	if !strings.Contains(string(out), "visible") {
		t.Errorf("notenv read: out=%q, want the file contents", out)
	}
}

// TestSeatbeltEnforceNetworkBlocked proves that under a network-denied policy
// (Net zero → default-deny egress) a sandboxed connect to a LIVE Loopback listener
// is blocked. A control dial from the test process (unsandboxed) succeeds first, so
// a sandboxed failure is attributable to enforcement, not a dead port.
func TestSeatbeltEnforceNetworkBlocked(t *testing.T) {
	requireSandboxExec(t)
	if _, err := os.Stat("/usr/bin/nc"); err != nil {
		t.Skip("/usr/bin/nc not available for the connect probe")
	}
	ws := t.TempDir()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	// Control: an unsandboxed connect to the live port succeeds.
	c, derr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if derr != nil {
		t.Fatalf("control dial to live port failed: %v", derr)
	}
	_ = c.Close()

	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if err != nil {
		t.Fatalf("newExecutor: %v", err)
	}

	// profile.Sandboxed connect probe is denied: nc -z exits nonzero when connect is blocked.
	out, code, err := e.RunCommand(context.Background(), ws, fmt.Sprintf("/usr/bin/nc -z -w1 127.0.0.1 %d", port))
	if err != nil {
		t.Fatalf("nc probe: spawn err %v", err)
	}
	if code == 0 {
		t.Errorf("sandboxed connect: exit 0, want nonzero (egress denied under write); out=%s", out)
	}
}

// TestSeatbeltEnforceLevelAndGuarantees asserts the compiled posture of the REAL
// Seatbelt executor: a writable sandboxed profile reaches LevelFull and
// its profile.Guarantees carry WriteBoundary, ReadBoundary, EnvScrub, and NetworkBoundary,
// with AddressNetwork false (SBPL cannot address-scope, §7.1/M1). This inspects the
// compiled backend metadata, so it needs the darwin backend selected but does not
// itself spawn sandbox-exec.
func TestSeatbeltEnforceLevelAndGuarantees(t *testing.T) {
	ws := t.TempDir()
	profile := mustProfile(t, profile.ProfileConfig{
		WorkspaceRoot: ws, WorkspaceRead: profile.Allow, WorkspaceWrite: profile.Allow,
		HostRead: profile.Deny, HostWrite: profile.Deny, Network: profile.Deny, Command: profile.Allow,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	e, err := set.For("guarantees")
	if err != nil {
		t.Fatalf("ExecutorSet.For: %v", err)
	}
	if e.Level() != LevelFull {
		t.Errorf("real Seatbelt Write Level() = %d, want LevelFull (%d)", e.Level(), LevelFull)
	}
	g := e.Guarantees()
	if !(g.WriteBoundary && g.ReadBoundary && g.EnvScrub && g.NetworkBoundary) {
		t.Errorf("Guarantees() = %+v, want WriteBoundary && ReadBoundary && EnvScrub && NetworkBoundary all true", g)
	}
	if g.AddressNetwork {
		t.Error("Guarantees().AddressNetwork = true, want false (SBPL cannot address-scope)")
	}
}
