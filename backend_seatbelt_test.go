//go:build darwin

package sandbox

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// update rewrites the testdata/*.sbpl golden files from the current generator
// output when set: `go test -run TestCompileSBPLGolden -update`. Determinism for
// the goldens comes from a fixed workspace (/ws) and a fixed HOME (set via
// t.Setenv), so DefaultSecretDenials' ~ expansion is stable and the goldens hold
// no machine-specific paths.
var update = flag.Bool("update", false, "update .sbpl golden files")

// goldenModes is the mode → golden-file table. One SBPL profile is generated per
// mode and compared byte-for-byte against testdata/<name>.sbpl.
var goldenModes = []struct {
	name string
	mode Mode
}{
	{"zerotrust", ZeroTrust},
	{"readonly", ReadOnly},
	{"write", Write},
	{"trusted", Trusted},
	{"unconfined", Unconfined},
}

// TestCompileSBPLGolden pins the full generated profile per mode against a
// committed golden. With -update it (re)writes the goldens instead of asserting.
func TestCompileSBPLGolden(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	for _, tc := range goldenModes {
		t.Run(tc.name, func(t *testing.T) {
			profile, _, _, _ := compileSBPL(PolicyFor(tc.mode, "/ws"))
			golden := filepath.Join("testdata", tc.name+".sbpl")
			if *update {
				if err := os.MkdirAll("testdata", 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(golden, []byte(profile), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("read golden %s (run: go test -run TestCompileSBPLGolden -update): %v", golden, err)
			}
			if profile != string(want) {
				t.Errorf("profile for %s does not match golden %s\n--- got ---\n%s\n--- want ---\n%s",
					tc.name, golden, profile, want)
			}
		})
	}
}

// TestCompileSBPLBase asserts the base of every profile: (version 1) then
// (deny default), so the sandbox is fail-closed before any allow.
func TestCompileSBPLBase(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, _, _, _ := compileSBPL(PolicyFor(Write, "/ws"))
	if !strings.HasPrefix(profile, "(version 1)\n(deny default)\n") {
		t.Errorf("profile does not begin with (version 1) then (deny default):\n%s", profile)
	}
	if !strings.Contains(profile, "(deny default)") {
		t.Error("profile missing (deny default)")
	}
}

// TestCompileSBPLSecretDenyAfterBroadRead asserts the last-match-wins ordering:
// the §5.3 secret deny for ~/.ssh is emitted AFTER the broad file-read* allow, so
// the deny overrides the allow under SBPL's last-match-wins precedence.
func TestCompileSBPLSecretDenyAfterBroadRead(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, _, _, _ := compileSBPL(PolicyFor(Write, "/ws"))

	broadRead := `(allow file-read* (subpath "/"))`
	sshDeny := `(deny file-read* file-write* (subpath "/lrsbx-home/tester/.ssh"))`

	iAllow := strings.Index(profile, broadRead)
	iDeny := strings.Index(profile, sshDeny)
	if iAllow < 0 {
		t.Fatalf("profile missing broad read allow %q", broadRead)
	}
	if iDeny < 0 {
		t.Fatalf("profile missing ~/.ssh deny %q", sshDeny)
	}
	if iDeny < iAllow {
		t.Errorf("~/.ssh deny (idx %d) must come AFTER the broad read allow (idx %d) for last-match-wins", iDeny, iAllow)
	}
}

// TestCompileSBPLEnvGlobDeny asserts the **/.env* glob deny is translated to the
// expected anchored SBPL regex (matching fsresolve.go's glob→regexp), and that it
// denies both read and write.
func TestCompileSBPLEnvGlobDeny(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, _, _, _ := compileSBPL(PolicyFor(Write, "/ws"))

	want := `(deny file-read* file-write* (regex #"^.*/\.env[^/]*$"))`
	if !strings.Contains(profile, want) {
		t.Errorf("profile missing translated **/.env* regex deny %q\n%s", want, profile)
	}
}

// TestCompileSBPLCarveoutWriteDeny asserts the .git carveout: a read-only entry
// nested in the writable workspace root gets its write removed by a deny emitted
// AFTER the workspace write allow (so last-match-wins makes it read-only).
func TestCompileSBPLCarveoutWriteDeny(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, _, _, _ := compileSBPL(PolicyFor(Write, "/ws"))

	wsWrite := `(allow file-write* (subpath "/ws"))`
	gitDeny := `(deny file-write* (subpath "/ws/.git"))`

	iWrite := strings.Index(profile, wsWrite)
	iDeny := strings.Index(profile, gitDeny)
	if iWrite < 0 {
		t.Fatalf("profile missing workspace write allow %q", wsWrite)
	}
	if iDeny < 0 {
		t.Fatalf("profile missing .git carveout write deny %q", gitDeny)
	}
	if iDeny < iWrite {
		t.Errorf(".git write deny (idx %d) must come AFTER the workspace write allow (idx %d)", iDeny, iWrite)
	}
}

// TestCompileSBPLNetworkTrusted asserts the M1-verified network mapping for the
// Trusted policy (Loopback + Private + Ports{443} + DNS): a port rule, the
// localhost loopback rule, and the mDNSResponder unix-socket for DNS; Private is
// NOT emitted (SBPL cannot address-scope) but IS reported unenforced.
func TestCompileSBPLNetworkTrusted(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, report, _, _ := compileSBPL(PolicyFor(Trusted, "/ws"))

	wantLines := []string{
		`(allow network-outbound (remote tcp "*:443"))`,
		`(allow network-outbound (remote ip "localhost:*"))`,
		`(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))`,
	}
	for _, w := range wantLines {
		if !strings.Contains(profile, w) {
			t.Errorf("Trusted profile missing %q\n%s", w, profile)
		}
	}

	// Private must NOT be compiled to any positive rule.
	if strings.Contains(profile, "Private") || strings.Contains(profile, "10.0.0.0") || strings.Contains(profile, "rfc1918") {
		t.Errorf("Trusted profile appears to emit a Private/address rule; SBPL cannot address-scope:\n%s", profile)
	}

	// ... but Private IS reported as unenforced (compile-to-blocked).
	if !hasReport(report, "address-network", "unenforced") {
		t.Errorf("Trusted report missing address-network/unenforced entry for Private: %+v", report.Entries)
	}
	// Loopback widening (localhost matches host's own addresses) is noted.
	if !hasReportFeature(report, "loopback") {
		t.Errorf("Trusted report missing loopback widening note: %+v", report.Entries)
	}
}

// TestCompileSBPLNetworkPorts asserts an arbitrary port compiles to the M1
// outbound-tcp form.
func TestCompileSBPLNetworkPorts(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	p := PolicyFor(Write, "/ws", WithNet(NetPolicy{Ports: []uint16{443, 8080}}))
	profile, _, _, _ := compileSBPL(p)
	for _, w := range []string{
		`(allow network-outbound (remote tcp "*:443"))`,
		`(allow network-outbound (remote tcp "*:8080"))`,
	} {
		if !strings.Contains(profile, w) {
			t.Errorf("profile missing port rule %q\n%s", w, profile)
		}
	}
}

// TestCompileSBPLNetworkOpen asserts Net.Open (unconfined) compiles to the
// blanket network allow.
func TestCompileSBPLNetworkOpen(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, _, _, _ := compileSBPL(PolicyFor(Unconfined, "/ws"))
	if !strings.Contains(profile, "(allow network*)") {
		t.Errorf("Unconfined (Net.Open) profile missing (allow network*)\n%s", profile)
	}
}

// TestCompileSBPLLevels asserts the Full/Degraded split: a policy whose network
// needs no address-scoping is Full; requesting Private (unsatisfiable
// AddressNetwork) tops out at Degraded.
func TestCompileSBPLLevels(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")

	_, _, writeLevel, _ := compileSBPL(PolicyFor(Write, "/ws"))
	if writeLevel != LevelFull {
		t.Errorf("Write level = %d, want LevelFull (%d)", writeLevel, LevelFull)
	}

	_, _, trustedLevel, _ := compileSBPL(PolicyFor(Trusted, "/ws"))
	if trustedLevel != LevelDegraded {
		t.Errorf("Trusted level = %d, want LevelDegraded (%d) because Private is unsatisfiable", trustedLevel, LevelDegraded)
	}
}

// TestCompileSBPLLevelAndReportPerMode asserts the §7.5 soundness fix per mode:
// the base preamble broad-allows reads/execs, so a restricted-read policy
// (zerotrust — no "/" grant) is compiled WIDER than intent and must be recorded
// (restricted-read + exec-scoping, both unenforced) AND demoted to Degraded.
// Policies that themselves grant broad root read/exec (readonly/write/trusted/
// unconfined) stay Full unless demoted for another reason (Trusted → Private),
// and never carry a restricted-read entry. This exercises level+report per mode,
// which the golden test deliberately discards.
func TestCompileSBPLLevelAndReportPerMode(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	cases := []struct {
		name             string
		mode             Mode
		wantLevel        uint8
		wantRestrictRead bool // restricted-read + exec-scoping entries expected
	}{
		{"zerotrust", ZeroTrust, LevelDegraded, true},
		{"readonly", ReadOnly, LevelFull, false},
		{"write", Write, LevelFull, false},
		{"trusted", Trusted, LevelDegraded, false}, // Degraded via Private, not restricted-read
		{"unconfined", Unconfined, LevelFull, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, report, level, _ := compileSBPL(PolicyFor(tc.mode, "/ws"))
			if level != tc.wantLevel {
				t.Errorf("%s level = %d, want %d (report %+v)", tc.name, level, tc.wantLevel, report.Entries)
			}
			gotRead := hasReportFeature(report, "restricted-read")
			gotExec := hasReportFeature(report, "exec-scoping")
			if gotRead != tc.wantRestrictRead {
				t.Errorf("%s restricted-read entry present = %v, want %v (report %+v)", tc.name, gotRead, tc.wantRestrictRead, report.Entries)
			}
			if gotExec != tc.wantRestrictRead {
				t.Errorf("%s exec-scoping entry present = %v, want %v (report %+v)", tc.name, gotExec, tc.wantRestrictRead, report.Entries)
			}
			if tc.wantRestrictRead {
				if !hasReport(report, "restricted-read", "unenforced") {
					t.Errorf("%s restricted-read entry not marked unenforced: %+v", tc.name, report.Entries)
				}
				if !hasReport(report, "exec-scoping", "unenforced") {
					t.Errorf("%s exec-scoping entry not marked unenforced: %+v", tc.name, report.Entries)
				}
			}
		})
	}
}

// TestCompileSBPLGuarantees asserts the guarantee bitmask: AddressNetwork is
// always false (SBPL cannot address-scope); EnvScrub tracks !Env.Inherit; and the
// Write policy has the process/write/read/network boundaries.
func TestCompileSBPLGuarantees(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")

	_, _, _, writeBits := compileSBPL(PolicyFor(Write, "/ws"))
	if writeBits&GuaranteeAddressNetwork != 0 {
		t.Error("Write AddressNetwork bit set; SBPL cannot address-scope, must always be false")
	}
	if writeBits&GuaranteeEnvScrub == 0 {
		t.Error("Write EnvScrub bit clear; a non-Inherit policy scrubs env")
	}
	for _, want := range []struct {
		name string
		bit  uint64
	}{
		{"ProcessBoundary", GuaranteeProcessBoundary},
		{"WriteBoundary", GuaranteeWriteBoundary},
		{"ReadDenies", GuaranteeReadDenies},
		{"NetworkBoundary", GuaranteeNetworkBoundary},
	} {
		if writeBits&want.bit == 0 {
			t.Errorf("Write %s bit clear, want set", want.name)
		}
	}
	if writeBits&GuaranteeResourceLimits != 0 {
		t.Error("Write ResourceLimits bit set; darwin ulimit approximation is a later task, must be false")
	}

	// An Inherit policy (unconfined-style) does NOT scrub env.
	_, _, _, inheritBits := compileSBPL(Policy{Workspace: "/ws", Env: EnvPolicy{Inherit: true}})
	if inheritBits&GuaranteeEnvScrub != 0 {
		t.Error("Inherit policy EnvScrub bit set; an inherited env is not scrubbed")
	}
	if inheritBits&GuaranteeAddressNetwork != 0 {
		t.Error("Inherit policy AddressNetwork bit set; must always be false")
	}
}

// TestCompileSBPLGlobDenyFailsClosed asserts an untranslatable deny glob is not
// skipped: it compiles to a broad conservative deny (fail closed, over-deny) and
// is recorded in the report.
func TestCompileSBPLGlobDenyFailsClosed(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	// "[z-a]" is a reversed range: a valid glob metacharacter run that cannot be
	// compiled to a regexp, so the translation fails and must fall back to a broad
	// deny rather than silently dropping the secret rule.
	p := PolicyFor(Write, "/ws", WithoutSecretDenials(), WithDenyRead("/secret/data/[z-a]"))
	profile, report, _, _ := compileSBPL(p)

	broad := `(deny file-read* file-write* (subpath "/secret/data"))`
	if !strings.Contains(profile, broad) {
		t.Errorf("untranslatable glob deny not failed-closed to a broad deny %q\n%s", broad, profile)
	}
	if len(report.Entries) == 0 {
		t.Error("untranslatable glob deny not recorded in the compile report")
	}
	var found bool
	for _, e := range report.Entries {
		if strings.Contains(e.Feature, "glob") {
			found = true
		}
	}
	if !found {
		t.Errorf("no glob-deny report entry for the fail-closed over-deny: %+v", report.Entries)
	}
}

// TestCompileSBPLGlobDenyQuoteFailsClosed asserts a deny glob whose translated
// regex would contain a double-quote — which an SBPL #"..." literal cannot
// represent — falls back to a conservative subpath deny rather than emitting a
// malformed (unbalanced-delimiter) profile. Reachable via a consumer WithDenyRead
// of a quote-bearing path.
func TestCompileSBPLGlobDenyQuoteFailsClosed(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	p := PolicyFor(Write, "/ws", WithoutSecretDenials(), WithDenyRead(`/danger"x/*.env`))
	profile, report, _, _ := compileSBPL(p)

	wantDeny := `(deny file-read* file-write* (subpath "/danger\"x"))`
	if !strings.Contains(profile, wantDeny) {
		t.Errorf("quote-bearing deny glob not failed-closed to a conservative subpath deny %q\n%s", wantDeny, profile)
	}
	// No regex literal at all should be emitted for this policy (secret denials
	// dropped, so the only deny is the quote glob → which must NOT be a #"..."
	// literal).
	if strings.Contains(profile, `#"`) {
		t.Errorf("profile emitted a regex literal for a quote-bearing glob (would be malformed):\n%s", profile)
	}
	var found bool
	for _, e := range report.Entries {
		if e.Feature == "glob-deny" && strings.Contains(e.Detail, "quote") {
			found = true
		}
	}
	if !found {
		t.Errorf("no glob-deny/quote report entry for the fail-closed widening: %+v", report.Entries)
	}
	// The generated profile must still parse under the real SBPL compiler.
	sandboxExecParses(t, profile)
}

// TestSeatbeltBackendSpawnSpec asserts the backend wraps commands and argv with
// sandbox-exec -p <profile> -- , sets no configure hook, and returns the same
// level/bits as compileSBPL.
func TestSeatbeltBackendSpawnSpec(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	p := PolicyFor(Write, "/ws")
	b := newSeatbeltBackend()
	spec, report, level, bits, err := b.compile(p)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	wantProfile, wantReport, wantLevel, wantBits := compileSBPL(p)
	if level != wantLevel {
		t.Errorf("backend level = %d, want %d", level, wantLevel)
	}
	if bits != wantBits {
		t.Errorf("backend bits = %d, want %d", bits, wantBits)
	}
	if len(report.Entries) != len(wantReport.Entries) {
		t.Errorf("backend report entries = %d, want %d", len(report.Entries), len(wantReport.Entries))
	}

	shell := spec.wrapShell("echo hi")
	wantShell := []string{"/usr/bin/sandbox-exec", "-p", wantProfile, "--", "/bin/sh", "-c", "echo hi"}
	if !equalStrings(shell, wantShell) {
		t.Errorf("wrapShell = %v\nwant %v", shell, wantShell)
	}

	argv := spec.wrapArgv([]string{"ls", "-l"})
	wantArgv := []string{"/usr/bin/sandbox-exec", "-p", wantProfile, "--", "ls", "-l"}
	if !equalStrings(argv, wantArgv) {
		t.Errorf("wrapArgv = %v\nwant %v", argv, wantArgv)
	}

	if spec.configure != nil {
		t.Error("seatbelt spawnSpec.configure should be nil (executor sets attributes)")
	}
}

// --- Task 8b: REAL sandbox-exec enforcement (SPEC §12.1 macOS write row) ---
//
// These tests construct a REAL Seatbelt executor (NewExecutor(PolicyFor(Write, ws))
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
// /tmp→/private/tmp, /etc→/private/etc, /var→/private/var (so t.TempDir workspaces
// under /var/folders resolve into /private). The generator therefore canonicalizes
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

// TestSeatbeltEnforceWriteBoundary is the §12.1 write-boundary row: an in-workspace
// write succeeds and lands; a write to a sibling dir that is neither the workspace
// nor /tmp is denied (nonzero exit, file not created). The deny only holds under
// real Seatbelt — under null the write would succeed.
func TestSeatbeltEnforceWriteBoundary(t *testing.T) {
	requireSandboxExec(t)
	// RAW t.TempDir() (symlinked under /var/folders → /private/var). Passing it
	// straight to PolicyFor proves the GENERATOR canonicalizes the workspace: without
	// canonPath the emitted (subpath "/var/…") never matches the kernel's /private/…
	// resolution and even this in-workspace write would be denied.
	ws := t.TempDir()
	outside := t.TempDir() // a sibling temp dir: NOT ws, NOT /tmp
	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
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
// macOS /tmp is a symlink to /private/tmp, so the raw (subpath "/tmp") grant matched
// NOTHING — every $TMPDIR write was DENIED, making the Seatbelt backend unusable for
// tools that write to their temp dir. With canonPath the grant is (subpath
// "/private/tmp") and the write succeeds. This test FAILS without the fix.
func TestSeatbeltEnforceTmpWrite(t *testing.T) {
	requireSandboxExec(t)
	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	name := fmt.Sprintf("lrsb-tmpwrite-%d", time.Now().UnixNano())
	target := filepath.Join("/tmp", name)
	t.Cleanup(func() {
		os.Remove(target)
		os.Remove(filepath.Join("/private/tmp", name))
	})

	// The child's TMPDIR is the forced /tmp; write through $TMPDIR as a real tool would.
	out, code, err := e.RunCommand(context.Background(), ws, `echo hi > "$TMPDIR/`+name+`"`)
	if err != nil {
		t.Fatalf("$TMPDIR write: spawn err %v (out=%s)", err, out)
	}
	if code != 0 {
		t.Errorf("$TMPDIR (/tmp) write: exit %d, want 0 (grant must canonicalize to /private/tmp); out=%s", code, out)
	}
	if _, serr := os.Stat(target); serr != nil {
		t.Errorf("$TMPDIR write: %s not created (%v); the /tmp grant did not enforce as /private/tmp", target, serr)
	}
}

// TestSeatbeltEnforceGitCarveout is the §12.1 .git carveout row: a sandboxed write
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

	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
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

// TestSeatbeltEnforceSSHDeny is the §12.1 ~/.ssh row: a sandboxed read of a file
// under $HOME/.ssh is DENIED. HOME is set to a temp home BEFORE NewExecutor so
// DefaultSecretDenials compiles that home's ~/.ssh (subpath) deny into the profile.
// Verifies the §5.3 (subpath …) secret deny enforces under real SBPL.
func TestSeatbeltEnforceSSHDeny(t *testing.T) {
	requireSandboxExec(t)
	home := t.TempDir()
	t.Setenv("HOME", home) // BEFORE NewExecutor: anchors ~/.ssh secret deny under this home
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(home, ".ssh", "id")
	if err := os.WriteFile(secret, []byte("PRIVATE KEY"), 0o600); err != nil {
		t.Fatal(err)
	}

	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
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
// /var/folders workspace (symlinked into /private), a raw-Clean canonPath left the
// carveout write-deny UNRESOLVED so it never matched the kernel's resolved path — the
// write fell through to the workspace ALLOW (fail OPEN, .git/.looprig writable). The
// deepest-existing-ancestor resolution fixes it. The carveout dir is created AFTER
// compile (so the write itself would succeed if not for the deny), which is exactly
// the compile-time-nonexistent / runtime-existent case the old code got wrong.
func TestSeatbeltEnforceCarveoutNotPreCreated(t *testing.T) {
	requireSandboxExec(t)
	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws)) // .looprig does NOT exist yet
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
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
	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
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

// TestSeatbeltEnforceEnvGlobDeny is the §12.1 .env row and the reviewer's I2 proof:
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

	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
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

// TestSeatbeltEnforceNetworkBlocked is the §12.1 network row: under write mode
// (Net zero → default-deny egress) a sandboxed connect to a LIVE loopback listener
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

	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	// Sandboxed connect probe is denied: nc -z exits nonzero when connect is blocked.
	out, code, err := e.RunCommand(context.Background(), ws, fmt.Sprintf("/usr/bin/nc -z -w1 127.0.0.1 %d", port))
	if err != nil {
		t.Fatalf("nc probe: spawn err %v", err)
	}
	if code == 0 {
		t.Errorf("sandboxed connect: exit 0, want nonzero (egress denied under write); out=%s", out)
	}
}

// TestSeatbeltEnforceLevelAndGuarantees asserts the compiled posture of the REAL
// Seatbelt executor (SPEC §12.1: Level = Full): Write mode reaches LevelFull and
// its Guarantees carry WriteBoundary, ReadDenies, EnvScrub, and NetworkBoundary,
// with AddressNetwork false (SBPL cannot address-scope, §7.1/M1). This inspects the
// compiled backend metadata, so it needs the darwin backend selected but does not
// itself spawn sandbox-exec.
func TestSeatbeltEnforceLevelAndGuarantees(t *testing.T) {
	ws := t.TempDir()
	e, err := NewExecutor(PolicyFor(Write, ws))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	if e.Level() != LevelFull {
		t.Errorf("real Seatbelt Write Level() = %d, want LevelFull (%d)", e.Level(), LevelFull)
	}
	g := e.Guarantees()
	if !(g.WriteBoundary && g.ReadDenies && g.EnvScrub && g.NetworkBoundary) {
		t.Errorf("Guarantees() = %+v, want WriteBoundary && ReadDenies && EnvScrub && NetworkBoundary all true", g)
	}
	if g.AddressNetwork {
		t.Error("Guarantees().AddressNetwork = true, want false (SBPL cannot address-scope)")
	}
}

// hasReport reports whether the report has an entry with the given feature and
// status.
func hasReport(r CompileReport, feature, status string) bool {
	for _, e := range r.Entries {
		if e.Feature == feature && e.Status == status {
			return true
		}
	}
	return false
}

// hasReportFeature reports whether the report has any entry with the given
// feature.
func hasReportFeature(r CompileReport, feature string) bool {
	for _, e := range r.Entries {
		if e.Feature == feature {
			return true
		}
	}
	return false
}

// equalStrings reports whether two string slices are element-wise equal.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// sandboxExecParses asserts the profile compiles under the real macOS SBPL
// parser via `sandbox-exec -f <profile> /usr/bin/true`. It first confirms
// sandbox-exec is present AND runnable in this environment with a known-good
// profile, skipping otherwise — so a locked-down environment yields a skip, not a
// false failure, while a genuinely malformed generated profile fails the test.
// (This is a targeted parse check; the full real-exec enforcement matrix is a
// separate follow-up.)
func sandboxExecParses(t *testing.T, profile string) {
	t.Helper()
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not available")
	}
	if rc := runSandboxExec(t, "(version 1)(allow default)\n"); rc != 0 {
		t.Skipf("sandbox-exec present but not runnable here (known-good profile exit %d)", rc)
	}
	if rc := runSandboxExec(t, profile); rc != 0 {
		t.Fatalf("generated profile did not parse under sandbox-exec (exit %d):\n%s", rc, profile)
	}
}

// runSandboxExec writes profile to a temp file and runs it under sandbox-exec,
// returning the process exit code (0 = compiled and ran /usr/bin/true).
func runSandboxExec(t *testing.T, profile string) int {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "*.sbpl")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(profile); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	err = exec.Command("/usr/bin/sandbox-exec", "-f", f.Name(), "/usr/bin/true").Run()
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	t.Fatalf("running sandbox-exec: %v", err)
	return -1
}
