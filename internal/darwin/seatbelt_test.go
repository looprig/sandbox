//go:build darwin

package darwin

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
)

// TestCompileSBPLBase asserts the base of every profile: (version 1) then
// (deny default), so the sandbox is fail-closed before any allow.
func TestCompileSBPLBase(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, _, _, _ := compileSBPL(backendFixturePolicy(fixtureWorkspaceWrite, "/ws"))
	if !strings.HasPrefix(profile, "(version 1)\n(deny default)\n") {
		t.Errorf("profile does not begin with (version 1) then (deny default):\n%s", profile)
	}
	if !strings.Contains(profile, "(deny default)") {
		t.Error("profile missing (deny default)")
	}
}

// TestCompileSBPLXcrunCachePlumbing asserts every profile carries the fixed,
// backend-controlled xcrun/git tool-path cache allow (compileXcrunCachePlumbing),
// in both the /private/var/folders and /var/folders spellings, reports it via
// CompileReport for honesty, and that the resulting profile still parses under
// the real SBPL compiler.
func TestCompileSBPLXcrunCachePlumbing(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, report, _, _ := compileSBPL(backendFixturePolicy(fixtureWorkspaceWrite, "/ws"))
	for _, want := range []string{
		`(allow file-read* file-write* (regex #"^/private/var/folders/[^/]+/[^/]+/T/xcrun_db[^/]*$"))`,
		`(allow file-read* file-write* (regex #"^/var/folders/[^/]+/[^/]+/T/xcrun_db[^/]*$"))`,
	} {
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing xcrun-cache allow %q:\n%s", want, profile)
		}
	}
	if !hasReport(report, "xcrun-cache", "widened") {
		t.Errorf("report missing xcrun-cache/widened entry: %+v", report.Entries)
	}
	sandboxExecParses(t, profile)
}

// TestCompileSBPLPTYSlaveIoctl asserts every profile carries the fixed
// PTY-slave ioctl allow (compilePTYSlaveIoctl) scoped to exactly the
// /dev/ttysNNN device family, reports it via CompileReport for honesty, and
// that the resulting profile still parses under the real SBPL compiler. This
// is the fast unit-level pin for the rule that unblocks `stty size` and
// other controlling-terminal ioctls under real Seatbelt confinement
// (TestIntegrationProcessPTYLifecycle, internal/exec — the heavier
// -tags integration real-sandbox-exec path) — this test exists so an
// accidental broadening (e.g. a loosened regex) or accidental deletion of
// this security-relevant rule is caught at the fast unit-test tier too, not
// only by the integration suite.
func TestCompileSBPLPTYSlaveIoctl(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, report, _, _ := compileSBPL(backendFixturePolicy(fixtureWorkspaceWrite, "/ws"))
	want := `(allow file-ioctl (regex #"^/dev/ttys[0-9]+$"))`
	if !strings.Contains(profile, want) {
		t.Errorf("profile missing PTY-slave ioctl allow %q:\n%s", want, profile)
	}
	if !hasReport(report, "pty-slave-ioctl", "widened") {
		t.Errorf("report missing pty-slave-ioctl/widened entry: %+v", report.Entries)
	}
	sandboxExecParses(t, profile)
}

// TestCompileSBPLSecretDenyAfterBroadRead asserts the last-match-wins ordering:
// the §5.3 secret deny for ~/.ssh is emitted AFTER the broad file-read* allow, so
// the deny overrides the allow under SBPL's last-match-wins precedence.
func TestCompileSBPLSecretDenyAfterBroadRead(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, _, _, _ := compileSBPL(backendFixturePolicy(fixtureWorkspaceWrite, "/ws"))

	broadRead := `(allow file-read* (subpath "/"))`
	sshDeny := `(deny file-read* (subpath "/lrsbx-home/tester/.ssh"))`

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
// denies each filesystem axis independently.
func TestCompileSBPLEnvGlobDeny(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, _, _, _ := compileSBPL(backendFixturePolicy(fixtureWorkspaceWrite, "/ws"))

	wants := []string{
		`(deny file-read* (regex #"^.*/\.env[^/]*$"))`,
		`(deny process-exec (regex #"^.*/\.env[^/]*$"))`,
		`(deny file-write* (regex #"^.*/\.env[^/]*$"))`,
	}
	for _, want := range wants {
		if !strings.Contains(profile, want) {
			t.Errorf("profile missing translated **/.env* regex deny %q\n%s", want, profile)
		}
	}
}

// TestCompileSBPLCarveoutWriteDeny asserts the .git carveout: a read-only entry
// nested in the writable workspace root gets its write removed by a deny emitted
// AFTER the workspace write allow (so last-match-wins makes it read-only).
func TestCompileSBPLCarveoutWriteDeny(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, _, _, _ := compileSBPL(backendFixturePolicy(fixtureWorkspaceWrite, "/ws"))

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

// TestCompileSBPLNetworkBroadTarget asserts the M1-verified network mapping for
// a loopback + private + port 443 + DNS policy: a port rule, the
// localhost loopback rule, and the mDNSResponder unix-socket for DNS; Private is
// NOT emitted (SBPL cannot address-scope) but IS reported unenforced.
func TestCompileSBPLNetworkBroadTarget(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	profile, report, _, _ := compileSBPL(backendFixturePolicy(fixtureBroadNetwork, "/ws"))

	wantLines := []string{
		`(allow network-outbound (remote tcp "*:443"))`,
		`(allow network-outbound (remote ip "localhost:*"))`,
		`(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))`,
	}
	for _, w := range wantLines {
		if !strings.Contains(profile, w) {
			t.Errorf("network profile missing %q\n%s", w, profile)
		}
	}

	// Private must NOT be compiled to any positive rule.
	if strings.Contains(profile, "Private") || strings.Contains(profile, "10.0.0.0") || strings.Contains(profile, "rfc1918") {
		t.Errorf("network profile appears to emit a Private/address rule; SBPL cannot address-scope:\n%s", profile)
	}

	// ... but Private IS reported as unenforced (compile-to-blocked).
	if !hasReport(report, "address-network", "unenforced") {
		t.Errorf("network report missing address-network/unenforced entry for Private: %+v", report.Entries)
	}
	// Loopback widening (localhost matches host's own addresses) is noted.
	if !hasReportFeature(report, "loopback") {
		t.Errorf("network report missing loopback widening note: %+v", report.Entries)
	}
}

// TestCompileSBPLNetworkPorts asserts an arbitrary port compiles to the M1
// outbound-tcp form.
func TestCompileSBPLNetworkPorts(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	p := backendFixturePolicy(fixtureWorkspaceWrite, "/ws", fixtureWithNet(policy.NetPolicy{Ports: []uint16{443, 8080}}))
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
	profile, _, _, _ := compileSBPL(backendFixturePolicy(fixtureDirect, "/ws"))
	if !strings.Contains(profile, "(allow network*)") {
		t.Errorf("profile.Unconfined (Net.Open) profile missing (allow network*)\n%s", profile)
	}
}

// TestCompileSBPLLevels asserts the Full/Degraded split: a policy whose network
// needs no address-scoping is Full; requesting Private (unsatisfiable
// AddressNetwork) tops out at Degraded.
func TestCompileSBPLLevels(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")

	_, _, writeLevel, _ := compileSBPL(backendFixturePolicy(fixtureWorkspaceWrite, "/ws"))
	if writeLevel != profile.LevelFull {
		t.Errorf("Write level = %d, want profile.LevelFull (%d)", writeLevel, profile.LevelFull)
	}

	_, _, trustedLevel, _ := compileSBPL(backendFixturePolicy(fixtureBroadNetwork, "/ws"))
	if trustedLevel != profile.LevelDegraded {
		t.Errorf("broad-network level = %d, want profile.LevelDegraded (%d) because Private is unsatisfiable", trustedLevel, profile.LevelDegraded)
	}
}

// TestCompileSBPLLevelAndReportByPolicyShape asserts scoped reads are fully enforced;
// only the legacy fixture requesting unexpressible private-address access is
// degraded.
func TestCompileSBPLLevelAndReportByPolicyShape(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	cases := []struct {
		name             string
		shape            backendFixtureShape
		wantLevel        uint8
		wantRestrictRead bool // restricted-read + exec-scoping entries expected
	}{
		{"scoped runtime", fixtureScopedRuntime, profile.LevelFull, false},
		{"host read", fixtureHostRead, profile.LevelFull, false},
		{"workspace write", fixtureWorkspaceWrite, profile.LevelFull, false},
		{"broad network", fixtureBroadNetwork, profile.LevelDegraded, false},
		{"unconfined", fixtureDirect, profile.LevelFull, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, report, level, _ := compileSBPL(backendFixturePolicy(tc.shape, "/ws"))
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
		})
	}
}

// TestCompileSBPLGuarantees asserts the guarantee bitmask: AddressNetwork is
// always false (SBPL cannot address-scope); EnvScrub tracks !Env.Inherit; and the
// Write policy has the process/write/read/network boundaries.
func TestCompileSBPLGuarantees(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")

	_, _, _, writeBits := compileSBPL(backendFixturePolicy(fixtureWorkspaceWrite, "/ws"))
	if writeBits&profile.GuaranteeAddressNetwork != 0 {
		t.Error("Write AddressNetwork bit set; SBPL cannot address-scope, must always be false")
	}
	if writeBits&profile.GuaranteeEnvScrub == 0 {
		t.Error("Write EnvScrub bit clear; a non-Inherit policy scrubs env")
	}
	for _, want := range []struct {
		name string
		bit  uint64
	}{
		{"ProcessBoundary", profile.GuaranteeProcessBoundary},
		{"WriteBoundary", profile.GuaranteeWriteBoundary},
		{"NetworkBoundary", profile.GuaranteeNetworkBoundary},
	} {
		if writeBits&want.bit == 0 {
			t.Errorf("Write %s bit clear, want set", want.name)
		}
	}
	broadReadPolicy := backendFixturePolicy(fixtureHostRead, "/ws", fixtureWithoutSecretDenials())
	_, _, _, broadReadBits := compileSBPL(broadReadPolicy)
	if broadReadBits&profile.GuaranteeReadBoundary != 0 {
		t.Error("unrestricted root-read policy claimed ReadBoundary")
	}
	_, _, _, scopedBits := compileSBPL(backendFixturePolicy(fixtureScopedRuntime, "/ws"))
	if scopedBits&profile.GuaranteeReadBoundary == 0 {
		t.Error("scoped-read policy did not claim ReadBoundary")
	}
	if writeBits&profile.GuaranteeResourceLimits != 0 {
		t.Error("Write ResourceLimits bit set; darwin ulimit approximation is a later task, must be false")
	}

	// An Inherit policy (unconfined-style) does NOT scrub env.
	_, _, _, inheritBits := compileSBPL(policy.Effective{Workspace: "/ws", Env: policy.EnvPolicy{Inherit: true}})
	if inheritBits&profile.GuaranteeEnvScrub != 0 {
		t.Error("Inherit policy EnvScrub bit set; an inherited env is not scrubbed")
	}
	if inheritBits&profile.GuaranteeAddressNetwork != 0 {
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
	p := backendFixturePolicy(fixtureWorkspaceWrite, "/ws", fixtureWithoutSecretDenials(), fixtureWithDenyRead("/secret/data/[z-a]"))
	profile, report, _, _ := compileSBPL(p)

	broad := `(deny file-read* (subpath "/secret/data"))`
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
// malformed (unbalanced-delimiter) profile. Reachable via a consumer fixtureWithDenyRead
// of a quote-bearing path.
func TestCompileSBPLGlobDenyQuoteFailsClosed(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	p := backendFixturePolicy(fixtureWorkspaceWrite, "/ws", fixtureWithoutSecretDenials(), fixtureWithDenyRead(`/danger"x/*.env`))
	profile, report, _, _ := compileSBPL(p)

	wantDeny := `(deny file-read* (subpath "/danger\"x"))`
	if !strings.Contains(profile, wantDeny) {
		t.Errorf("quote-bearing deny glob not failed-closed to a conservative subpath deny %q\n%s", wantDeny, profile)
	}
	// No DENY regex literal should be emitted for this policy (secret denials
	// dropped, so the only deny is the quote glob → which must NOT be a #"..."
	// literal). ALLOW regex literals are expected regardless of this policy's
	// denies — see compileXcrunCachePlumbing's fixed, backend-controlled rules,
	// which are never derived from caller-supplied (and therefore possibly
	// quote-bearing) glob input.
	for _, denyRegex := range []string{
		`(deny file-read* (regex #"`,
		`(deny process-exec (regex #"`,
		`(deny file-write* (regex #"`,
	} {
		if strings.Contains(profile, denyRegex) {
			t.Errorf("profile emitted a deny regex literal for a quote-bearing glob (would be malformed):\n%s", profile)
		}
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
	p := backendFixturePolicy(fixtureWorkspaceWrite, "/ws")
	b := NewBackend()
	spec, report, level, bits, err := b.Compile(p)
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

	// Shell path: the executor shell-normalizes a command string to /bin/sh -c
	// (shellArgv) and hands that inner argv to the backend's wrap; dir is ignored.
	shell, shellCfg, shellClean := spec.Wrap("/work", enforce.ShellArgv("echo hi"))
	wantShell := []string{"/usr/bin/sandbox-exec", "-p", wantProfile, "--", "/bin/sh", "-c", "echo hi"}
	if !equalStrings(shell, wantShell) {
		t.Errorf("wrap(shell) = %v\nwant %v", shell, wantShell)
	}
	if shellCfg != nil {
		t.Error("seatbelt wrap configure should be nil (executor sets attributes)")
	}
	if shellClean != nil {
		t.Error("seatbelt wrap cleanup should be nil (no per-spawn resources)")
	}

	// Direct argv path (RunArgv): the backend wraps the caller's argv verbatim.
	argv, argvCfg, argvClean := spec.Wrap("/work", []string{"ls", "-l"})
	wantArgv := []string{"/usr/bin/sandbox-exec", "-p", wantProfile, "--", "ls", "-l"}
	if !equalStrings(argv, wantArgv) {
		t.Errorf("wrap(argv) = %v\nwant %v", argv, wantArgv)
	}
	if argvCfg != nil || argvClean != nil {
		t.Error("seatbelt wrap should return nil configure and nil cleanup")
	}
}

// hasReport reports whether the report has an entry with the given feature and
// status.
func hasReport(r profile.CompileReport, feature, status string) bool {
	for _, e := range r.Entries {
		if e.Feature == feature && e.Status == status {
			return true
		}
	}
	return false
}

// hasReportFeature reports whether the report has any entry with the given
// feature.
func hasReportFeature(r profile.CompileReport, feature string) bool {
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
