//go:build darwin

package sandbox

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
	t.Setenv("HOME", "/home/tester")
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
	t.Setenv("HOME", "/home/tester")
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
	t.Setenv("HOME", "/home/tester")
	profile, _, _, _ := compileSBPL(PolicyFor(Write, "/ws"))

	broadRead := `(allow file-read* (subpath "/"))`
	sshDeny := `(deny file-read* file-write* (subpath "/home/tester/.ssh"))`

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
	t.Setenv("HOME", "/home/tester")
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
	t.Setenv("HOME", "/home/tester")
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
	t.Setenv("HOME", "/home/tester")
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
	t.Setenv("HOME", "/home/tester")
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
	t.Setenv("HOME", "/home/tester")
	profile, _, _, _ := compileSBPL(PolicyFor(Unconfined, "/ws"))
	if !strings.Contains(profile, "(allow network*)") {
		t.Errorf("Unconfined (Net.Open) profile missing (allow network*)\n%s", profile)
	}
}

// TestCompileSBPLLevels asserts the Full/Degraded split: a policy whose network
// needs no address-scoping is Full; requesting Private (unsatisfiable
// AddressNetwork) tops out at Degraded.
func TestCompileSBPLLevels(t *testing.T) {
	t.Setenv("HOME", "/home/tester")

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
	t.Setenv("HOME", "/home/tester")
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
	t.Setenv("HOME", "/home/tester")

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
	t.Setenv("HOME", "/home/tester")
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

// TestSeatbeltBackendSpawnSpec asserts the backend wraps commands and argv with
// sandbox-exec -p <profile> -- , sets no configure hook, and returns the same
// level/bits as compileSBPL.
func TestSeatbeltBackendSpawnSpec(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
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
