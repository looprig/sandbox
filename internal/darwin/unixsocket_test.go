//go:build darwin

package darwin

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
)

// The AF_UNIX contract (profile.UnixSocketPolicy) on Seatbelt. Measured with
// sandbox-exec on macOS 26 before any rule was written (the probes are
// recorded on compileUnixSockets): under (deny default) socket(AF_UNIX) and
// socketpair() succeed, but connect(2) to a pathname socket needs
// network-outbound (remote unix-socket ...) and bind(2) needs network-bind
// (local unix-socket ...) PLUS file-write-create on the socket file, and every
// unix-socket path filter matches only the fully symlink-resolved spelling
// (/private/tmp/..., never /tmp/...). (allow network*) — what Net.Open
// compiles to — admits every pathname socket on the host.

func unixSocketPolicy(t *testing.T, ws string, sockets profile.UnixSocketPolicy) policy.Effective {
	t.Helper()
	p := backendFixturePolicy(fixtureWorkspaceWrite, ws, fixtureWithoutSecretDenials())
	p.Isolation = profile.Sandboxed
	p.UnixSockets = sockets
	return p
}

func unixSocketLines(sbpl string) []string {
	var lines []string
	for _, line := range strings.Split(sbpl, "\n") {
		if strings.Contains(line, "unix-socket") {
			lines = append(lines, line)
		}
	}
	return lines
}

// TestCompileSBPLUnixSocketsDefaultDenied: the zero policy emits no
// unix-socket rule at all (the base (deny default) denies connect and bind)
// and keeps ProcessBoundary at LevelFull.
func TestCompileSBPLUnixSocketsDefaultDenied(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	sbpl, report, level, bits := compileSBPL(unixSocketPolicy(t, "/ws", profile.UnixSocketPolicy{}))
	if lines := unixSocketLines(sbpl); len(lines) != 0 {
		t.Fatalf("default policy emitted unix-socket rules %q", lines)
	}
	if hasReportFeature(report, "unix-sockets") || hasReportFeature(report, "unix-sockets.dangerous") {
		t.Fatalf("default policy reported a unix-socket posture: %+v", report.Entries)
	}
	if level != profile.LevelFull || bits&profile.GuaranteeProcessBoundary == 0 {
		t.Fatalf("default policy level %d bits %#b, want LevelFull with ProcessBoundary", level, bits)
	}
}

// TestCompileSBPLUnixSocketsLocalGolden pins Local mode's exact rules: one
// outbound and one bind rule per spelling of every writable, non-exact root
// — here the workspace and the fixture's shared /tmp, each canonicalized to
// /private/... with its public alias kept — and nothing for read-only roots,
// the exact /dev/null entry or the .git/.looprig carveouts.
func TestCompileSBPLUnixSocketsLocalGolden(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	sbpl, report, level, bits := compileSBPL(unixSocketPolicy(t, "/ws", profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal}))
	want := []string{
		`(allow network-outbound (remote unix-socket (subpath "/ws")))`,
		`(allow network-bind (local unix-socket (subpath "/ws")))`,
		`(allow network-outbound (remote unix-socket (subpath "/private/tmp")))`,
		`(allow network-bind (local unix-socket (subpath "/private/tmp")))`,
		`(allow network-outbound (remote unix-socket (subpath "/tmp")))`,
		`(allow network-bind (local unix-socket (subpath "/tmp")))`,
	}
	if got := unixSocketLines(sbpl); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Local unix-socket rules =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !hasReport(report, "unix-sockets", "enforced") {
		t.Fatalf("Local mode not reported enforced: %+v", report.Entries)
	}
	if level != profile.LevelFull || bits&profile.GuaranteeProcessBoundary == 0 {
		t.Fatalf("Local mode level %d bits %#b, want LevelFull with ProcessBoundary", level, bits)
	}
	sandboxExecParses(t, sbpl)
}

// TestCompileSBPLUnixSocketsPathsGolden pins Paths mode: one exact
// path-literal outbound rule per spelling, the existing prefix canonicalized
// (a socket under a t.TempDir is under /var/folders, which Seatbelt sees as
// /private/var/folders), no bind rule, and a per-path report entry.
func TestCompileSBPLUnixSocketsPathsGolden(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	dir := t.TempDir() // /var/folders/... (public spelling)
	socket := filepath.Join(dir, "agent.sock")
	canonicalDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	sbpl, report, level, bits := compileSBPL(unixSocketPolicy(t, "/ws", profile.UnixSocketPolicy{Paths: []string{socket}}))
	want := []string{
		`(allow network-outbound (remote unix-socket (path-literal "` + filepath.Join(canonicalDir, "agent.sock") + `")))`,
		`(allow network-outbound (remote unix-socket (path-literal "` + socket + `")))`,
	}
	if got := unixSocketLines(sbpl); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Paths unix-socket rules =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	var found bool
	for _, entry := range report.Entries {
		if entry.Feature == "unix-sockets" && entry.Status == "enforced" && strings.Contains(entry.Detail, socket) {
			found = true
		}
	}
	if !found {
		t.Fatalf("Paths mode missing a per-path enforced entry naming %s: %+v", socket, report.Entries)
	}
	if level != profile.LevelFull || bits&profile.GuaranteeProcessBoundary == 0 {
		t.Fatalf("benign Paths level %d bits %#b, want LevelFull with ProcessBoundary", level, bits)
	}
	sandboxExecParses(t, sbpl)
}

// TestCompileSBPLUnixSocketsLeafSymlinkFailsClosed: Seatbelt matches the
// resolved endpoint, and the backend deliberately does not follow a symlinked
// LEAF (profile.UnixSocketPolicy's contract: a symlinked socket path fails
// closed), so the rule names the link itself and the report says so.
func TestCompileSBPLUnixSocketsLeafSymlinkFailsClosed(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	dir := t.TempDir()
	target := filepath.Join(dir, "real.sock")
	link := filepath.Join(dir, "link.sock")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	sbpl, report, _, _ := compileSBPL(unixSocketPolicy(t, "/ws", profile.UnixSocketPolicy{Paths: []string{link}}))
	if strings.Contains(sbpl, "real.sock") {
		t.Fatalf("a symlinked socket leaf was followed to its target:\n%s", strings.Join(unixSocketLines(sbpl), "\n"))
	}
	var noted bool
	for _, entry := range report.Entries {
		if entry.Feature == "unix-sockets" && strings.Contains(entry.Detail, "symlink") {
			noted = true
		}
	}
	if !noted {
		t.Fatalf("symlinked socket leaf not reported: %+v", report.Entries)
	}
}

// TestCompileSBPLUnixSocketsDangerousPathWithholdsProcessBoundary: naming a
// same-user broker socket (profile.DangerousUnixSocket — the docker socket
// here) is a trust decision about that daemon, so the backend flags it,
// withholds ProcessBoundary and tops out at LevelDegraded, while still
// emitting the grant the caller explicitly asked for.
func TestCompileSBPLUnixSocketsDangerousPathWithholdsProcessBoundary(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	sbpl, report, level, bits := compileSBPL(unixSocketPolicy(t, "/ws", profile.UnixSocketPolicy{Paths: []string{"/var/run/docker.sock"}}))
	if !strings.Contains(sbpl, `(path-literal "/var/run/docker.sock")`) {
		t.Fatalf("dangerous path grant not emitted:\n%s", strings.Join(unixSocketLines(sbpl), "\n"))
	}
	if !hasReport(report, "unix-sockets.dangerous", "narrowed") {
		t.Fatalf("dangerous path not flagged: %+v", report.Entries)
	}
	if bits&profile.GuaranteeProcessBoundary != 0 {
		t.Fatal("ProcessBoundary claimed with a container-daemon socket granted")
	}
	if level != profile.LevelDegraded {
		t.Fatalf("level = %d, want LevelDegraded", level)
	}
	// Positive control: the other guarantees are untouched.
	if bits&profile.GuaranteeWriteBoundary == 0 || bits&profile.GuaranteeNetworkBoundary == 0 {
		t.Fatalf("unrelated guarantees dropped: %#b", bits)
	}
}

// TestCompileSBPLUnixSocketsDarwinBrokerIsDangerous covers the macOS
// container-daemon sockets the cross-platform list (Linux-shaped) does not
// name: Docker Desktop's per-user socket is the macOS docker.sock.
func TestCompileSBPLUnixSocketsDarwinBrokerIsDangerous(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	for _, socket := range []string{
		"/Users/someone/.docker/run/docker.sock",
		"/Users/someone/.colima/default/docker.sock",
		"/Users/someone/.orbstack/run/docker.sock",
		"/Users/someone/.rd/docker.sock",
	} {
		_, report, level, bits := compileSBPL(unixSocketPolicy(t, "/ws", profile.UnixSocketPolicy{Paths: []string{socket}}))
		if !hasReport(report, "unix-sockets.dangerous", "narrowed") || bits&profile.GuaranteeProcessBoundary != 0 || level != profile.LevelDegraded {
			t.Errorf("%s: dangerous=%v ProcessBoundary=%v level=%d", socket, hasReport(report, "unix-sockets.dangerous", "narrowed"), bits&profile.GuaranteeProcessBoundary != 0, level)
		}
	}
}

// TestCompileSBPLUnixSocketsLocalWithWritableHostRootIsDangerous: Local mode
// admits sockets beneath every writable root, and a host-writable profile's
// writable root is "/", which reaches every broker socket on the machine.
func TestCompileSBPLUnixSocketsLocalWithWritableHostRootIsDangerous(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	p := unixSocketPolicy(t, "/ws", profile.UnixSocketPolicy{Mode: profile.UnixSocketsLocal})
	p.FS = append(p.FS, policy.FSEntry{Path: "/", Access: policy.ReadAccess | policy.WriteAccess | policy.ExecAccess})
	_, report, level, bits := compileSBPL(p)
	if !hasReport(report, "unix-sockets.dangerous", "narrowed") || bits&profile.GuaranteeProcessBoundary != 0 || level != profile.LevelDegraded {
		t.Fatalf("Local with writable / : report %+v level %d bits %#b", report.Entries, level, bits)
	}
}

// TestCompileSBPLNetworkOpenStillDeniesUnixSockets: Net.Open on a sandboxed
// profile compiles to (allow network*), which on its own admits every
// pathname socket — the very AF_UNIX authority the profile's default denies.
// The unix-socket operations are re-denied after it, with the DNS socket
// re-admitted (name resolution goes through it), and the policy's own
// unix-socket grants re-admitted after that.
func TestCompileSBPLNetworkOpenStillDeniesUnixSockets(t *testing.T) {
	t.Setenv("HOME", "/lrsbx-home/tester")
	p := unixSocketPolicy(t, "/ws", profile.UnixSocketPolicy{})
	p.Net = policy.NetPolicy{Open: true}
	sbpl, report, _, bits := compileSBPL(p)
	want := []string{
		`(deny network-outbound (remote unix-socket))`,
		`(deny network-bind (local unix-socket))`,
		`(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))`,
	}
	if got := unixSocketLines(sbpl); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("Open unix-socket rules =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if strings.Index(sbpl, "(allow network*)") > strings.Index(sbpl, want[0]) {
		t.Fatal("unix-socket deny must follow (allow network*) under last-match-wins")
	}
	if !hasReport(report, "unix-sockets", "enforced") || bits&profile.GuaranteeProcessBoundary == 0 {
		t.Fatalf("Open sandboxed profile: report %+v bits %#b", report.Entries, bits)
	}
	sandboxExecParses(t, sbpl)

	// An Unconfined profile never reaches Seatbelt in production; if it is
	// compiled anyway it keeps the blanket network allow untouched.
	direct, _, _, _ := compileSBPL(backendFixturePolicy(fixtureDirect, "/ws"))
	if lines := unixSocketLines(direct); len(lines) != 0 {
		t.Fatalf("Unconfined profile gained unix-socket rules %q", lines)
	}
}
