//go:build darwin

package darwin

import (
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeatbeltProfileUsesScopedRuntimeReadExecAndExactProxyListener(t *testing.T) {
	pol := policy.Effective{
		Workspace: "/workspace",
		FS: []policy.FSEntry{
			{Path: "/usr", Access: policy.ReadAccess | policy.ExecAccess},
			{Path: "/bin", Access: policy.ReadAccess | policy.ExecAccess},
			{Path: "/workspace", Access: policy.ReadAccess | policy.WriteAccess | policy.ExecAccess},
		},
		Net:       policy.NetPolicy{ProxyPort: 43123},
		Env:       policy.EnvPolicy{Set: map[string]string{}},
		Isolation: profile.Sandboxed,
	}
	sbpl, report, level, bits := compileSBPL(pol)
	for _, forbidden := range []string{
		"(allow file-read*)\n",
		"(allow file-read-metadata)\n",
		"(allow process-exec*)\n",
		`(allow network-outbound (remote tcp "*:43123"))`,
		`(allow network-outbound (remote ip "localhost:*"))`,
	} {
		if strings.Contains(sbpl, forbidden) {
			t.Fatalf("Seatbelt profile contains broad rule %q:\n%s", forbidden, sbpl)
		}
	}
	for _, required := range []string{
		`(allow file-read-data (literal "/"))`,
		`(allow file-read* (subpath "/private/var/select"))`,
		`(allow file-read* (subpath "/usr"))`,
		`(allow process-exec (subpath "/bin"))`,
		`(allow network-outbound (remote tcp4 "localhost:43123"))`,
	} {
		if !strings.Contains(sbpl, required) {
			t.Errorf("Seatbelt profile missing scoped rule %q:\n%s", required, sbpl)
		}
	}
	if level != profile.LevelFull || bits&profile.GuaranteeReadBoundary == 0 || bits&profile.GuaranteeTargetNetwork == 0 || bits&profile.GuaranteeNetworkBoundary == 0 {
		t.Fatalf("Seatbelt posture = level %d bits %#b report %+v", level, bits, report.Entries)
	}
	// Review L2: the listener rule cannot name 127.0.0.1, so it is reported
	// narrowed exactly like the loopback rule, never silently claimed exact.
	var reported bool
	for _, entry := range report.Entries {
		if entry.Feature == "proxy-listener" && entry.Status == "narrowed" {
			reported = true
		}
	}
	if !reported {
		t.Fatalf("proxy listener rule not reported narrowed: %+v", report.Entries)
	}
	// The proxy rule is the IPv4 form (the listener is 127.0.0.1 only), and
	// the profile must still parse.
	if strings.Contains(sbpl, `(remote tcp "localhost:43123")`) {
		t.Fatalf("proxy rule kept the dual-stack tcp form:\n%s", sbpl)
	}
}

func TestSeatbeltScopedRuntimeRulesLaunch(t *testing.T) {
	requireSandboxExec(t)
	accessProfile := mustProfile(t, profile.ProfileConfig{
		WorkspaceRoot: t.TempDir(), WorkspaceRead: profile.Allow, WorkspaceWrite: profile.Allow,
		HostRead: profile.Deny, HostWrite: profile.Deny, Network: profile.Deny, Command: profile.Allow,
	})
	pol, err := policy.Compile(accessProfile)
	if err != nil {
		t.Fatal(err)
	}
	sbpl, _, _, _ := compileSBPL(pol)
	if err := exec.Command("/usr/bin/sandbox-exec", "-p", sbpl, "--", "/bin/sh", "-c", "/usr/bin/true").Run(); err != nil {
		t.Fatalf("narrow runtime profile could not launch shell + true: %v\n%s", err, sbpl)
	}
}

func TestSeatbeltProfileCarvesNarrowerRootAxesFromHostAllow(t *testing.T) {
	workspace := t.TempDir()
	accessProfile := mustProfile(t, profile.ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: profile.Deny, WorkspaceWrite: profile.Gated,
		HostRead: profile.Allow, HostWrite: profile.Allow, Network: profile.Deny, Command: profile.Allow,
	})
	pol, err := policy.Compile(accessProfile)
	if err != nil {
		t.Fatal(err)
	}
	sbpl, _, _, _ := compileSBPL(pol)
	rootAllow := `(allow file-read* (subpath "/"))`
	workspacePath := sbplString(accessProfile.Settings().WorkspaceRoot)
	for _, deny := range []string{
		`(deny file-read* (subpath "` + workspacePath + `"))`,
		`(deny process-exec (subpath "` + workspacePath + `"))`,
		`(deny file-write* (subpath "` + workspacePath + `"))`,
	} {
		allowIndex, denyIndex := strings.Index(sbpl, rootAllow), strings.Index(sbpl, deny)
		if allowIndex < 0 || denyIndex <= allowIndex {
			t.Errorf("Seatbelt profile must emit narrower axis deny %q after host allow:\n%s", deny, sbpl)
		}
	}
}

func TestSeatbeltProfileCompilesExactPathAsLiteralAndTreeAsSubpath(t *testing.T) {
	sbpl, _, _, _ := compileSBPL(policy.Effective{FS: []policy.FSEntry{
		{Path: "/workspace/exact", Access: policy.WriteAccess, Exact: true},
		{Path: "/workspace/tree", Access: policy.WriteAccess},
	}})
	exact := `(allow file-write* (literal "/workspace/exact"))`
	tree := `(allow file-write* (subpath "/workspace/tree"))`
	if !strings.Contains(sbpl, exact) {
		t.Fatalf("profile missing exact-path literal %q\n%s", exact, sbpl)
	}
	if !strings.Contains(sbpl, tree) {
		t.Fatalf("profile missing recursive-tree subpath %q\n%s", tree, sbpl)
	}
	if strings.Contains(sbpl, `(allow file-write* (subpath "/workspace/exact"))`) {
		t.Fatalf("exact path widened to recursive subpath\n%s", sbpl)
	}
}

func TestSeatbeltCanonicalGrantPathIsNotRefollowed(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	link := filepath.Join(root, "link")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	sbpl, _, _, _ := compileSBPL(policy.Effective{FS: []policy.FSEntry{{
		Path: link, Access: policy.WriteAccess, Exact: true, Canonical: true,
	}}})
	want := `(allow file-write* (literal "` + link + `"))`
	if !strings.Contains(sbpl, want) {
		t.Fatalf("canonical grant path was followed again; missing %q\n%s", want, sbpl)
	}
	if strings.Contains(sbpl, `(allow file-write* (literal "`+target+`"))`) {
		t.Fatalf("canonical grant path was redirected to symlink target\n%s", sbpl)
	}
}

func TestSeatbeltExactGrantFollowsTreeDenyAtSamePath(t *testing.T) {
	sbpl, _, _, _ := compileSBPL(policy.Effective{FS: []policy.FSEntry{
		{Path: "/workspace/target", Denied: policy.WriteAccess},
		{Path: "/workspace/target", Access: policy.WriteAccess, Exact: true, Canonical: true},
	}})
	deny := `(deny file-write* (subpath "/workspace/target"))`
	allow := `(allow file-write* (literal "/workspace/target"))`
	if denyIndex, allowIndex := strings.Index(sbpl, deny), strings.Index(sbpl, allow); denyIndex < 0 || allowIndex <= denyIndex {
		t.Fatalf("exact grant must follow same-path tree denial: deny=%d allow=%d\n%s", denyIndex, allowIndex, sbpl)
	}
}

func TestSeatbeltGuaranteesTrackIndependentDeniedAxes(t *testing.T) {
	workspace := t.TempDir()
	for _, test := range []struct {
		name                string
		config              profile.ProfileConfig
		wantRead, wantWrite bool
	}{
		{name: "narrow read denial under host allow", config: profile.ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: profile.Deny, WorkspaceWrite: profile.Allow, HostRead: profile.Allow, HostWrite: profile.Allow, Network: profile.Allow, Command: profile.Allow}, wantRead: true},
		{name: "write denial does not imply read boundary", config: profile.ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: profile.Allow, WorkspaceWrite: profile.Deny, HostRead: profile.Allow, HostWrite: profile.Allow, Network: profile.Allow, Command: profile.Allow}, wantWrite: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			pol, err := policy.Compile(mustProfile(t, test.config))
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, bits := compileSBPL(pol)
			if got := bits&profile.GuaranteeReadBoundary != 0; got != test.wantRead {
				t.Fatalf("ReadBoundary = %v, want %v", got, test.wantRead)
			}
			if got := bits&profile.GuaranteeWriteBoundary != 0; got != test.wantWrite {
				t.Fatalf("WriteBoundary = %v, want %v", got, test.wantWrite)
			}
		})
	}
}

// requireSandboxExec capability-skips (with a recorded reason) when
// /usr/bin/sandbox-exec is absent or not runnable here (e.g. a CI that forbids
// nested sandboxing), so a locked-down environment yields a skip, not a false
// failure. These tests are meaningless without a working sandbox-exec. With
// SANDBOX_REQUIRE_SEATBELT=1 (the test-macos CI job sets it) the skip becomes
// a failure instead, so a runner that lost nested sandboxing cannot pass the
// Seatbelt suite as a set of green skips.
func requireSandboxExec(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		skipOrFailSeatbelt(t, "sandbox-exec not available: %v", err)
	}
	if err := exec.Command("/usr/bin/sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true").Run(); err != nil {
		skipOrFailSeatbelt(t, "sandbox-exec present but not runnable here: %v", err)
	}
}

// skipOrFailSeatbelt records a capability skip, or fails when the host has
// declared (SANDBOX_REQUIRE_SEATBELT=1) that Seatbelt must be exercised.
func skipOrFailSeatbelt(t *testing.T, format string, args ...any) {
	t.Helper()
	if os.Getenv("SANDBOX_REQUIRE_SEATBELT") == "1" {
		t.Fatalf("SANDBOX_REQUIRE_SEATBELT=1 but "+format, args...)
	}
	t.Skipf(format, args...)
}

// TestSeatbeltRuntimePlumbingSurvivesHostRootDeny: with HostRead/HostWrite
// Deny the FS section emits (deny file-read*/file-write* (subpath "/")),
// which under last-match-wins shadowed every fixed runtime allow the
// preamble had made earlier — the shell selector (/bin/sh then printed
// "Error opening /private/var/select/sh: Operation not permitted" into every
// command's output) and the xcrun cache file. Those fixed allows are
// re-asserted after the FS section, so the production default shape gets
// them too.
func TestSeatbeltRuntimePlumbingSurvivesHostRootDeny(t *testing.T) {
	requireSandboxExec(t)
	workspace := t.TempDir()
	pol, err := policy.Compile(mustProfile(t, profile.ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: profile.Allow, WorkspaceWrite: profile.Allow,
		HostRead: profile.Deny, HostWrite: profile.Deny, Network: profile.Deny, Command: profile.Allow,
	}))
	if err != nil {
		t.Fatal(err)
	}
	sbpl, _, _, _ := compileSBPL(pol)
	hostDeny := strings.Index(sbpl, `(deny file-read* (subpath "/"))`)
	reasserted := strings.LastIndex(sbpl, `(allow file-read* (subpath "/private/var/select"))`)
	if hostDeny < 0 || reasserted < hostDeny {
		t.Fatalf("shell-selector allow is not re-asserted after the host-root deny:\n%s", sbpl)
	}
	shell := exec.Command("/usr/bin/sandbox-exec", "-p", sbpl, "--", "/bin/sh", "-c", "echo hi")
	shell.Dir = workspace
	out, err := shell.CombinedOutput()
	if err != nil || string(out) != "hi\n" {
		t.Fatalf("/bin/sh under HostRead: Deny = %q (err %v), want exactly %q", out, err, "hi\n")
	}
}
