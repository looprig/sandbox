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
		`(allow network-outbound (remote tcp "localhost:43123"))`,
	} {
		if !strings.Contains(sbpl, required) {
			t.Errorf("Seatbelt profile missing scoped rule %q:\n%s", required, sbpl)
		}
	}
	if level != profile.LevelFull || bits&profile.GuaranteeReadBoundary == 0 || bits&profile.GuaranteeTargetNetwork == 0 || bits&profile.GuaranteeNetworkBoundary == 0 {
		t.Fatalf("Seatbelt posture = level %d bits %#b report %+v", level, bits, report.Entries)
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
