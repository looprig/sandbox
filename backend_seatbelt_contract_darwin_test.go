//go:build darwin

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestSeatbeltProfileUsesScopedRuntimeReadExecAndExactProxyListener(t *testing.T) {
	policy := effectivePolicy{
		Workspace: "/workspace",
		FS: []fsEntry{
			{Path: "/usr", Access: readFSAccess | execFSAccess},
			{Path: "/bin", Access: readFSAccess | execFSAccess},
			{Path: "/workspace", Access: readFSAccess | writeFSAccess | execFSAccess},
		},
		Net:       effectiveNetPolicy{ProxyPort: 43123},
		Env:       effectiveEnvPolicy{Set: map[string]string{}},
		Isolation: Sandboxed,
	}
	profile, report, level, bits := compileSBPL(policy)
	for _, forbidden := range []string{
		"(allow file-read*)\n",
		"(allow file-read-metadata)\n",
		"(allow process-exec*)\n",
		`(allow network-outbound (remote tcp "*:43123"))`,
		`(allow network-outbound (remote ip "localhost:*"))`,
	} {
		if strings.Contains(profile, forbidden) {
			t.Fatalf("Seatbelt profile contains broad rule %q:\n%s", forbidden, profile)
		}
	}
	for _, required := range []string{
		`(allow file-read-data (literal "/"))`,
		`(allow file-read* (subpath "/private/var/select"))`,
		`(allow file-read* (subpath "/usr"))`,
		`(allow process-exec (subpath "/bin"))`,
		`(allow network-outbound (remote tcp "localhost:43123"))`,
	} {
		if !strings.Contains(profile, required) {
			t.Errorf("Seatbelt profile missing scoped rule %q:\n%s", required, profile)
		}
	}
	if level != LevelFull || bits&GuaranteeReadBoundary == 0 || bits&GuaranteeTargetNetwork == 0 || bits&GuaranteeNetworkBoundary == 0 {
		t.Fatalf("Seatbelt posture = level %d bits %#b report %+v", level, bits, report.Entries)
	}
}

func TestSeatbeltScopedRuntimeRulesLaunch(t *testing.T) {
	requireSandboxExec(t)
	accessProfile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: t.TempDir(), WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	policy, err := compileEffectivePolicy(accessProfile)
	if err != nil {
		t.Fatal(err)
	}
	profile, _, _, _ := compileSBPL(policy)
	if err := exec.Command("/usr/bin/sandbox-exec", "-p", profile, "--", "/bin/sh", "-c", "/usr/bin/true").Run(); err != nil {
		t.Fatalf("narrow runtime profile could not launch shell + true: %v\n%s", err, profile)
	}
}

func TestSeatbeltProfileCarvesNarrowerRootAxesFromHostAllow(t *testing.T) {
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Deny, WorkspaceWrite: Gated,
		HostRead: Allow, HostWrite: Allow, Network: Deny, Command: Allow,
	})
	policy, err := compileEffectivePolicy(profile)
	if err != nil {
		t.Fatal(err)
	}
	sbpl, _, _, _ := compileSBPL(policy)
	rootAllow := `(allow file-read* (subpath "/"))`
	workspacePath := sbplString(profile.Settings().WorkspaceRoot)
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
	profile, _, _, _ := compileSBPL(effectivePolicy{FS: []fsEntry{
		{Path: "/workspace/exact", Access: writeFSAccess, Exact: true},
		{Path: "/workspace/tree", Access: writeFSAccess},
	}})
	exact := `(allow file-write* (literal "/workspace/exact"))`
	tree := `(allow file-write* (subpath "/workspace/tree"))`
	if !strings.Contains(profile, exact) {
		t.Fatalf("profile missing exact-path literal %q\n%s", exact, profile)
	}
	if !strings.Contains(profile, tree) {
		t.Fatalf("profile missing recursive-tree subpath %q\n%s", tree, profile)
	}
	if strings.Contains(profile, `(allow file-write* (subpath "/workspace/exact"))`) {
		t.Fatalf("exact path widened to recursive subpath\n%s", profile)
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
	profile, _, _, _ := compileSBPL(effectivePolicy{FS: []fsEntry{{
		Path: link, Access: writeFSAccess, Exact: true, Canonical: true,
	}}})
	want := `(allow file-write* (literal "` + link + `"))`
	if !strings.Contains(profile, want) {
		t.Fatalf("canonical grant path was followed again; missing %q\n%s", want, profile)
	}
	if strings.Contains(profile, `(allow file-write* (literal "`+target+`"))`) {
		t.Fatalf("canonical grant path was redirected to symlink target\n%s", profile)
	}
}

func TestSeatbeltExactGrantFollowsTreeDenyAtSamePath(t *testing.T) {
	profile, _, _, _ := compileSBPL(effectivePolicy{FS: []fsEntry{
		{Path: "/workspace/target", Denied: writeFSAccess},
		{Path: "/workspace/target", Access: writeFSAccess, Exact: true, Canonical: true},
	}})
	deny := `(deny file-write* (subpath "/workspace/target"))`
	allow := `(allow file-write* (literal "/workspace/target"))`
	if denyIndex, allowIndex := strings.Index(profile, deny), strings.Index(profile, allow); denyIndex < 0 || allowIndex <= denyIndex {
		t.Fatalf("exact grant must follow same-path tree denial: deny=%d allow=%d\n%s", denyIndex, allowIndex, profile)
	}
}

func TestSeatbeltGuaranteesTrackIndependentDeniedAxes(t *testing.T) {
	workspace := t.TempDir()
	for _, test := range []struct {
		name                string
		config              ProfileConfig
		wantRead, wantWrite bool
	}{
		{name: "narrow read denial under host allow", config: ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: Deny, WorkspaceWrite: Allow, HostRead: Allow, HostWrite: Allow, Network: Allow, Command: Allow}, wantRead: true},
		{name: "write denial does not imply read boundary", config: ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Deny, HostRead: Allow, HostWrite: Allow, Network: Allow, Command: Allow}, wantWrite: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			policy, err := compileEffectivePolicy(mustProfile(t, test.config))
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, bits := compileSBPL(policy)
			if got := bits&GuaranteeReadBoundary != 0; got != test.wantRead {
				t.Fatalf("ReadBoundary = %v, want %v", got, test.wantRead)
			}
			if got := bits&GuaranteeWriteBoundary != 0; got != test.wantWrite {
				t.Fatalf("WriteBoundary = %v, want %v", got, test.wantWrite)
			}
		})
	}
}
