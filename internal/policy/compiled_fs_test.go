package policy

import (
	"errors"
	"github.com/looprig/sandbox/pkg/profile"
	"os"
	"path/filepath"
	"testing"
)

func TestCompiledFSPreservesRealProfileAxisPrecedence(t *testing.T) {
	workspace := t.TempDir()
	additional := t.TempDir()
	outside := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Deny, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Allow, Network: Deny, Command: Allow,
		AdditionalRoots: []RootAccess{{Path: additional, Read: Allow, Write: Gated}},
	})
	policy, err := Compile(profile)
	if err != nil {
		t.Fatal(err)
	}
	compiled := CompileFS(policy.FS)
	for _, test := range []struct {
		name                string
		path                string
		wantRead, wantWrite bool
	}{
		{"workspace independent axes", profile.Settings().WorkspaceRoot, false, true},
		{"additional independent axes", profile.Settings().AdditionalRoots[0].Path, true, false},
		{"host access outside carveouts", outside, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := compiled.Resolve(test.path)
			if got&ReadAccess != 0 != test.wantRead || got&WriteAccess != 0 != test.wantWrite {
				t.Fatalf("compiled access at %q = %#x, want read=%v write=%v", test.path, got, test.wantRead, test.wantWrite)
			}
		})
	}
}

func TestCompiledFSSnapshotAxes(t *testing.T) {
	t.Parallel()
	root := filepath.Join(string(filepath.Separator), "workspace")
	protected := filepath.Join(root, "protected")
	tests := []struct {
		name    string
		entries []FSEntry
		want    FSAccess
	}{
		{
			name: "write carveout withholds write and execute",
			entries: []FSEntry{
				{Path: root, Access: AllAccess},
				{Path: protected, Access: ReadAccess, Denied: WriteAccess | ExecAccess},
			},
			want: WriteAccess | ExecAccess,
		},
		{
			name: "nested read deny snapshots read and covering write topology",
			entries: []FSEntry{
				{Path: root, Access: AllAccess},
				{Path: protected, Denied: ReadAccess},
			},
			want: ReadAccess | WriteAccess,
		},
		{
			name: "nested execute deny snapshots execute and covering write topology",
			entries: []FSEntry{
				{Path: root, Access: AllAccess},
				{Path: protected, Denied: ExecAccess},
			},
			want: ExecAccess | WriteAccess,
		},
		{
			name: "deny outside covering allow axes does not carve",
			entries: []FSEntry{
				{Path: root, Access: WriteAccess},
				{Path: protected, Denied: ReadAccess},
			},
		},
		{
			name: "split read and write allows still protect topology",
			entries: []FSEntry{
				{Path: root, Access: WriteAccess},
				{Path: filepath.Join(root, "readable"), Access: ReadAccess},
				{Path: protected, Denied: ReadAccess},
			},
			want: WriteAccess,
		},
		{
			name: "equal-path tie is not sibling enumeration",
			entries: []FSEntry{
				{Path: root, Access: AllAccess},
				{Path: root, Denied: AllAccess},
			},
		},
		{
			name: "equal-path exact deny snapshots recursive descendants",
			entries: []FSEntry{
				{Path: root, Access: AllAccess},
				{Path: root, Denied: AllAccess, Exact: true},
			},
			want: AllAccess,
		},
		{
			name:    "plain writable root has no snapshot",
			entries: []FSEntry{{Path: root, Access: AllAccess}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if got := CompileFS(test.entries).SnapshotAxes(); got != test.want {
				t.Fatalf("SnapshotAxes() = %#x, want %#x", got, test.want)
			}
		})
	}
}

func TestCompiledFSCarveoutExcludesTopologyOnlyWriteSnapshot(t *testing.T) {
	root := filepath.Join(string(filepath.Separator), "workspace")
	protected := filepath.Join(root, "protected")
	if CompileFS([]FSEntry{
		{Path: root, Access: AllAccess},
		{Path: protected, Denied: ReadAccess},
	}).HasCarveout() {
		t.Fatal("read deny topology barrier reported as a read-only carveout")
	}
	if !CompileFS([]FSEntry{
		{Path: root, Access: AllAccess},
		{Path: protected, Denied: WriteAccess},
	}).HasCarveout() {
		t.Fatal("nested write deny not reported as a carveout")
	}
}

func TestEnumerateFSRulesWithholdsWriteTopologyAroundReadDeny(t *testing.T) {
	root := t.TempDir()
	denied := filepath.Join(root, "denied")
	allowed := filepath.Join(root, "allowed")
	for _, path := range []string{denied, allowed} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	compiled := CompileFS([]FSEntry{
		{Path: root, Access: AllAccess},
		{Path: denied, Denied: ReadAccess, Exact: true},
	})
	rules := EnumerateFSRules(compiled)
	if got := resolveEnumeratedRules(rules, root); got&WriteAccess != 0 {
		t.Fatalf("covering root retained topology write access: %#x; rules=%+v", got, rules)
	}
	if got := resolveEnumeratedRules(rules, denied); got != WriteAccess|ExecAccess {
		t.Fatalf("denied object access = %#x, want write+execute; rules=%+v", got, rules)
	}
	if got := resolveEnumeratedRules(rules, allowed); got != AllAccess {
		t.Fatalf("unaffected sibling access = %#x, want full access; rules=%+v", got, rules)
	}
}

func TestEnumerateFSRulesWithholdsSplitAxisWriteTopology(t *testing.T) {
	root := t.TempDir()
	readable := filepath.Join(root, "readable")
	denied := filepath.Join(root, "denied")
	for _, path := range []string{readable, denied} {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	compiled := CompileFS([]FSEntry{
		{Path: root, Access: WriteAccess},
		{Path: readable, Access: ReadAccess, Exact: true},
		{Path: denied, Denied: ReadAccess, Exact: true},
	})
	rules := EnumerateFSRules(compiled)
	if got := resolveEnumeratedRules(rules, root); got&WriteAccess != 0 {
		t.Fatalf("split-axis covering root retained topology write: %#x; rules=%+v", got, rules)
	}
	if got := resolveEnumeratedRules(rules, readable); got != ReadAccess|WriteAccess {
		t.Fatalf("readable source access = %#x, want read+write; rules=%+v", got, rules)
	}
}

func TestEnumerateFSRulesPreservesDescendantsOfEqualPathExactDeny(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(child, "leaf")
	if err := os.WriteFile(leaf, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled := CompileFS([]FSEntry{
		{Path: root, Access: AllAccess},
		{Path: root, Denied: AllAccess, Exact: true},
	})
	rules := EnumerateFSRules(compiled)
	if got := resolveEnumeratedRules(rules, root); got != DenyAccess {
		t.Fatalf("exactly denied root access = %#x, want deny; rules=%+v", got, rules)
	}
	if got := resolveEnumeratedRules(rules, leaf); got != AllAccess {
		t.Fatalf("descendant access = %#x, want full access; rules=%+v", got, rules)
	}
	for _, rule := range rules {
		if rule.Path == root {
			t.Fatalf("exactly denied root received rule: %+v", rule)
		}
	}
}

func TestEnumerateFSRulesEnforcesIndependentAxes(t *testing.T) {
	root := t.TempDir()
	workspace := filepath.Join(root, "workspace")
	outside := filepath.Join(root, "outside")
	for _, path := range []string{workspace, outside} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	compiled := CompileFS([]FSEntry{
		{Path: root, Access: AllAccess},
		{Path: workspace, Access: WriteAccess, Denied: ReadAccess | ExecAccess},
	})
	rules := EnumerateFSRules(compiled)
	if got := resolveEnumeratedRules(rules, filepath.Join(workspace, "file")); got != WriteAccess {
		t.Fatalf("workspace enumerated access = %#x, want write-only", got)
	}
	if got := resolveEnumeratedRules(rules, filepath.Join(outside, "file")); got != AllAccess {
		t.Fatalf("outside enumerated access = %#x, want full root access", got)
	}
}

func TestEnumerateFSRulesKeepsDeepNonexistentDenyFailNarrow(t *testing.T) {
	root := t.TempDir()
	sibling := filepath.Join(root, "work")
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(root, ".git", "a", "b", "secret")
	compiled := CompileFS([]FSEntry{
		{Path: root, Access: AllAccess},
		{Path: denied, Denied: AllAccess},
	})

	rules := EnumerateFSRules(compiled)
	if got := resolveEnumeratedRules(rules, filepath.Join(sibling, "future")); got != AllAccess {
		t.Fatalf("unaffected pre-existing sibling access = %#x, want full access; rules=%+v", got, rules)
	}
	if got := resolveEnumeratedRules(rules, filepath.Join(root, "future")); got != DenyAccess {
		t.Fatalf("nonexistent deny failed to keep covering root narrow: access=%#x rules=%+v", got, rules)
	}
	if got := resolveEnumeratedRules(rules, denied); got != DenyAccess {
		t.Fatalf("nonexistent denied subtree received access=%#x rules=%+v", got, rules)
	}
}

func TestEnumerateFSRulesKeepsNonENOENTDenyFailClosed(t *testing.T) {
	root := t.TempDir()
	notDirectory := filepath.Join(root, "not-a-directory")
	if err := os.WriteFile(notDirectory, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	denied := filepath.Join(notDirectory, "secret")
	compiled := CompileFS([]FSEntry{
		{Path: root, Access: AllAccess},
		{Path: denied, Denied: AllAccess},
	})

	rules := EnumerateFSRules(compiled)
	if got := resolveEnumeratedRules(rules, notDirectory); got != DenyAccess {
		t.Fatalf("ENOTDIR deny failure granted covering leaf: access=%#x rules=%+v", got, rules)
	}
	if got := resolveEnumeratedRules(rules, denied); got != DenyAccess {
		t.Fatalf("ENOTDIR deny failure granted denied subtree: access=%#x rules=%+v", got, rules)
	}
}

func TestCompiledFSPreservesExactScope(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled := CompileFS([]FSEntry{{Path: target, Access: WriteAccess, Exact: true}})
	if got := compiled.Resolve(target); got != WriteAccess {
		t.Fatalf("exact target access = %#x, want write", got)
	}
	if got := compiled.Resolve(filepath.Join(target, "child")); got != DenyAccess {
		t.Fatalf("exact target widened recursively after compilation: %#x", got)
	}
	rules := EnumerateFSRules(compiled)
	if got := resolveEnumeratedRules(rules, target); got != WriteAccess {
		t.Fatalf("exact target enumerated access = %#x, want write", got)
	}
}

func TestValidateLandlockExactPaths(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		entries []FSEntry
		wantErr bool
	}{
		{name: "exact regular file", entries: []FSEntry{{Path: file, Access: WriteAccess, Exact: true, Canonical: true}}},
		{name: "recursive directory", entries: []FSEntry{{Path: root, Access: WriteAccess}}},
		{name: "exact directory unsupported", entries: []FSEntry{{Path: root, Access: WriteAccess, Exact: true, Canonical: true}}, wantErr: true},
		{name: "exact nonexistent unsupported", entries: []FSEntry{{Path: filepath.Join(root, "future"), Access: WriteAccess, Exact: true, Canonical: true}}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateLandlockExactPaths(test.entries, nil)
			if test.wantErr && !errors.Is(err, ErrUnsupportedClass) {
				t.Fatalf("error = %v, want ErrUnsupportedClass", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
		})
	}
}

func resolveEnumeratedRules(rules []FSRule, path string) FSAccess {
	var access FSAccess
	for _, rule := range rules {
		if rule.Path == path || rule.IsDir && profile.PathWithin(path, rule.Path) {
			access |= rule.Access
		}
	}
	return access
}
