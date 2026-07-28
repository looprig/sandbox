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
