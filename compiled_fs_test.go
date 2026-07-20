package sandbox

import (
	"errors"
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
	policy, err := compileEffectivePolicy(profile)
	if err != nil {
		t.Fatal(err)
	}
	compiled := compileFSPolicy(policy.FS)
	for _, test := range []struct {
		name                string
		path                string
		wantRead, wantWrite bool
	}{
		{"workspace independent axes", profile.workspaceRoot, false, true},
		{"additional independent axes", profile.additionalRoots[0].Path, true, false},
		{"host access outside carveouts", outside, true, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := compiled.resolve(test.path)
			if got&readFSAccess != 0 != test.wantRead || got&writeFSAccess != 0 != test.wantWrite {
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
	compiled := compileFSPolicy([]fsEntry{
		{Path: root, Access: allFSAccess},
		{Path: workspace, Access: writeFSAccess, Denied: readFSAccess | execFSAccess},
	})
	rules := enumerateFSRules(compiled)
	if got := resolveEnumeratedRules(rules, filepath.Join(workspace, "file")); got != writeFSAccess {
		t.Fatalf("workspace enumerated access = %#x, want write-only", got)
	}
	if got := resolveEnumeratedRules(rules, filepath.Join(outside, "file")); got != allFSAccess {
		t.Fatalf("outside enumerated access = %#x, want full root access", got)
	}
}

func TestCompiledFSPreservesExactScope(t *testing.T) {
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled := compileFSPolicy([]fsEntry{{Path: target, Access: writeFSAccess, Exact: true}})
	if got := compiled.resolve(target); got != writeFSAccess {
		t.Fatalf("exact target access = %#x, want write", got)
	}
	if got := compiled.resolve(filepath.Join(target, "child")); got != denyFSAccess {
		t.Fatalf("exact target widened recursively after compilation: %#x", got)
	}
	rules := enumerateFSRules(compiled)
	if got := resolveEnumeratedRules(rules, target); got != writeFSAccess {
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
		entries []fsEntry
		wantErr bool
	}{
		{name: "exact regular file", entries: []fsEntry{{Path: file, Access: writeFSAccess, Exact: true, Canonical: true}}},
		{name: "recursive directory", entries: []fsEntry{{Path: root, Access: writeFSAccess}}},
		{name: "exact directory unsupported", entries: []fsEntry{{Path: root, Access: writeFSAccess, Exact: true, Canonical: true}}, wantErr: true},
		{name: "exact nonexistent unsupported", entries: []fsEntry{{Path: filepath.Join(root, "future"), Access: writeFSAccess, Exact: true, Canonical: true}}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateLandlockExactPaths(test.entries)
			if test.wantErr && !errors.Is(err, ErrGrantUnsupported) {
				t.Fatalf("error = %v, want ErrGrantUnsupported", err)
			}
			if !test.wantErr && err != nil {
				t.Fatalf("error = %v, want nil", err)
			}
		})
	}
}

func resolveEnumeratedRules(rules []fsRule, path string) fsAccess {
	var access fsAccess
	for _, rule := range rules {
		if rule.Path == path || rule.IsDir && pathWithin(path, rule.Path) {
			access |= rule.Access
		}
	}
	return access
}
