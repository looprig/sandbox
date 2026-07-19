package sandbox

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestCompileEffectivePolicyDenyAndGatedStayClosed(t *testing.T) {
	workspace := t.TempDir()
	root := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace,
		WorkspaceRead: Gated,
		HostWrite:     Gated,
		Network:       Gated,
		Command:       Gated,
		AdditionalRoots: []RootAccess{{
			Path: root, Read: Gated, Write: Deny,
		}},
	})

	policy, err := compileEffectivePolicy(profile)
	if err != nil {
		t.Fatalf("compileEffectivePolicy: %v", err)
	}
	if got := resolveFS(policy.FS, profile.workspaceRoot); got != denyFSAccess {
		t.Fatalf("workspace access = %d, want denied until grant", got)
	}
	if got := resolveFS(policy.FS, profile.additionalRoots[0].Path); got != denyFSAccess {
		t.Fatalf("additional-root access = %d, want denied until grant", got)
	}
	if !netBlocked(policy) {
		t.Fatalf("network policy = %#v, want blocked until grant", policy.Net)
	}
	want := GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub
	if profile.requiredGuarantees&want != want {
		t.Fatalf("required guarantees = %#b, want at least %#b", profile.requiredGuarantees, want)
	}
	if resolveFS(policy.FS, filepath.Join(profile.workspaceRoot, ".env")) != denyFSAccess {
		t.Fatal("denied workspace unexpectedly readable")
	}
}

func TestCompileEffectivePolicyAllow(t *testing.T) {
	workspace := t.TempDir()
	root := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Allow, Command: Allow,
		AdditionalRoots: []RootAccess{{Path: root, Read: Allow, Write: Allow}},
	})
	policy, err := compileEffectivePolicy(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{profile.workspaceRoot, profile.additionalRoots[0].Path} {
		got := resolveFS(policy.FS, path)
		want := readFSAccess | writeFSAccess | execFSAccess
		if got != want {
			t.Errorf("access for %q = %d, want %d", path, got, want)
		}
	}
	if !policy.Net.Open {
		t.Fatal("Network Allow did not compile to open base egress")
	}
	if got := resolveFS(policy.FS, filepath.Join(profile.workspaceRoot, ".git")); got&writeFSAccess == 0 {
		t.Fatal("compiler retained an implicit .git carveout")
	}
}

func TestCompileEffectivePolicyRejectsZeroProfile(t *testing.T) {
	if _, err := compileEffectivePolicy(&Profile{}); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("compileEffectivePolicy zero error = %v, want ErrInvalidProfile", err)
	}
}
