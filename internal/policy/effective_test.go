package policy

import (
	"errors"
	"path/filepath"
	"runtime"
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

	policy, err := Compile(profile)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got := ResolveFS(policy.FS, profile.Settings().WorkspaceRoot); got != DenyAccess {
		t.Fatalf("workspace access = %d, want denied until grant", got)
	}
	if got := ResolveFS(policy.FS, profile.Settings().AdditionalRoots[0].Path); got != DenyAccess {
		t.Fatalf("additional-root access = %d, want denied until grant", got)
	}
	if !netBlocked(policy) {
		t.Fatalf("network policy = %#v, want blocked until grant", policy.Net)
	}
	want := GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub
	if profile.Settings().RequiredGuarantees&want != want {
		t.Fatalf("required guarantees = %#b, want at least %#b", profile.Settings().RequiredGuarantees, want)
	}
	if ResolveFS(policy.FS, filepath.Join(profile.Settings().WorkspaceRoot, ".env")) != DenyAccess {
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
	policy, err := Compile(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{profile.Settings().WorkspaceRoot, profile.Settings().AdditionalRoots[0].Path} {
		got := ResolveFS(policy.FS, path)
		want := ReadAccess | WriteAccess | ExecAccess
		if got != want {
			t.Errorf("access for %q = %d, want %d", path, got, want)
		}
	}
	if !policy.Net.Open {
		t.Fatal("Network Allow did not compile to open base egress")
	}
	if got := ResolveFS(policy.FS, filepath.Join(profile.Settings().WorkspaceRoot, ".git")); got&WriteAccess == 0 {
		t.Fatal("compiler retained an implicit .git carveout")
	}
}

func TestCompileEffectivePolicyPreservesIndependentRootPrecedence(t *testing.T) {
	workspace := t.TempDir()
	additional := t.TempDir()
	outside := t.TempDir()
	tests := []struct {
		name                string
		config              ProfileConfig
		path                string
		wantRead, wantWrite bool
	}{
		{
			name: "workspace deny read carves broad host read",
			config: ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: Deny, WorkspaceWrite: Deny,
				HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow},
			path: workspace, wantRead: false, wantWrite: false,
		},
		{
			name: "workspace gated write carves broad host write",
			config: ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
				HostRead: Deny, HostWrite: Allow, Network: Deny, Command: Allow},
			path: workspace, wantRead: true, wantWrite: false,
		},
		{
			name: "additional deny and gated carve broad host access",
			config: ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
				HostRead: Allow, HostWrite: Allow, Network: Deny, Command: Allow,
				AdditionalRoots: []RootAccess{{Path: additional, Read: Deny, Write: Gated}}},
			path: additional, wantRead: false, wantWrite: false,
		},
		{
			name: "narrow workspace allow overrides host deny",
			config: ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
				HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow},
			path: workspace, wantRead: true, wantWrite: true,
		},
		{
			name: "broad host allow remains outside carveouts",
			config: ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: Deny, WorkspaceWrite: Gated,
				HostRead: Allow, HostWrite: Allow, Network: Deny, Command: Allow},
			path: outside, wantRead: true, wantWrite: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profile := mustProfile(t, test.config)
			policy, err := Compile(profile)
			if err != nil {
				t.Fatal(err)
			}
			target := test.path
			if target == workspace {
				target = profile.Settings().WorkspaceRoot
			} else if target == additional {
				target = profile.Settings().AdditionalRoots[0].Path
			}
			got := ResolveFS(policy.FS, target)
			if read := got&ReadAccess != 0; read != test.wantRead {
				t.Errorf("read at %q = %v, want %v (access=%#x)", target, read, test.wantRead, got)
			}
			if write := got&WriteAccess != 0; write != test.wantWrite {
				t.Errorf("write at %q = %v, want %v (access=%#x)", target, write, test.wantWrite, got)
			}
		})
	}
}

func TestCompileEffectivePolicyLeavesTempOwnershipToExecutorSet(t *testing.T) {
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	policy, err := Compile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := policy.Env.Set["TMPDIR"]; ok {
		t.Fatalf("base profile selected a shared TMPDIR: %+v", policy.Env.Set)
	}
	if got := ResolveFS(policy.FS, "/tmp"); got&WriteAccess != 0 {
		t.Fatalf("base profile granted shared /tmp write: %#x", got)
	}
}

func TestCompileEffectivePolicyUsesNarrowRuntimeClosure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix runtime closure")
	}
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	policy, err := Compile(profile)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		path string
		want FSAccess
	}{
		{path: "/bin/sh", want: ReadAccess | ExecAccess},
		{path: "/usr/bin/env", want: ReadAccess | ExecAccess},
		{path: "/usr/lib/libSystem.B.dylib", want: ReadAccess},
		{path: "/etc/hosts", want: ReadAccess},
		{path: "/usr/local/private", want: DenyAccess},
		{path: "/etc/ssh/ssh_config", want: DenyAccess},
		{path: "/Library/Keychains/private.keychain", want: DenyAccess},
	} {
		if got := ResolveFS(policy.FS, test.path); got != test.want {
			t.Errorf("runtime access for %q = %#x, want %#x", test.path, got, test.want)
		}
	}
}

func TestCompileEffectivePolicyHasNoNamedRuntimeBaselineOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix runtime vocabulary")
	}
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	policy, err := Compile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.RuntimeBaselines) != 0 {
		t.Fatalf("runtime baselines = %q, want none", policy.RuntimeBaselines)
	}
}

func TestCompileEffectivePolicyRejectsZeroProfile(t *testing.T) {
	if _, err := Compile(&Profile{}); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("Compile zero error = %v, want ErrInvalidProfile", err)
	}
}
