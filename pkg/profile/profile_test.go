package profile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestNewProfileAccessValues(t *testing.T) {
	if Deny != 0 || Gated != 1 || Allow != 2 {
		t.Fatalf("Access values = (%d,%d,%d), want (0,1,2)", Deny, Gated, Allow)
	}

	workspace := t.TempDir()
	root := t.TempDir()
	config := ProfileConfig{
		WorkspaceRoot:   equivalentRootSpelling(workspace),
		WorkspaceRead:   Allow,
		WorkspaceWrite:  Gated,
		HostRead:        Deny,
		HostWrite:       Gated,
		Network:         Allow,
		Command:         Gated,
		Home:            IsolatedHome,
		Isolation:       Sandboxed,
		AdditionalRoots: []RootAccess{{Path: equivalentRootSpelling(root), Read: Allow, Write: Deny}},
	}
	p, err := NewProfile(config)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	if p.AccessVersion() != 1 {
		t.Fatalf("AccessVersion = %d, want 1", p.AccessVersion())
	}
	wantWorkspace, err := filepath.EvalSymlinks(workspace)
	if err != nil {
		t.Fatal(err)
	}
	wantRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if p.workspaceRoot != wantWorkspace {
		t.Fatalf("workspaceRoot = %q, want %q", p.workspaceRoot, wantWorkspace)
	}
	if len(p.additionalRoots) != 1 || p.additionalRoots[0].Path != wantRoot {
		t.Fatalf("additionalRoots = %#v, want canonical %q", p.additionalRoots, wantRoot)
	}

	// Construction owns its normalized copy.
	config.AdditionalRoots[0].Read = Deny
	if p.additionalRoots[0].Read != Allow {
		t.Fatal("Profile changed after caller mutated ProfileConfig")
	}
}

func TestNewProfileValidation(t *testing.T) {
	workspace := t.TempDir()
	root := t.TempDir()
	tests := []struct {
		name   string
		config ProfileConfig
	}{
		{name: "missing workspace", config: ProfileConfig{}},
		{name: "relative workspace", config: ProfileConfig{WorkspaceRoot: "relative"}},
		{name: "unknown workspace access", config: ProfileConfig{WorkspaceRoot: workspace, WorkspaceRead: Access(3)}},
		{name: "unknown home", config: ProfileConfig{WorkspaceRoot: workspace, Home: Home(2)}},
		{name: "unknown isolation", config: ProfileConfig{WorkspaceRoot: workspace, Isolation: Isolation(2)}},
		{name: "relative additional root", config: ProfileConfig{WorkspaceRoot: workspace, AdditionalRoots: []RootAccess{{Path: "relative"}}}},
		{name: "contradictory duplicate root", config: ProfileConfig{WorkspaceRoot: workspace, AdditionalRoots: []RootAccess{{Path: root, Read: Allow}, {Path: equivalentRootSpelling(root), Read: Deny}}}},
		{name: "unacknowledged unconfined", config: unconfinedConfig(workspace, false)},
		{name: "restricted unconfined", config: func() ProfileConfig { c := unconfinedConfig(workspace, true); c.HostWrite = Gated; return c }()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewProfile(tt.config); err == nil {
				t.Fatal("NewProfile error = nil, want validation error")
			}
		})
	}

	var zero Profile
	if zero.AccessVersion() != 0 {
		t.Fatalf("zero AccessVersion = %d, want unsupported 0", zero.AccessVersion())
	}
	if _, err := zero.AccessFor("command.execute", ""); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("zero AccessFor error = %v, want ErrInvalidProfile", err)
	}
}

func TestAccessFor(t *testing.T) {
	workspace := t.TempDir()
	root := t.TempDir()
	p, err := NewProfile(ProfileConfig{
		WorkspaceRoot:  workspace,
		WorkspaceRead:  Allow,
		WorkspaceWrite: Gated,
		HostRead:       Deny,
		HostWrite:      Gated,
		Network:        Allow,
		Command:        Gated,
		AdditionalRoots: []RootAccess{{
			Path: root, Read: Gated, Write: Allow,
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	workspace = p.workspaceRoot
	root = p.additionalRoots[0].Path

	tests := []struct {
		name  string
		kind  string
		scope string
		want  Access
	}{
		{name: "command", kind: "command.execute", want: Gated},
		{name: "network", kind: "network", want: Allow},
		{name: "workspace exact read", kind: "filesystem.read", scope: filepath.Join(workspace, "file"), want: Allow},
		{name: "workspace tree write", kind: "filesystem.write", scope: "tree:" + workspace, want: Gated},
		{name: "additional read", kind: "filesystem.read", scope: filepath.Join(root, "file"), want: Gated},
		{name: "additional tree write", kind: "filesystem.write", scope: "tree:" + root, want: Allow},
		{name: "host exact read", kind: "filesystem.read", scope: filepath.Join(filepath.Dir(workspace), "elsewhere"), want: Deny},
		{name: "host broad write", kind: "filesystem.write", scope: "host:*", want: Gated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := p.AccessFor(tt.kind, tt.scope)
			if err != nil {
				t.Fatalf("AccessFor: %v", err)
			}
			if Access(got) != tt.want {
				t.Fatalf("AccessFor = %d, want %d", got, tt.want)
			}
		})
	}

	bad := []struct{ kind, scope string }{
		{"unknown", ""},
		{"command.execute", workspace},
		{"network", "github.com"},
		{"filesystem.read", ""},
		{"filesystem.read", "relative"},
		{"filesystem.read", workspace + string(os.PathSeparator) + ".." + string(os.PathSeparator) + "escape"},
		{"filesystem.write", "tree:" + filepath.Join(workspace, "missing")},
		{"filesystem.write", "tree:relative"},
	}
	for _, tt := range bad {
		if _, err := p.AccessFor(tt.kind, tt.scope); err == nil {
			t.Errorf("AccessFor(%q,%q) error = nil", tt.kind, tt.scope)
		}
	}
}

func TestRestrict(t *testing.T) {
	workspace := t.TempDir()
	root := t.TempDir()
	base := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Allow, Network: Allow, Command: Allow,
		Home: RealHome, Isolation: Unconfined, AckUnconfined: true,
		AdditionalRoots: []RootAccess{{Path: root, Read: Allow, Write: Allow}},
	})
	ceiling := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Deny,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Gated,
		Home: IsolatedHome, Isolation: Sandboxed,
		AdditionalRoots: []RootAccess{{Path: root, Read: Gated, Write: Deny}},
	})

	got, err := Restrict(base, ceiling)
	if err != nil {
		t.Fatalf("Restrict: %v", err)
	}
	if got.workspaceWrite != Deny || got.hostRead != Deny || got.network != Deny || got.command != Gated {
		t.Fatalf("restricted access = %#v", got)
	}
	if got.home != IsolatedHome || got.isolation != Sandboxed || got.ackUnconfined {
		t.Fatalf("restricted confinement = home %d isolation %d ack %v", got.home, got.isolation, got.ackUnconfined)
	}
	if len(got.additionalRoots) != 1 || got.additionalRoots[0].Read != Gated || got.additionalRoots[0].Write != Deny {
		t.Fatalf("restricted roots = %#v", got.additionalRoots)
	}
	if got.requiredGuarantees&GuaranteeReadBoundary == 0 {
		t.Fatal("restricted profile does not require the distinct read boundary")
	}
	if base.workspaceWrite != Allow || ceiling.workspaceWrite != Deny {
		t.Fatal("Restrict mutated an input")
	}

	other := mustProfile(t, ProfileConfig{WorkspaceRoot: t.TempDir()})
	if _, err := Restrict(base, other); err == nil {
		t.Fatal("Restrict workspace mismatch error = nil")
	}
	if _, err := Restrict(nil, ceiling); !errors.Is(err, ErrInvalidProfile) {
		t.Fatalf("Restrict nil error = %v, want ErrInvalidProfile", err)
	}
}

func TestProfileFingerprint(t *testing.T) {
	workspace := t.TempDir()
	rootA := t.TempDir()
	rootB := t.TempDir()
	a := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
		AdditionalRoots: []RootAccess{{Path: rootB, Read: Gated}, {Path: rootA, Write: Allow}},
	})
	b := mustProfile(t, ProfileConfig{
		WorkspaceRoot: equivalentRootSpelling(workspace), WorkspaceRead: Allow, WorkspaceWrite: Gated,
		AdditionalRoots: []RootAccess{{Path: rootA, Write: Allow}, {Path: rootB, Read: Gated}},
	})
	if a.Fingerprint() == "" || a.Fingerprint() != b.Fingerprint() {
		t.Fatalf("equivalent fingerprints = %q and %q", a.Fingerprint(), b.Fingerprint())
	}
	c := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Deny,
		AdditionalRoots: []RootAccess{{Path: rootA, Write: Allow}, {Path: rootB, Read: Gated}},
	})
	if a.Fingerprint() == c.Fingerprint() {
		t.Fatal("authority change did not change fingerprint")
	}
	var zero Profile
	if zero.Fingerprint() != "" {
		t.Fatalf("zero Fingerprint = %q, want empty", zero.Fingerprint())
	}
}

func unconfinedConfig(workspace string, ack bool) ProfileConfig {
	return ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Allow, Network: Allow, Command: Allow,
		Home: RealHome, Isolation: Unconfined, AckUnconfined: ack,
	}
}

func mustProfile(t *testing.T, config ProfileConfig) *Profile {
	t.Helper()
	p, err := NewProfile(config)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	return p
}
