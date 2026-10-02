//go:build windows

package policy

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/looprig/sandbox/internal/winpath"
)

func TestCompileEffectivePolicyUsesWindowsRuntimeVocabulary(t *testing.T) {
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: t.TempDir(), WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	// Probe with the profile's canonical workspace, never the t.TempDir()
	// spelling it was built from. NewProfile stores the handle-resolved DOS
	// path (profile.CanonicalRoot), which expands 8.3 aliases: on a
	// GitHub-hosted runner %TEMP% is C:\Users\RUNNER~1\... while the stored
	// root is C:\Users\runneradmin\.... ResolveFS is lexical by contract and
	// cannot expand a short name without I/O, so the raw spelling is a
	// different key and resolves under the denied drive-root intent instead.
	// Its Windows callers pass canonical paths: the backend's ACL planning
	// joins a handle-resolved target (binding.CanonicalPath,
	// PathHandle.Target) with names its own directory enumeration returned.
	workspace := profile.Settings().WorkspaceRoot
	policy, err := Compile(profile)
	if err != nil {
		t.Fatal(err)
	}
	if !winpath.EqualPath(policy.Workspace, workspace) {
		t.Fatalf("effective workspace = %q, want the profile's canonical root %q", policy.Workspace, workspace)
	}

	if len(policy.RuntimeBaselines) != 1 || policy.RuntimeBaselines[0] != WindowsRuntimeBaseline {
		t.Fatalf("runtime baselines = %q, want [%q]", policy.RuntimeBaselines, WindowsRuntimeBaseline)
	}
	if got := ResolveFS(policy.FS, filepath.Join(workspace, "main.go")); got != ReadAccess|WriteAccess|ExecAccess {
		t.Fatalf("workspace access = %#x, want rwx", got)
	}
	workspaceRoot := filepath.VolumeName(workspace) + `\`
	if got := ResolveFS(policy.FS, filepath.Join(workspaceRoot, "elsewhere")); got != DenyAccess {
		t.Fatalf("drive-root access = %#x, want denied", got)
	}
	if got := ResolveFS(policy.FS, NullDevicePath); got != ReadAccess|WriteAccess {
		t.Fatalf("null device access = %#x, want read/write", got)
	}
	if NullDevicePath != "NUL" {
		t.Fatalf("NullDevicePath = %q, want NUL", NullDevicePath)
	}

	foundDriveRoot := false
	for _, entry := range policy.FS {
		if winpath.EqualPath(entry.Path, workspaceRoot) {
			foundDriveRoot = true
		}
		path := strings.ToLower(entry.Path)
		if path == "/dev/null" || path == "/bin" || path == "/usr/lib" || strings.HasPrefix(path, "/bin/") || strings.HasPrefix(path, "/usr/lib/") {
			t.Fatalf("Windows policy contains Unix runtime entry: %+v", entry)
		}
	}
	if !foundDriveRoot {
		t.Fatalf("Windows policy entries = %+v, want %s drive-root intent", policy.FS, workspaceRoot)
	}
}

func TestWindowsCompileEnumeratesEverySupportedLocalVolumeRoot(t *testing.T) {
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	workspaceRoot := filepath.VolumeName(workspace) + `\`
	otherRoot := `Z:\`
	if strings.EqualFold(workspaceRoot, otherRoot) {
		otherRoot = `Y:\`
	}
	compiled, err := compileWithHostRoots(profile, func() ([]string, error) {
		return []string{otherRoot, workspaceRoot}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var roots []string
	for _, entry := range compiled.FS {
		if pathKeyIsRoot(pathKey(entry.Path)) {
			roots = append(roots, entry.Path)
		}
	}
	want := []string{workspaceRoot, otherRoot}
	slices.SortFunc(want, winpath.Compare)
	if len(roots) != 2 || !winpath.EqualPath(roots[0], want[0]) || !winpath.EqualPath(roots[1], want[1]) {
		t.Fatalf("volume root entries = %q, want deterministic %q", roots, want)
	}
}
