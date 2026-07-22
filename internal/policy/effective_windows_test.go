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
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	policy, err := Compile(profile)
	if err != nil {
		t.Fatal(err)
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
