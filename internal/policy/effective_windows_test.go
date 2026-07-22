//go:build windows

package policy

import (
	"strings"
	"testing"
)

func TestCompileEffectivePolicyUsesWindowsRuntimeVocabulary(t *testing.T) {
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: `C:\work\repo`, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	policy, err := Compile(profile)
	if err != nil {
		t.Fatal(err)
	}

	if len(policy.RuntimeBaselines) != 1 || policy.RuntimeBaselines[0] != WindowsRuntimeBaseline {
		t.Fatalf("runtime baselines = %q, want [%q]", policy.RuntimeBaselines, WindowsRuntimeBaseline)
	}
	if got := ResolveFS(policy.FS, `C:\work\repo\main.go`); got != ReadAccess|WriteAccess|ExecAccess {
		t.Fatalf("workspace access = %#x, want rwx", got)
	}
	if got := ResolveFS(policy.FS, `C:\elsewhere`); got != DenyAccess {
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
		if entry.Path == `C:\` {
			foundDriveRoot = true
		}
		path := strings.ToLower(entry.Path)
		if path == "/dev/null" || path == "/bin" || path == "/usr/lib" || strings.HasPrefix(path, "/bin/") || strings.HasPrefix(path, "/usr/lib/") {
			t.Fatalf("Windows policy contains Unix runtime entry: %+v", entry)
		}
	}
	if !foundDriveRoot {
		t.Fatalf("Windows policy entries = %+v, want C:\\ drive-root intent", policy.FS)
	}
}
