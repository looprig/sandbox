//go:build windows

package exec

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestWindowsBroadHostFilesystemGrantsAreUnsupportedBeforeDelta(t *testing.T) {
	if hostFilesystemGrantsSupported() {
		t.Fatal("Windows v1 unexpectedly reports broad host grants supported")
	}
	for _, test := range []struct {
		kind, class string
	}{
		{kind: "filesystem.read", class: GrantClassFilesystemHostRead},
		{kind: "filesystem.write", class: GrantClassFilesystemHostWrite},
	} {
		delta, _, err := validateGrantClass(test.kind, "host:*", test.class, "host:*")
		if !errors.Is(err, ErrGrantUnsupported) {
			t.Fatalf("validateGrantClass(%s) error = %v, want ErrGrantUnsupported", test.class, err)
		}
		if delta.entry != nil {
			t.Fatalf("validateGrantClass(%s) emitted filesystem delta %+v", test.class, delta.entry)
		}
	}
}

func TestWindowsIssueGrantRejectsBroadHostReadAndWrite(t *testing.T) {
	now := time.Date(2026, 7, 21, 19, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Gated, HostWrite: Gated, Network: Deny, Command: Allow,
	})
	executor, err := newTestExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
		withClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		kind, class string
	}{
		{kind: "filesystem.read", class: GrantClassFilesystemHostRead},
		{kind: "filesystem.write", class: GrantClassFilesystemHostWrite},
	} {
		if _, err := executor.IssueGrant(context.Background(), "host", "true", workspace,
			test.kind, "host:*", test.class, "host:*", now.Add(time.Minute).UnixMilli()); !errors.Is(err, ErrGrantUnsupported) {
			t.Fatalf("IssueGrant(%s) error = %v, want ErrGrantUnsupported", test.class, err)
		}
	}
	if len(executor.retainedGrantPaths) != 0 {
		t.Fatalf("host grant rejection consumed handles: %d", len(executor.retainedGrantPaths))
	}
}

func TestWindowsIssueGrantValidatesBeforeProbingNonexistentExactTarget(t *testing.T) {
	now := time.Date(2026, 7, 21, 19, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	target := filepath.Join(workspace, "not-created.txt")

	tests := []struct {
		name           string
		cwd            string
		kind           string
		scope          string
		class          string
		workspaceWrite Access
		nilExecutor    bool
		want           error
	}{
		{
			name: "malformed kind", cwd: workspace, kind: "filesystem.read", scope: target,
			class: GrantClassFilesystemPathWrite, workspaceWrite: Gated, want: ErrGrantMalformed,
		},
		{
			name: "invalid cwd", cwd: filepath.Join(workspace, "not-created-cwd"), kind: "filesystem.write", scope: target,
			class: GrantClassFilesystemPathWrite, workspaceWrite: Gated, want: ErrGrantMalformed,
		},
		{
			name: "scope mismatch", cwd: workspace, kind: "filesystem.write", scope: filepath.Join(workspace, "other.txt"),
			class: GrantClassFilesystemPathWrite, workspaceWrite: Gated, want: ErrGrantMalformed,
		},
		{
			name: "unsupported class", cwd: workspace, kind: "filesystem.write", scope: target,
			class: "filesystem.path.future.v1", workspaceWrite: Gated, want: ErrGrantUnsupported,
		},
		{
			name: "profile denies request", cwd: workspace, kind: "filesystem.write", scope: target,
			class: GrantClassFilesystemPathWrite, workspaceWrite: Deny, want: ErrGrantDenied,
		},
		{
			name: "profile does not gate request", cwd: workspace, kind: "filesystem.write", scope: target,
			class: GrantClassFilesystemPathWrite, workspaceWrite: Allow, want: ErrGrantUnsupported,
		},
		{
			name: "invalid profile", cwd: workspace, kind: "filesystem.write", scope: target,
			class: GrantClassFilesystemPathWrite, nilExecutor: true, want: ErrInvalidProfile,
		},
		{
			name: "authorized nonexistent exact", cwd: workspace, kind: "filesystem.write", scope: target,
			class: GrantClassFilesystemPathWrite, workspaceWrite: Gated, want: ErrGrantUnsupported,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var executor *Executor
			if !test.nilExecutor {
				profile := mustProfile(t, ProfileConfig{
					WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: test.workspaceWrite,
					HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
				})
				var err error
				executor, err = newTestExecutor(profile,
					withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
					withClock(func() time.Time { return now }),
				)
				if err != nil {
					t.Fatal(err)
				}
			}

			if _, err := executor.IssueGrant(context.Background(), "missing-exact", "true", test.cwd,
				test.kind, test.scope, test.class, target, now.Add(time.Minute).UnixMilli()); !errors.Is(err, test.want) {
				t.Fatalf("IssueGrant(nonexistent exact target) error = %v, want %v", err, test.want)
			}
			if executor != nil && len(executor.retainedGrantPaths) != 0 {
				t.Fatalf("rejected exact grant retained handles: %d", len(executor.retainedGrantPaths))
			}
		})
	}
}
