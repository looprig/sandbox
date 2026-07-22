//go:build windows

package exec

import (
	"context"
	"errors"
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
