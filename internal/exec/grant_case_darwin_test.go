//go:build darwin

package exec

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestIssueGrantRefusesCaseVariantOfDenyRoot pins H5: Seatbelt matches paths
// case-insensitively on APFS and a longer literal allow outranks a shorter
// subpath deny, so a grant minted for a case variant of a file under a Deny
// root would open it. The target must resolve to the Deny root and be refused.
func TestIssueGrantRefusesCaseVariantOfDenyRoot(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	secret := filepath.Join(workspace, "R", "secret")
	if err := os.MkdirAll(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secret, "key"), []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	upper := filepath.Join(workspace, "R", "SECRET", "key")
	if _, err := os.Lstat(upper); err != nil {
		t.Skipf("case-sensitive volume: %v", err)
	}
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Gated, WorkspaceWrite: Gated,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
		AdditionalRoots: []RootAccess{{Path: secret, Read: Deny, Write: Deny}},
	})
	executor, err := newTestExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
		withClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []struct{ kind, class string }{
		{"filesystem.read", GrantClassFilesystemPathRead},
		{"filesystem.write", GrantClassFilesystemPathWrite},
	} {
		_, err := executor.IssueGrant(context.Background(), "case", "true", workspace,
			request.kind, upper, request.class, upper, now.Add(time.Minute).UnixMilli())
		if !errors.Is(err, ErrGrantDenied) {
			t.Fatalf("IssueGrant(%s, %s) error = %v, want ErrGrantDenied", request.class, upper, err)
		}
	}
	if len(executor.retainedGrantPaths) != 0 {
		t.Fatalf("refused grants retained %d path handles", len(executor.retainedGrantPaths))
	}
}
