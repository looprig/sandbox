//go:build darwin

package profile

import (
	"os"
	"path/filepath"
	"testing"
)

// requireCaseInsensitive skips on a case-sensitive volume, where a case
// variant names a different (here absent) object rather than an alias.
func requireCaseInsensitive(t *testing.T, path, variant string) {
	t.Helper()
	if _, err := os.Lstat(variant); err != nil {
		t.Skipf("%s is on a case-sensitive volume: %v", path, err)
	}
}

// TestCanonicalRootUsesOnDiskSpelling pins H5: on APFS a case or Unicode
// normalization variant opens the same directory, and Seatbelt matches it, so
// the canonical root must carry the on-disk spelling rather than the caller's.
func TestCanonicalRootUsesOnDiskSpelling(t *testing.T) {
	base := mustCanonicalTestRoot(t, t.TempDir())
	secret := filepath.Join(base, "R", "secret")
	if err := os.MkdirAll(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	composed := filepath.Join(base, "Café")
	if err := os.Mkdir(composed, 0o700); err != nil {
		t.Fatal(err)
	}
	upper := filepath.Join(base, "R", "SECRET")
	requireCaseInsensitive(t, secret, upper)

	for variant, want := range map[string]string{
		upper:                              secret,
		filepath.Join(base, "r", "Secret"): secret,
		filepath.Join(base, "Café"):       composed,
		filepath.Join(base, "CAFÉ"):        composed,
		secret:                             secret,
	} {
		got, err := CanonicalRoot(variant)
		if err != nil {
			t.Fatalf("CanonicalRoot(%q): %v", variant, err)
		}
		if got != want {
			t.Errorf("CanonicalRoot(%q) = %q, want on-disk %q", variant, got, want)
		}
	}

	p := mustProfile(t, ProfileConfig{
		WorkspaceRoot: base, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		AdditionalRoots: []RootAccess{{Path: upper, Read: Deny, Write: Deny}},
	})
	if got := p.additionalRoots[0].Path; got != secret {
		t.Fatalf("configured root = %q, want on-disk %q", got, secret)
	}
	if access, err := p.AccessFor("filesystem.read", filepath.Join(secret, "key")); err != nil || Access(access) != Deny {
		t.Fatalf("AccessFor on-disk child = %d, %v; want Deny", access, err)
	}
}

// TestCanonicalRootRespellsUnreadableDirectory covers the fallback for a
// directory that cannot be opened: its name is recovered from its parent.
func TestCanonicalRootRespellsUnreadableDirectory(t *testing.T) {
	base := mustCanonicalTestRoot(t, t.TempDir())
	locked := filepath.Join(base, "Locked")
	if err := os.Mkdir(locked, 0o700); err != nil {
		t.Fatal(err)
	}
	requireCaseInsensitive(t, locked, filepath.Join(base, "LOCKED"))
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	got, err := CanonicalRoot(filepath.Join(base, "LOCKED"))
	if err != nil {
		t.Fatalf("CanonicalRoot: %v", err)
	}
	if got != locked {
		t.Fatalf("CanonicalRoot = %q, want on-disk %q", got, locked)
	}
}
