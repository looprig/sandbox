//go:build darwin

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

// TestCanonicalPathUsesOnDiskSpelling pins H5 on the grant side: a grant
// target must canonicalize to the same spelling as a configured root, or a
// case variant of a Deny root escapes the byte-exact root comparison.
func TestCanonicalPathUsesOnDiskSpelling(t *testing.T) {
	base, err := CanonicalPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(base, "R", "secret")
	if err := os.MkdirAll(secret, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(secret, "key")
	if err := os.WriteFile(key, []byte("k"), 0o600); err != nil {
		t.Fatal(err)
	}
	locked := filepath.Join(secret, "Locked")
	if err := os.WriteFile(locked, nil, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(base, "R", "SECRET")); err != nil {
		t.Skipf("case-sensitive volume: %v", err)
	}
	for variant, want := range map[string]string{
		filepath.Join(base, "R", "SECRET", "KEY"):      key,
		filepath.Join(base, "r", "Secret", "key"):      key,
		filepath.Join(base, "R", "SECRET", "LOCKED"):   locked,
		filepath.Join(base, "R", "SECRET", "Missing"):  filepath.Join(secret, "Missing"),
		filepath.Join(base, "R", "SECRET", "New", "x"): filepath.Join(secret, "New", "x"),
		key: key,
	} {
		got, err := CanonicalPath(variant)
		if err != nil {
			t.Fatalf("CanonicalPath(%q): %v", variant, err)
		}
		if got != want {
			t.Errorf("CanonicalPath(%q) = %q, want %q", variant, got, want)
		}
	}
}
