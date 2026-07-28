//go:build linux

package exec

import (
	"os"
	"path/filepath"
	"testing"
)

// Linux exact-path grants are backed by an O_PATH descriptor and therefore
// require the approved leaf to exist. Creating both leaves lets the shared
// ancestor-swap test reach binding capture and retained-handle acquisition
// before replacing the ancestor identity.
func prepareGrantAncestorIdentityFixture(t *testing.T, target, replacementRoot string) {
	t.Helper()
	for _, path := range []string{target, filepath.Join(replacementRoot, filepath.Base(target))} {
		if err := os.WriteFile(path, []byte("identity fixture"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func replaceGrantIdentityFixture(t *testing.T, path, replacement string) {
	t.Helper()
	if err := os.Symlink(replacement, path); err != nil {
		t.Fatal(err)
	}
}

func replaceGrantAncestorIdentityFixture(t *testing.T, ancestor, replacement string) bool {
	t.Helper()
	if err := os.Rename(ancestor, ancestor+".old"); err != nil {
		t.Fatal(err)
	}
	replaceGrantIdentityFixture(t, ancestor, replacement)
	return true
}
