//go:build !windows

package exec

import (
	"os"
	"testing"
)

func prepareGrantAncestorIdentityFixture(t *testing.T, _ string, _ string) {
	t.Helper()
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
