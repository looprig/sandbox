//go:build windows

package exec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// Windows exact grants require an existing object to pin. Unix intentionally
// leaves this leaf nonexistent so its nearest-existing-ancestor binding keeps
// the original ancestor-swap coverage.
func prepareGrantAncestorIdentityFixture(t *testing.T, target, replacementRoot string) {
	t.Helper()
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(replacementRoot, filepath.Base(target)), []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// replaceGrantIdentityFixture prefers a reparse-point replacement, but keeps
// identity-swap coverage mandatory on standard Windows accounts where creating
// symbolic links is not permitted. Directory junctions do not require the
// symbolic-link privilege; if the host disallows those too, a newly created
// object at the same path remains a valid, security-relevant identity swap.
func replaceGrantIdentityFixture(t *testing.T, path, replacement string) {
	t.Helper()
	if err := os.Symlink(replacement, path); err == nil {
		return
	} else {
		t.Logf("symbolic-link fixture unavailable; using Windows identity replacement: %v", err)
	}

	info, err := os.Stat(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if info.IsDir() {
		if output, junctionErr := exec.Command("cmd.exe", "/D", "/C", "mklink", "/J", path, replacement).CombinedOutput(); junctionErr == nil {
			return
		} else {
			t.Logf("junction fixture unavailable; using fresh-directory identity replacement: %v (%s)", junctionErr, output)
		}
		if err := os.Mkdir(path, 0o700); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(replacement)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				t.Fatalf("unsupported nested fallback fixture %q", entry.Name())
			}
			contents, err := os.ReadFile(filepath.Join(replacement, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(path, entry.Name()), contents, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return
	}
	if err := os.WriteFile(path, []byte("replacement identity"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// replaceGrantAncestorIdentityFixture returns false only when the retained
// no-follow Windows handle prevents the rename itself. That prevention is the
// platform's stronger control: the path remains bound to the approved object,
// and the caller must prove the still-valid grant can subsequently be used.
func replaceGrantAncestorIdentityFixture(t *testing.T, ancestor, replacement string) bool {
	t.Helper()
	if err := os.Rename(ancestor, ancestor+".old"); err != nil {
		if !errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			t.Fatal(err)
		}
		if _, statErr := os.Stat(ancestor); statErr != nil {
			t.Fatalf("ancestor disappeared despite rejected identity swap: %v", statErr)
		}
		t.Logf("Windows retained handle prevented ancestor identity replacement: %v", err)
		return false
	}
	replaceGrantIdentityFixture(t, ancestor, replacement)
	return true
}
