//go:build windows

package profile

import (
	"errors"
	"testing"

	"github.com/looprig/sandbox/internal/winpath"
)

func TestWindowsCanonicalRootRejectsUnsupportedSpelling(t *testing.T) {
	for _, path := range []string{`C:relative`, `\\server\share`, `\\.\C:\`, `C:\root:stream`} {
		if _, err := CanonicalRoot(path); !errors.Is(err, winpath.ErrUnsupportedPath) {
			t.Fatalf("CanonicalRoot(%q) error = %v, want ErrUnsupportedPath", path, err)
		}
	}
}

func TestWindowsCanonicalRootReturnsHandleResolvedDOSPath(t *testing.T) {
	root := t.TempDir()
	got, err := CanonicalRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if !winpath.EqualPath(got, root) {
		t.Fatalf("CanonicalRoot(%q) = %q", root, got)
	}
}

func TestWindowsPathWithinUsesOrdinalCaseInsensitiveBoundaries(t *testing.T) {
	if !PathWithin(`c:\WORK\child`, `C:\work`) {
		t.Fatal("case variant child was not within root")
	}
	if PathWithin(`C:\workspace`, `C:\work`) {
		t.Fatal("component-prefix sibling was treated as within root")
	}
}
