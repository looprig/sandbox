//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOpenEmptyMaskSource pins how file masks get their empty source. It is
// created on the bare new root BEFORE any bind (a "/" read bind would shadow
// that path and make it read-only) and handed out as a /proc/self/fd path, so
// it stays reachable once its pathname is gone. Directory-only masks create
// nothing.
func TestOpenEmptyMaskSource(t *testing.T) {
	t.Run("directory masks need no source", func(t *testing.T) {
		root := t.TempDir()
		source, closeSource, err := openEmptyMaskSource(root, []MaskSpec{{Target: "/secret", IsDir: true}})
		if err != nil {
			t.Fatal(err)
		}
		defer closeSource()
		if source != "" {
			t.Fatalf("source = %q, want none for directory-only masks", source)
		}
		if _, err := os.Lstat(filepath.Join(root, emptyMaskFile)); !os.IsNotExist(err) {
			t.Fatalf("empty mask file created without a file mask: %v", err)
		}
	})
	t.Run("file mask source survives losing its path", func(t *testing.T) {
		root := t.TempDir()
		source, closeSource, err := openEmptyMaskSource(root, []MaskSpec{{Target: "/dir", IsDir: true}, {Target: "/.env"}})
		if err != nil {
			t.Fatal(err)
		}
		defer closeSource()
		if !strings.HasPrefix(source, "/proc/self/fd/") {
			t.Fatalf("source = %q, want a /proc/self/fd path", source)
		}
		// Stand-in for a later bind shadowing the new root's path.
		if err := os.Rename(filepath.Join(root, emptyMaskFile), filepath.Join(t.TempDir(), "moved")); err != nil {
			t.Fatal(err)
		}
		st, err := os.Stat(source)
		if err != nil {
			t.Fatalf("source unreachable after its path moved: %v", err)
		}
		if !st.Mode().IsRegular() || st.Size() != 0 {
			t.Fatalf("source = %v size %d, want an empty regular file", st.Mode(), st.Size())
		}
	})
}
