//go:build windows

package winpath

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestWindowsNormalizeRejectsUnsupportedNamespacesAndADS(t *testing.T) {
	tests := []string{
		`C:relative`,
		`relative\path`,
		`\\server\share\x`,
		`\\.\C:\x`,
		`\\?\GLOBALROOT\Device\HarddiskVolume1\x`,
		`\\?\Volume{01234567-89ab-cdef-0123-456789abcdef}\x`,
		`C:\x:stream`,
		`C:\allowed\..\broader`,
		"C:\\x\x00tail",
	}
	for _, path := range tests {
		t.Run(path, func(t *testing.T) {
			if _, err := Normalize(path); !errors.Is(err, ErrUnsupportedPath) {
				t.Fatalf("Normalize(%q) error = %v, want ErrUnsupportedPath", path, err)
			}
		})
	}
}

func TestWindowsNormalizeUnifiesDriveAndExtendedSpellings(t *testing.T) {
	paths := []string{`C:\x`, `c:\X`, `\\?\C:\x`}
	keys := make([]string, len(paths))
	for i, path := range paths {
		normalized, err := Normalize(path)
		if err != nil {
			t.Fatalf("Normalize(%q): %v", path, err)
		}
		keys[i] = normalized
	}
	if !EqualPath(keys[0], keys[1]) || !EqualPath(keys[0], keys[2]) {
		t.Fatalf("normalized paths are not ordinal-case equal: %#v", keys)
	}
}

func TestWindowsOpenCapturesCompleteLocalIdentity(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "identity.txt")
	if err := os.WriteFile(file, []byte("identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	object, err := Open(file)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer object.Close()
	if object.Handle == 0 || object.Handle == windows.InvalidHandle {
		t.Fatal("Open returned no owned handle")
	}
	if object.DOSPath == "" || object.PathKey == "" || object.VolumeSerial == 0 || object.FileID == ([16]byte{}) {
		t.Fatalf("incomplete identity: %+v", object)
	}
	if object.Kind != KindFile || object.ReparseTag != 0 || object.LinkCount < 1 {
		t.Fatalf("unexpected file metadata: %+v", object)
	}

	directory, err := Open(root)
	if err != nil {
		t.Fatalf("Open directory: %v", err)
	}
	defer directory.Close()
	if directory.Kind != KindDirectory {
		t.Fatalf("directory kind = %v, want KindDirectory", directory.Kind)
	}
}

func TestWindowsOpenResolvesShortAliasToSameIdentity(t *testing.T) {
	root := t.TempDir()
	long := filepath.Join(root, "long filename for identity.txt")
	if err := os.WriteFile(long, []byte("alias"), 0o600); err != nil {
		t.Fatal(err)
	}
	short, err := shortPathName(long)
	if err != nil || EqualPath(short, long) {
		t.Skip("8.3 aliases are unavailable on this volume")
	}
	left, err := Open(long)
	if err != nil {
		t.Fatal(err)
	}
	defer left.Close()
	right, err := Open(short)
	if err != nil {
		t.Fatal(err)
	}
	defer right.Close()
	if !left.SameIdentity(right) || !EqualPath(left.PathKey, right.PathKey) {
		t.Fatalf("short alias did not converge: long=%+v short=%+v", left, right)
	}
}

func shortPathName(path string) (string, error) {
	input, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	buffer := make([]uint16, windows.MAX_PATH)
	n, err := windows.GetShortPathName(input, &buffer[0], uint32(len(buffer)))
	if err != nil {
		return "", err
	}
	if n >= uint32(len(buffer)) {
		buffer = make([]uint16, n+1)
		n, err = windows.GetShortPathName(input, &buffer[0], uint32(len(buffer)))
		if err != nil {
			return "", err
		}
	}
	return windows.UTF16ToString(buffer[:n]), nil
}

func TestWindowsOpenDoesNotFollowLeafReparsePoint(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	link := filepath.Join(root, "link.txt")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("creating symlink requires Windows developer mode or privilege: %v", err)
	}
	object, err := Open(link)
	if err != nil {
		t.Fatalf("Open symlink: %v", err)
	}
	defer object.Close()
	if object.ReparseTag != windows.IO_REPARSE_TAG_SYMLINK {
		t.Fatalf("reparse tag = %#x, want symlink %#x", object.ReparseTag, windows.IO_REPARSE_TAG_SYMLINK)
	}
	if object.Kind != KindReparsePoint {
		t.Fatalf("kind = %v, want KindReparsePoint", object.Kind)
	}
}

func TestWindowsOpenPinnedBlocksRootSwapUntilClose(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "pinned.txt")
	if err := os.WriteFile(file, []byte("pinned"), 0o600); err != nil {
		t.Fatal(err)
	}
	object, err := OpenPinned(file)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(root, "moved.txt")
	if err := os.Rename(file, moved); err == nil {
		object.Close()
		t.Fatal("rename succeeded while a no-delete-sharing identity handle was retained")
	}
	if err := object.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(file, moved); err != nil {
		t.Fatalf("rename after Close: %v", err)
	}
}
