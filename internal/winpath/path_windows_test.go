//go:build windows

package winpath

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
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

func TestWindowsCompareUsesOrdinalUTF16Ordering(t *testing.T) {
	if got := Compare(`C:\x`, `c:\X`); got != 0 {
		t.Fatalf("case-insensitive Compare = %d, want 0", got)
	}
	// CompareStringOrdinal orders UTF-16 code units. A supplementary-plane
	// character starts with a surrogate below U+E000, which is the opposite of
	// Go's UTF-8 string ordering and catches strings.ToUpper(a) < strings.ToUpper(b).
	if got := Compare("C:\\"+string(rune(0x10000)), "C:\\"+string(rune(0xe000))); got >= 0 {
		t.Fatalf("supplementary/BMP ordinal Compare = %d, want negative", got)
	}
	if got := Compare(`C:\b`, `C:\a`); got <= 0 {
		t.Fatalf("descending Compare = %d, want positive", got)
	}
}

func TestWindowsVolumeMountRootsIncludeDirectoryOnlyVolumesAndDedupeIdentity(t *testing.T) {
	got := selectVolumeMountRoots([]enumeratedVolume{
		{identity: "volume-b", paths: []string{`C:\mounts\data\`}},
		{identity: "volume-a", paths: []string{`C:\mounts\system\`, `D:\`}},
		{identity: "volume-a", paths: []string{`d:\`}},
		{identity: "volume-c", paths: []string{`Z:\`, `z:\`}},
	})
	want := []string{`C:\mounts\data`, `D:\`, `Z:\`}
	if len(got) != len(want) {
		t.Fatalf("roots = %q, want %q", got, want)
	}
	for i := range want {
		if !EqualPath(got[i], want[i]) {
			t.Fatalf("roots[%d] = %q, want %q", i, got[i], want[i])
		}
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

func TestWindowsOpenRejectsLeafReparsePoint(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	link := filepath.Join(root, "link.txt")
	if err := os.WriteFile(target, []byte("target"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("creating symlink requires Windows developer mode or privilege: %v", err)
	}
	if _, err := Open(link); !errors.Is(err, ErrUnsupportedPath) {
		t.Fatalf("Open symlink error = %v, want ErrUnsupportedPath", err)
	}
}

func TestWindowsComponentWalkRetainsParentsAndUsesRelativeNames(t *testing.T) {
	var roots []string
	var relatives []string
	var closed []windows.Handle
	handles, err := walkPathComponents(`C:\one\two\leaf`, windows.FILE_SHARE_READ,
		func(root string, _ uint32) (windows.Handle, error) {
			roots = append(roots, root)
			return 1, nil
		},
		func(parent windows.Handle, name string, directory bool, _ uint32) (windows.Handle, error) {
			relatives = append(relatives, name)
			if want := windows.Handle(len(relatives)); parent != want {
				t.Fatalf("relative parent = %d, want %d", parent, want)
			}
			if directory != (name != "leaf") {
				t.Fatalf("relative %q directory = %t", name, directory)
			}
			return parent + 1, nil
		},
		func(windows.Handle) (bool, error) { return false, nil },
		func(handle windows.Handle) error { closed = append(closed, handle); return nil },
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := roots, []string{`C:\`}; !slices.Equal(got, want) {
		t.Fatalf("roots = %q, want %q", got, want)
	}
	if got, want := relatives, []string{"one", "two", "leaf"}; !slices.Equal(got, want) {
		t.Fatalf("relative opens = %q, want %q", got, want)
	}
	if len(handles) != 4 || len(closed) != 0 {
		t.Fatalf("handles=%v closed=%v, want retained chain", handles, closed)
	}
}

func TestWindowsComponentWalkClosesChainWhenReparseAppears(t *testing.T) {
	var closed []windows.Handle
	_, err := walkPathComponents(`C:\one\junction\leaf`, windows.FILE_SHARE_READ,
		func(string, uint32) (windows.Handle, error) { return 1, nil },
		func(parent windows.Handle, _ string, _ bool, _ uint32) (windows.Handle, error) {
			return parent + 1, nil
		},
		func(handle windows.Handle) (bool, error) { return handle == 3, nil },
		func(handle windows.Handle) error { closed = append(closed, handle); return nil },
	)
	if !errors.Is(err, ErrUnsupportedPath) {
		t.Fatalf("walk error = %v, want ErrUnsupportedPath", err)
	}
	if got, want := closed, []windows.Handle{3, 2, 1}; !slices.Equal(got, want) {
		t.Fatalf("closed handles = %v, want %v", got, want)
	}
}

func TestWindowsOpenNeverEscapesDuringConcurrentSymlinkSwap(t *testing.T) {
	parent := t.TempDir()
	safe := filepath.Join(parent, "slot")
	held := filepath.Join(parent, "held")
	outside := filepath.Join(parent, "outside")
	if err := os.Mkdir(safe, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(safe, "leaf"), []byte("safe"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "leaf"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(parent, "probe-link")
	if err := os.Symlink(outside, probe); err != nil {
		t.Skipf("directory symlink privilege unavailable: %v", err)
	}
	if err := os.Remove(probe); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			if os.Rename(safe, held) == nil {
				if os.Symlink(outside, safe) == nil {
					_ = os.Remove(safe)
				}
				_ = os.Rename(held, safe)
			}
		}
	}()
	for range 500 {
		object, err := Open(filepath.Join(safe, "leaf"))
		if err != nil {
			continue
		}
		if strings.Contains(strings.ToLower(object.DOSPath), `\outside\`) {
			object.Close()
			close(stop)
			<-done
			t.Fatalf("walk escaped requested namespace: %q", object.DOSPath)
		}
		_ = object.Close()
	}
	close(stop)
	<-done
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
