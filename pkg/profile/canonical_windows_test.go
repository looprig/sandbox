//go:build windows

package profile

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/looprig/sandbox/internal/winpath"
	"golang.org/x/sys/windows"
)

func TestWindowsCanonicalRootRejectsUnsupportedSpelling(t *testing.T) {
	for _, path := range []string{`C:relative`, `\\server\share`, `\\.\C:\`, `C:\root:stream`, `C:\root\.`} {
		if _, err := CanonicalRoot(path); !errors.Is(err, winpath.ErrUnsupportedPath) {
			t.Fatalf("CanonicalRoot(%q) error = %v, want ErrUnsupportedPath", path, err)
		}
	}
}

// TestWindowsCanonicalRootReturnsHandleResolvedDOSPath pins that the root is
// the DOS path of the opened handle (design §10.1, identity by handle), NOT
// the caller's spelling echoed back. The two differ whenever the input carries
// an 8.3 short-name component: a GitHub-hosted runner's %TEMP% is
// C:\Users\RUNNER~1\..., and the handle names C:\Users\runneradmin\....
// The oracle is therefore GetLongPathNameW of the input — a path-based Win32
// expansion independent of the handle query CanonicalRoot uses — rather than
// the input itself, which was only ever correct on a long-named temp dir.
func TestWindowsCanonicalRootReturnsHandleResolvedDOSPath(t *testing.T) {
	root := t.TempDir()
	got, err := CanonicalRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := longPathName(t, root); !winpath.EqualPath(got, want) {
		t.Fatalf("CanonicalRoot(%q) = %q, want the long-name spelling %q", root, got, want)
	}
}

// TestWindowsCanonicalRootExpandsShortNameSpelling proves the case the hosted
// runner hit by accident, on purpose: a root named through its 8.3 alias
// canonicalizes to the long name, so a profile built from either spelling
// stores — and fingerprints — one path. Without it a policy entry keyed by
// the short spelling would never match the long spelling a handle-resolved
// probe reports (ResolveFS is lexical and cannot expand 8.3 names itself).
func TestWindowsCanonicalRootExpandsShortNameSpelling(t *testing.T) {
	long := filepath.Join(t.TempDir(), "a long directory name for 8dot3")
	if err := os.Mkdir(long, 0o700); err != nil {
		t.Fatal(err)
	}
	short := shortPathName(t, long)
	if winpath.EqualPath(filepath.Base(short), filepath.Base(long)) {
		// GetShortPathNameW returns the long component unchanged when the
		// volume does not generate 8.3 names (fsutil 8dot3name, the default
		// on non-system NTFS volumes and on ReFS); there is then no short
		// spelling to canonicalize and the property is not observable here.
		t.Skipf("volume holding %q generates no 8.3 alias (GetShortPathNameW = %q); short-name canonicalization is not observable on it", long, short)
	}
	wantLong, err := CanonicalRoot(long)
	if err != nil {
		t.Fatal(err)
	}
	got, err := CanonicalRoot(short)
	if err != nil {
		t.Fatalf("CanonicalRoot(short %q): %v", short, err)
	}
	if !winpath.EqualPath(got, wantLong) {
		t.Fatalf("CanonicalRoot(short %q) = %q, want the long-name root %q", short, got, wantLong)
	}
	if !winpath.EqualPath(filepath.Base(got), filepath.Base(long)) {
		t.Fatalf("CanonicalRoot(short %q) = %q, want final component %q", short, got, filepath.Base(long))
	}
}

func longPathName(t *testing.T, path string) string {
	t.Helper()
	return win32PathName(t, "GetLongPathNameW", path, windows.GetLongPathName)
}

func shortPathName(t *testing.T, path string) string {
	t.Helper()
	return win32PathName(t, "GetShortPathNameW", path, windows.GetShortPathName)
}

// win32PathName runs a GetLong/ShortPathNameW-shaped call with the usual
// size-then-fill protocol, failing if the name changes between the calls.
func win32PathName(t *testing.T, name, path string, call func(*uint16, *uint16, uint32) (uint32, error)) string {
	t.Helper()
	input, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	size, err := call(input, nil, 0)
	if size == 0 {
		t.Fatalf("%s(%q) size: %v", name, path, err)
	}
	buffer := make([]uint16, size)
	n, err := call(input, &buffer[0], uint32(len(buffer)))
	if n == 0 || n >= uint32(len(buffer)) {
		t.Fatalf("%s(%q) = %d of %d: %v", name, path, n, len(buffer), err)
	}
	return windows.UTF16ToString(buffer[:n])
}

func TestWindowsPathWithinUsesOrdinalCaseInsensitiveBoundaries(t *testing.T) {
	if !PathWithin(`c:\WORK\child`, `C:\work`) {
		t.Fatal("case variant child was not within root")
	}
	if PathWithin(`C:\workspace`, `C:\work`) {
		t.Fatal("component-prefix sibling was treated as within root")
	}
}

func TestWindowsCanonicalPathLessUsesOrdinalUTF16Ordering(t *testing.T) {
	if !canonicalPathLess("C:\\"+string(rune(0x10000)), "C:\\"+string(rune(0xe000))) {
		t.Fatal("canonical path ordering is not Windows ordinal UTF-16 ordering")
	}
}
