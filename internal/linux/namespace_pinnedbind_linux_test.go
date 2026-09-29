//go:build linux

package linux

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestReopenPinnedBindSource pins how stage 2 binds a grant-pinned root. The
// pinned descriptor belongs to the parent's mount namespace, which the kernel
// refuses to bind from inside the child's (EINVAL): every Rung-1 spawn carrying
// a filesystem grant failed with exit 126. Stage 2 re-resolves the path in its
// own namespace and binds that, but only if it is the pinned inode: a path
// swapped after pinning, or replaced by a symlink, fails closed.
func TestReopenPinnedBindSource(t *testing.T) {
	if fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC}); err != nil {
		t.Skipf("openat2 unavailable: %v", err)
	} else {
		_ = unix.Close(fd)
	}
	pin := func(t *testing.T, path string) int {
		t.Helper()
		fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = unix.Close(fd) })
		return fd
	}

	t.Run("same inode binds from a fresh descriptor", func(t *testing.T) {
		dir := t.TempDir()
		pinned := pin(t, dir)
		fd, err := reopenPinnedBindSource(pinned, dir, true)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		if fd == pinned {
			t.Fatal("returned the pinned descriptor itself; want one opened in this namespace")
		}
	})
	t.Run("swapped path fails closed", func(t *testing.T) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "ws")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		pinned := pin(t, dir)
		if err := os.Rename(dir, filepath.Join(parent, "moved")); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := reopenPinnedBindSource(pinned, dir, true); !errors.Is(err, errPinnedBindChanged) {
			t.Fatalf("err = %v, want errPinnedBindChanged", err)
		}
	})
	t.Run("symlinked path fails closed", func(t *testing.T) {
		parent := t.TempDir()
		real := filepath.Join(parent, "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		if _, err := reopenPinnedBindSource(pin(t, real), link, true); err == nil {
			t.Fatal("re-resolved through a symlink; want failure")
		}
	})
}
