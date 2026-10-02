//go:build linux

package linux

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// TestViewRootTargetsNeverLeaveTheNewRoot pins review L10 at the resolver: the
// Rung-1 mount view resolves every mountpoint INSIDE the new root by
// descriptor. The previous code joined newroot with the target and let
// os.MkdirAll / mount(2) follow the host path string, so an absolute symlink
// planted in a writable tree led mountpoint creation (and the mount) out to
// the host. It needs only openat2, no namespace, so it runs on every Linux
// host.
//
// The fixture is a stand-in new root holding a "workspace" with a planted
// absolute symlink to a real host directory outside the root.
func TestViewRootTargetsNeverLeaveTheNewRoot(t *testing.T) {
	newroot := t.TempDir()
	host := t.TempDir() // the host directory the planted link aims at
	ws := filepath.Join(newroot, "ws")
	if err := os.Mkdir(ws, 0o755); err != nil {
		t.Fatalf("mkdir ws: %v", err)
	}
	if err := os.Symlink(host, filepath.Join(ws, "link")); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}
	if err := os.Symlink("../../../../../../..", filepath.Join(ws, "up")); err != nil {
		t.Fatalf("plant dot-dot symlink: %v", err)
	}
	root, err := openViewRoot(newroot)
	if err != nil {
		t.Fatalf("openViewRoot: %v", err)
	}
	defer root.close()
	assertHostUntouched := func(t *testing.T) {
		t.Helper()
		entries, err := os.ReadDir(host)
		if err != nil {
			t.Fatalf("read host dir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("a mountpoint was created on the host through the planted link: %v", entries)
		}
	}

	t.Run("beneath a writable bind a symlinked component fails closed", func(t *testing.T) {
		root.writable = []string{"/ws"}
		defer func() { root.writable = nil }()
		for _, kind := range []mountpointKind{mountpointDir, mountpointFile} {
			fd, err := root.openTarget("/ws/link/carveout", kind)
			if err == nil {
				_ = unix.Close(fd)
				t.Fatalf("kind %d: openTarget through a planted link beneath a writable bind succeeded", kind)
			}
			if !errors.Is(err, unix.ELOOP) {
				t.Errorf("kind %d: openTarget error = %v, want ELOOP", kind, err)
			}
		}
		assertHostUntouched(t)
	})

	t.Run("elsewhere a link resolves inside the new root, never on the host", func(t *testing.T) {
		// The link's target does not exist INSIDE the new root: the walk
		// fails closed rather than creating through the link (mkdirat sees
		// the link itself, EEXIST, and the re-resolution is still absent).
		if fd, err := root.openTarget("/ws/link/carveout", mountpointDir); err == nil {
			_ = unix.Close(fd)
			t.Fatal("openTarget created through a link whose in-root target is absent")
		}
		assertHostUntouched(t)
		// Once the in-root counterpart exists, the absolute link resolves to
		// it — relative to the new root — and the mountpoint is made there.
		if err := os.MkdirAll(filepath.Join(newroot, host), 0o755); err != nil {
			t.Fatalf("mkdir in-root counterpart: %v", err)
		}
		fd, err := root.openTarget("/ws/link/carveout", mountpointDir)
		if err != nil {
			t.Fatalf("openTarget (IN_ROOT): %v", err)
		}
		_ = unix.Close(fd)
		assertHostUntouched(t)
		// The absolute link target was interpreted relative to the new root.
		if st, err := os.Stat(filepath.Join(newroot, host, "carveout")); err != nil || !st.IsDir() {
			t.Fatalf("mountpoint not created at <newroot>%s/carveout: %v", host, err)
		}
	})

	t.Run("dot-dot is clamped at the new root", func(t *testing.T) {
		fd, err := root.openTarget("/ws/up/clamped", mountpointFile)
		if err != nil {
			t.Fatalf("openTarget via ..: %v", err)
		}
		_ = unix.Close(fd)
		if _, err := os.Stat(filepath.Join(newroot, "clamped")); err != nil {
			t.Fatalf("a ..-escaping link was not clamped to the new root: %v", err)
		}
	})

	t.Run("a lookup-only target outside the view is absent", func(t *testing.T) {
		fd, err := root.openTargetResolve("/ws/link/never", mountpointNone, unix.RESOLVE_IN_ROOT|unix.RESOLVE_NO_MAGICLINKS)
		if err == nil {
			_ = unix.Close(fd)
			t.Fatal("lookup-only openTarget created or found a target it should not")
		}
		if !errors.Is(err, unix.ENOENT) {
			t.Fatalf("lookup-only error = %v, want ENOENT", err)
		}
		assertHostUntouched(t)
	})
}
