//go:build windows

package policy

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWindowsPathBindingRejectsRootSwap(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	binding, err := CapturePathBinding(root)
	if err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(parent, "moved")
	if err := os.Rename(root, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RevalidatePathBinding(&binding, binding.CanonicalPath); !errors.Is(err, ErrTargetChanged) {
		t.Fatalf("RevalidatePathBinding after root swap = %v, want ErrTargetChanged", err)
	}
}

func TestWindowsPathBindingRejectsJunctionRoot(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	junction := filepath.Join(parent, "junction")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("cmd.exe", "/D", "/C", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Skipf("creating junction failed: %v (%s)", err, output)
	}
	if _, err := CapturePathBinding(junction); !errors.Is(err, ErrUnsupportedClass) {
		t.Fatalf("CapturePathBinding(junction) = %v, want ErrUnsupportedClass", err)
	}
}

func TestWindowsExactPathHandleRejectsMultipleLinks(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "file.txt")
	alias := filepath.Join(root, "alias.txt")
	if err := os.WriteFile(file, []byte("hard link"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(file, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	binding, err := CapturePathBinding(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquirePathHandle(&binding, binding.CanonicalPath, true); !errors.Is(err, ErrUnsupportedClass) {
		t.Fatalf("AcquirePathHandle(multi-link file) = %v, want ErrUnsupportedClass", err)
	}
}

func TestWindowsPathHandleOwnsNoFollowIdentity(t *testing.T) {
	root := t.TempDir()
	binding, err := CapturePathBinding(root)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := AcquirePathHandle(&binding, binding.CanonicalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	if handle == nil || handle.identity == "" || !handle.IsDir() {
		t.Fatalf("incomplete path handle: %#v", handle)
	}
	if err := handle.Close(); err != nil {
		t.Fatal(err)
	}
	if err := handle.Close(); err != nil {
		t.Fatalf("Close is not idempotent: %v", err)
	}
}

func TestWindowsPathBindingRejectsSymlinkAndJunctionRoots(t *testing.T) {
	parent := t.TempDir()
	target := filepath.Join(parent, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(parent, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("creating directory symlink/junction requires privilege: %v", err)
	}
	if _, err := CapturePathBinding(link); !errors.Is(err, ErrUnsupportedClass) {
		t.Fatalf("CapturePathBinding(reparse root) = %v, want ErrUnsupportedClass", err)
	}
}
