//go:build linux

package linux

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTouchFileAcceptsUnwritableExistingTarget pins the Rung-1 stage-2 defect:
// a bind mountpoint is never written through, so an existing target the caller
// cannot open for writing is still a perfectly good mountpoint. The mount view
// hit this on /etc/hosts beneath a writable "/" bind and aborted with EACCES,
// which reached the caller as exit code 126.
//
// A 0444 file owned by the test's own uid reproduces it exactly: O_WRONLY on
// it fails EACCES for every non-root user. The test self-skips under root,
// which bypasses the permission check and would prove nothing.
func TestTouchFileAcceptsUnwritableExistingTarget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the write-permission check this test depends on")
	}
	path := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(path, []byte("127.0.0.1 localhost\n"), 0o444); err != nil {
		t.Fatalf("seed read-only target: %v", err)
	}
	if err := touchFile(path); err != nil {
		t.Fatalf("touchFile(existing read-only target) = %v, want nil", err)
	}
}

// TestTouchFileCreatesMissingTarget keeps the original behaviour covered.
func TestTouchFileCreatesMissingTarget(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := touchFile(path); err != nil {
		t.Fatalf("touchFile(missing target) = %v, want nil", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("target not created: %v", err)
	}
}
