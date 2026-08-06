//go:build !darwin && !linux && !windows

package exec

import (
	"context"
	"errors"
	"testing"
)

// This file covers terminal_other.go's fail-closed contract: on any platform
// with no real PTY primitive wired (ttySupported == false — every platform
// except darwin/linux/windows), PrepareProcess must reject a TTY request
// outright with ErrProcessTTYUnsupported, never silently downgrading to
// pipes. Unix's own (successful) TTY behavior is covered extensively by
// process_pty_unix_test.go, and Windows's own (successful) ConPTY behavior by
// process_conpty_windows_test.go, both of which this build tag excludes.

// TestPrepareProcessRejectsTTY proves a TTY request is refused before any
// reservation is made, on a platform with no real PTY primitive at all.
func TestPrepareProcessRejectsTTY(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	if _, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableSuccessCommand(), ExecutionID: "tty-rejected", TTY: true,
	}); !errors.Is(err, ErrProcessTTYUnsupported) {
		t.Fatalf("PrepareProcess with TTY error = %v, want ErrProcessTTYUnsupported", err)
	}
}
