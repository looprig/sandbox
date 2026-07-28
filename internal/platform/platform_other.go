//go:build !darwin && !linux && !windows

package platform

import (
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/windows"
)

// Backend selects the OS enforcement backend on every platform that is
// neither darwin (Seatbelt, platform_darwin.go) nor linux (the Landlock/namespace
// ladder, platform_linux.go). Sandboxed execution on these platforms fails
// closed. Explicit Unconfined execution bypasses this selector and uses the
// direct backend.
func Backend(options Options) (enforce.Backend, error) {
	if err := windows.ValidateConfig(options.Windows); err != nil {
		return nil, err
	}
	return nil, enforce.ErrUnavailable
}
