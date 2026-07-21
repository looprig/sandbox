//go:build !darwin && !linux

package platform

import (
	"github.com/looprig/sandbox/internal/enforce"
)

// Backend selects the OS enforcement backend on every platform that is
// neither darwin (Seatbelt, platform_darwin.go) nor linux (the Landlock/namespace
// ladder, platform_linux.go). Sandboxed execution on these platforms fails
// closed. Explicit Unconfined execution bypasses this selector and uses the
// direct backend.
func Backend() (enforce.Backend, error) { return nil, enforce.ErrUnavailable }
