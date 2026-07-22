package platform

import "github.com/looprig/sandbox/internal/windows"

// Options contains operational backend selection settings. Policy authority
// remains exclusively owned by profile.Settings.
type Options struct {
	Windows windows.Config
	// ScratchRoot is the caller-owned stable root for backend crash-recovery
	// state. It is deliberately separate from the elevated installation's
	// Windows.StateRoot.
	ScratchRoot string
}
