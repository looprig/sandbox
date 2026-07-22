package platform

import "github.com/looprig/sandbox/internal/windows"

// Options contains operational backend selection settings. Policy authority
// remains exclusively owned by profile.Settings.
type Options struct {
	Windows windows.Config
	// WindowsRestrictedRuntime is shared by every backend selected for one
	// ExecutorSet. It is deliberately separate from the elevated installation's
	// Windows.StateRoot.
	WindowsRestrictedRuntime *windows.RestrictedRuntime
}
