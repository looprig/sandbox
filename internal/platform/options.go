package platform

import "github.com/looprig/sandbox/internal/windows"

// Options contains operational backend selection settings. Policy authority
// remains exclusively owned by profile.Settings.
type Options struct {
	Windows windows.Config
}
