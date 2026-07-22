//go:build windows

package platform

import (
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/windows"
)

var windowsPlatformBackend = windows.PlatformBackend

// Backend delegates Windows mechanism selection to the package that owns it.
func Backend(options Options) (enforce.Backend, error) {
	return windowsPlatformBackend(options.Windows, options.ScratchRoot)
}
