//go:build linux

package platform

import (
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/linux"
	"github.com/looprig/sandbox/internal/windows"
)

// Backend selects the OS enforcement backend on Linux. The selection
// itself — capability probing, rung choice, and the fail-closed refusal when
// Init() was never called — lives in internal/linux, which owns every Linux
// mechanism; this is only the seam the executor resolves through.
func Backend(options Options) (enforce.Backend, error) {
	if err := windows.ValidateConfig(options.Windows); err != nil {
		return nil, err
	}
	return linux.PlatformBackend()
}
