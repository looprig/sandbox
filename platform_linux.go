//go:build linux

package sandbox

import (
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/linux"
)

// platformBackend selects the OS enforcement backend on Linux. The selection
// itself — capability probing, rung choice, and the fail-closed refusal when
// Init() was never called — lives in internal/linux, which owns every Linux
// mechanism; this is only the seam the executor resolves through.
func platformBackend() (enforce.Backend, error) { return linux.PlatformBackend() }
