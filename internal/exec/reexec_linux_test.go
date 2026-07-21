//go:build linux

package exec

import "github.com/looprig/sandbox/internal/linux"

// dispatchReexec is this package's test-only equivalent of sandbox.Init(). The
// facade's Init cannot be reached from here — root imports this package, not the
// other way round — so the TestMain below calls the same underlying dispatch
// directly. On linux that is load-bearing: this test binary is re-exec'd as
// /proc/self/exe for the stage-2 helper and the namespace probe.
func dispatchReexec() { linux.Init() }
