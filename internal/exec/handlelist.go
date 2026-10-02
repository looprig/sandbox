package exec

import "sync"

// configureChildHandleList narrows the handles a spawn's child inherits and
// returns the cleanup that releases whatever parent-side duplicates the
// narrowing created (platformConfigureChildHandleList: a no-op off Windows,
// the explicit Windows handle list on Windows). It is a variable only so a
// test can substitute a configurator with the Windows duplicate-owning shape
// on any host (executor_handlelist_drain_unix_test.go).
var configureChildHandleList = platformConfigureChildHandleList

// releaseChildHandleList adapts a configureChildHandleList cleanup into the
// idempotent closure every spawn path calls twice: once immediately after
// Start returns — success or failure — and once more, as a no-op safety net,
// from spawn cleanup.
//
// The early call is the load-bearing one. On Windows the configurator
// replaces cmd.Stdout/cmd.Stderr (and cmd.Stdin) with least-access duplicates
// the PARENT owns, and syscall.StartProcess has already handed the child its
// own inheritable copies by the time Start returns. A parent-held duplicate
// of an output pipe's write end that survives Start is one more writer the
// reader must wait out: the drain can never observe EOF while it is open.
// Deferring the cleanup to spawn release — which itself waits for the drain —
// made every synchronous Windows run wait out outputDrainGrace and then
// report a truncation that never happened (first Windows CI run, 2026-10-02).
func releaseChildHandleList(cleanup func()) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			if cleanup != nil {
				cleanup()
			}
		})
	}
}
