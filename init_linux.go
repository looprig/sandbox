//go:build linux

package sandbox

import "github.com/looprig/sandbox/internal/linux"

// Init is the re-exec dispatch entry point (SPEC §6). Consumers MUST call it as
// the very first line of main(), before any goroutine, file descriptor, or
// thread state is established:
//
//	func main() {
//		sandbox.Init()
//		// ... rest of program
//	}
//
// On Linux it inspects the reserved re-exec sentinels and dispatches a stage-2
// helper or namespace-probe child (the moby/reexec pattern, §7.2); in a normal
// process it records that it ran and returns immediately. The mechanism lives in
// internal/linux; Init stays at the root import path because that is where every
// consumer's main() calls it.
func Init() { linux.Init() }
