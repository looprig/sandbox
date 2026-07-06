// Package sandbox provides OS-level sandboxing for agent command execution.
//
// Harness's permission gates answer "may this tool call run?". This module
// answers "what can it touch once it runs?". The two compose: OS-level
// enforcement is what makes broad auto-approval safe. Concretely, it provides
// security modes, a two-axis policy model, and per-platform enforcement
// (Seatbelt on macOS; namespaces + Landlock + seccomp + nftables on Linux).
//
// # Initialization
//
// Consumers MUST call sandbox.Init() as the very first line of main():
//
//	func main() {
//		sandbox.Init()
//		// ... rest of program
//	}
//
// On Linux, Init is the load-bearing re-exec dispatch entry point: every
// sandboxed spawn re-executes /proc/self/exe as a confinement helper (the
// moby/reexec pattern), and Init catches that re-exec before main() runs. On
// other platforms it is a no-op — but call it unconditionally so the code is
// portable. If it is not called, constructing an Executor with a Linux
// enforcement backend fails closed with ErrInitNotCalled rather than running
// commands unconfined.
package sandbox
