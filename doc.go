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
// Init is a no-op stub today, but it becomes load-bearing on Linux, where the
// sandbox must re-exec or reconfigure the process before any other goroutine,
// file descriptor, or thread state is established. Wiring the call from day one
// means consumers do not have to retrofit it when the Linux enforcement lands.
package sandbox
