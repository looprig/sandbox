// Package sandbox provides standalone OS-level confinement for command
// execution under immutable, consumer-defined access profiles.
//
// Harness's permission gates answer "may this tool call run?". This module
// answers "what can it touch once it runs?". The two compose: OS-level
// enforcement is what makes approved authority meaningful. Concretely, it
// provides immutable consumer-defined access profiles, single-spawn
// post-decision grants, honest achieved guarantees, and per-platform enforcement
// (Seatbelt on macOS; namespaces + Landlock + seccomp + nftables on Linux;
// restricted-token and installed-broker tiers on Windows). It does not import
// an approval system or read permission files. The Windows elevated tier
// remains unavailable until setup inspection can verify approved live runtime
// evidence from supported Windows 11 and Windows Server workers.
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
// commands unconfined. A sandboxed profile also fails closed with
// enforce.ErrUnavailable on a host without a production backend; direct
// execution exists only for an explicitly acknowledged Unconfined profile.
package sandbox
