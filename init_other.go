//go:build !linux

package sandbox

// Init is a documented no-op on every non-Linux platform (SPEC §6): there is no
// stage-2 re-exec outside Linux (darwin confines in-process via Seatbelt), so
// there is nothing to dispatch. Consumers still call it as the first line of
// main() unconditionally, so the same wiring works across platforms and Linux's
// load-bearing dispatch (init_linux.go) needs no consumer change.
//
// This no-op says nothing about a platform's asynchronous/long-running command
// SUPERVISION capability, which is a separate contract entirely: on Darwin,
// internal/exec's PreparedProcess.Start rejects every Supervised (async,
// pipe-backed) spawn before it starts with
// enforce.ErrLifetimeContainmentUnavailable, because no kernel-enforced
// process-tree containment mechanism is wired for this platform yet (Task
// 12c). A caller must not read Init's no-op as evidence that async execution
// is fully supported here.
func Init() {}
