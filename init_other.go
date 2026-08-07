//go:build !linux

package sandbox

// Init is a documented no-op on every non-Linux platform (SPEC §6): there is no
// stage-2 re-exec outside Linux (darwin confines in-process via Seatbelt), so
// there is nothing to dispatch. Consumers still call it as the first line of
// main() unconditionally, so the same wiring works across platforms and Linux's
// load-bearing dispatch (init_linux.go) needs no consumer change.
//
// This no-op says nothing about a platform's asynchronous/long-running command
// SUPERVISION capability, which is a separate contract entirely and differs
// between the two platforms this file covers. On Darwin, internal/exec's
// PreparedProcess.Start runs every Supervised (async, pipe-backed) spawn:
// macOS has no kernel-enforced process-tree containment primitive available
// to an unentitled process, so the spawn instead receives a best-effort
// teardown prover (process-group SIGKILL plus process-table-closure
// descendant tracking), with the downgrade from a kernel-enforced proof
// reported per spawn through exec.LifetimeContainment (see
// docs/lifetime-containment.md); Seatbelt access confinement itself is
// unaffected. On every other non-Linux platform this file covers, Supervised
// spawn support depends on whatever that platform's own backend wires (e.g.
// Windows's Job-based kernel-enforced containment, internal/windows). A
// caller must not read Init's no-op as saying anything about either.
func Init() {}
