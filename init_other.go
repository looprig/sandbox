//go:build !linux

package sandbox

// Init is a documented no-op on every non-Linux platform (SPEC §6): there is no
// stage-2 re-exec outside Linux (darwin confines in-process via Seatbelt), so
// there is nothing to dispatch. Consumers still call it as the first line of
// main() unconditionally, so the same wiring works across platforms and Linux's
// load-bearing dispatch (init_linux.go) needs no consumer change.
//
// This no-op says nothing about a platform's asynchronous/long-running command
// SUPERVISION capability, which is a separate contract entirely and is not
// uniform across the platforms this file covers (everything except Linux —
// not just darwin and windows, but any other GOOS this module builds for).
// On Darwin, internal/exec's PreparedProcess.Start runs every Supervised
// (async, pipe-backed) spawn: macOS has no kernel-enforced process-tree
// containment primitive available to an unentitled process, so the spawn
// instead receives a best-effort teardown prover (process-group SIGKILL plus
// process-table-closure descendant tracking), with the downgrade from a
// kernel-enforced proof reported per spawn through exec.LifetimeContainment
// (see docs/lifetime-containment.md); Seatbelt access confinement itself is
// unaffected. On Windows, Supervised spawn support is real and
// kernel-enforced through its own backend (internal/windows's Job-based
// containment). On every other GOOS this file covers — anything that is
// neither darwin, linux, nor windows — internal/exec has no process-tree
// primitive at all (process_tree_other.go's newProcessTree unconditionally
// returns enforce.ErrUnavailable): no spawn, Supervised or otherwise,
// succeeds there. A caller must not read Init's no-op as saying anything
// about any of the three.
func Init() {}
