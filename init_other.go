//go:build !linux

package sandbox

// Init is a documented no-op on every non-Linux platform (SPEC §6): there is no
// stage-2 re-exec outside Linux (darwin confines in-process via Seatbelt), so
// there is nothing to dispatch. Consumers still call it as the first line of
// main() unconditionally, so the same wiring works across platforms and Linux's
// load-bearing dispatch (init_linux.go) needs no consumer change.
func Init() {}
