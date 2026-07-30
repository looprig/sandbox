//go:build !darwin

package exec

import "testing"

// requireSandboxExec is a no-op stub on non-Darwin platforms. This package's
// shared (no-OS-restriction) //go:build integration files — e.g.
// process_grant_integration_test.go — call it unconditionally alongside the
// Darwin implementation (seatbelt_enforcement_darwin_test.go, which skips
// when the sandbox-exec binary is unavailable), so without a non-Darwin
// counterpart the whole package fails to COMPILE with -tags integration on
// Linux/Windows — a pre-existing gap unrelated to Task 12b's own scope, but
// one that would otherwise block every -tags integration test in this
// package (including this microtask's new ones) from ever compiling on the
// Linux worker this microtask specifically needs to run real containment
// integration tests on. There is no Seatbelt-equivalent capability gate on
// these platforms, so this is unconditionally a no-op.
func requireSandboxExec(t *testing.T) {}
