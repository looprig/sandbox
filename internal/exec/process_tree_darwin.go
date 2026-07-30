//go:build darwin

package exec

import (
	"os/exec"
	"reflect"

	"github.com/looprig/sandbox/internal/darwin"
	"github.com/looprig/sandbox/internal/enforce"
)

// darwinBackendType identifies the real, production Seatbelt-backed
// enforce.Backend darwin.NewBackend() returns (internal/darwin's
// seatbeltBackend is unexported, so a reflect.TypeOf comparison is the same
// idiom internal/platform's own darwin backend-selection test already uses
// across this package boundary — see platform_darwin_test.go).
var darwinBackendType = reflect.TypeOf(darwin.NewBackend())

// attachSupervisedProof is Darwin's fail-closed counterpart to
// process_tree_linux.go (SPEC Task 12b is Linux-only containment scope; this
// is Task 12c). newProcessTree (process_tree_unix.go) calls it only when
// options.Supervised is true — a PreparedProcess.Start (asynchronous,
// pipe-backed) spawn, never the synchronous RunCommand/RunArgv path — because
// only a Supervised spawn requires the mandatory exact process-tree teardown
// proof enforce.ErrLifetimeContainmentUnavailable's doc describes: a
// process-group signal plus best-effort polling (this type's own
// terminateAndWait fallback when tree.proof is nil) is not sufficient
// evidence, since a setsid or double-forked descendant escapes it undetected.
//
// The rejection is scoped to the REAL Seatbelt backend only, exactly
// mirroring process_tree_linux.go's own scoping (which only rejects for a
// genuine *linux.Backend, never for enforce.NewNull() or a test double
// pinned through withBackend): an Unconfined executor or a test that pins a
// fake enforce.Backend is not claiming Darwin OS-level confinement at all, so
// it is not this contract's concern and is left exactly as it behaved before
// this microtask — only a spawn actually compiled through darwin.NewBackend()
// is asserting Seatbelt confinement, and that is precisely the case with no
// kernel-enforced lifetime mechanism wired yet.
//
// No kernel-enforced mechanism is wired for Darwin yet — a real one is a
// separately specified, later concrete containment primitive, deliberately
// out of this microtask's scope ("do not add a success path until a
// separately specified concrete containment primitive exists") — so this
// rejects every Supervised Seatbelt spawn unconditionally, exactly mirroring
// Linux's Rung-2-with-no-delegated-cgroup case (process_tree_linux.go).
// newProcessTree propagates the error straight back to its caller
// (PreparedProcess.startConfined, process.go) before cmd.Start() is ever
// reached, so no child process is created — satisfying the plan's literal
// requirement to return lifetime_enforcement_unavailable "before spawn."
func attachSupervisedProof(cmd *exec.Cmd, options processTreeOptions) (zeroProver, error) {
	if options.Backend == nil || reflect.TypeOf(options.Backend) != darwinBackendType {
		return nil, nil
	}
	return nil, enforce.ErrLifetimeContainmentUnavailable
}
