//go:build darwin

package exec

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/looprig/sandbox/internal/darwin"
	"github.com/looprig/sandbox/internal/enforce"
)

// TestDarwinLifetimeCapabilityFailsClosed is Task 12c's queued phase-gate
// selector test: it proves the Darwin fail-closed CONTAINMENT DECISION itself
// — a Supervised spawn compiled through the real Seatbelt backend
// (darwin.NewBackend()) is rejected with
// enforce.ErrLifetimeContainmentUnavailable before any OS process is ever
// created, a Supervised spawn NOT claiming real Seatbelt confinement (a nil
// backend, or a test double pinned through withBackend, exactly like
// enforce.NewNull()'s Unconfined path) is completely unaffected, and a
// non-Supervised (synchronous RunCommand/RunArgv) spawn is unaffected
// regardless of backend — mirroring process_tree_linux_test.go's
// TestProcessTreeLinuxContainmentPlan. It exercises attachSupervisedProof and
// newProcessTree directly (the exact functions a Supervised spawn's
// process.go/startConfined path calls) so the contract can be asserted
// without spawning a real process or depending on the integration-tagged
// escape proof in process_parent_death_integration_unix_test.go.
func TestDarwinLifetimeCapabilityFailsClosed(t *testing.T) {
	t.Run("a Supervised spawn through the real Seatbelt backend rejects unconditionally, attaching no proof", func(t *testing.T) {
		cmd := exec.Command("true")
		proof, err := attachSupervisedProof(cmd, processTreeOptions{Supervised: true, Backend: darwin.NewBackend()})
		if err == nil {
			t.Fatal("attachSupervisedProof succeeded on darwin; want a fail-closed error (no containment primitive exists yet)")
		}
		if proof != nil {
			t.Fatalf("attachSupervisedProof returned a non-nil proof alongside an error: %v", proof)
		}
		if !errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Errorf("error = %v, want it to wrap enforce.ErrLifetimeContainmentUnavailable", err)
		}
		if cmd.Process != nil {
			t.Fatal("attachSupervisedProof must never itself spawn a process")
		}
	})

	t.Run("newProcessTree propagates the rejection before cmd.Start is ever reached", func(t *testing.T) {
		cmd := exec.Command("true")
		tree, err := newProcessTree(cmd, processTreeOptions{Supervised: true, Backend: darwin.NewBackend()})
		if !errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Fatalf("newProcessTree error = %v, want it to wrap enforce.ErrLifetimeContainmentUnavailable", err)
		}
		if tree != nil {
			t.Fatalf("newProcessTree returned a non-nil tree alongside a fail-closed error: %v", tree)
		}
		// newProcessTree only ever wires cmd.Cancel / SysProcAttr.Setpgid ahead
		// of the containment decision; it never calls cmd.Start. Process being
		// nil is the direct proof no child was created by this call.
		if cmd.Process != nil {
			t.Fatal("a rejected containment plan must never result in a spawned process")
		}
	})

	t.Run("a Supervised spawn NOT claiming real Seatbelt confinement is unaffected", func(t *testing.T) {
		cmd := exec.Command("true")
		proof, err := attachSupervisedProof(cmd, processTreeOptions{Supervised: true, Backend: enforce.NewNull()})
		if err != nil {
			t.Fatalf("attachSupervisedProof (non-Seatbelt backend) = %v, want nil error: an Unconfined/test-double spawn is not claiming Darwin OS confinement", err)
		}
		if proof != nil {
			t.Fatalf("attachSupervisedProof (non-Seatbelt backend) returned a proof %T; want nil", proof)
		}
	})

	t.Run("a nil backend attaches no containment claim", func(t *testing.T) {
		cmd := exec.Command("true")
		proof, err := attachSupervisedProof(cmd, processTreeOptions{Supervised: true, Backend: nil})
		if err != nil {
			t.Fatalf("attachSupervisedProof (nil backend) = %v, want nil error", err)
		}
		if proof != nil {
			t.Fatalf("attachSupervisedProof (nil backend) returned a proof %T; want nil", proof)
		}
	})

	t.Run("a non-Supervised spawn never consults the containment plan, regardless of backend", func(t *testing.T) {
		cmd := exec.Command("true")
		tree, err := newProcessTree(cmd, processTreeOptions{Supervised: false, Backend: darwin.NewBackend()})
		if err != nil {
			t.Fatalf("newProcessTree (non-Supervised) = %v, want nil: Task 12c does not touch the synchronous path", err)
		}
		if tree == nil {
			t.Fatal("newProcessTree (non-Supervised) returned a nil tree")
		}
		if tree.proof != nil {
			t.Fatal("a non-Supervised process tree unexpectedly carries a containment proof")
		}
	})
}
