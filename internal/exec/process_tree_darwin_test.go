//go:build darwin

package exec

import (
	"os/exec"
	"testing"

	"github.com/looprig/sandbox/internal/darwin"
	"github.com/looprig/sandbox/internal/enforce"
)

// TestDarwinLifetimeCapabilityBestEffort is Task 4's queued phase-gate
// selector test: it proves the Darwin BEST-EFFORT CONTAINMENT DECISION — a
// Supervised spawn compiled through the real Seatbelt backend
// (darwin.NewBackend()) gets a best-effort zeroProver attached (process-group
// SIGKILL-and-poll plus proc-table-closure descendant tracking via
// descendantTracker, process_descendants_darwin.go) rather than being
// rejected outright, a Supervised spawn NOT claiming real Seatbelt
// confinement (a nil backend, or a test double pinned through withBackend,
// exactly like enforce.NewNull()'s Unconfined path) is completely
// unaffected, and a non-Supervised (synchronous RunCommand/RunArgv) spawn is
// unaffected regardless of backend — mirroring process_tree_linux_test.go's
// TestProcessTreeLinuxContainmentPlan. It exercises attachSupervisedProof and
// newProcessTree directly (the exact functions a Supervised spawn's
// process.go/startConfined path calls) so the contract can be asserted
// without spawning a real process or depending on the integration-tagged
// escape proof in process_parent_death_integration_unix_test.go.
func TestDarwinLifetimeCapabilityBestEffort(t *testing.T) {
	t.Run("a Supervised spawn through the real Seatbelt backend attaches a best-effort proof, no error", func(t *testing.T) {
		cmd := exec.Command("true")
		proof, err := attachSupervisedProof(cmd, processTreeOptions{Supervised: true, Backend: darwin.NewBackend()})
		if err != nil {
			t.Fatalf("attachSupervisedProof = %v, want nil error: darwin's best-effort prover always attaches", err)
		}
		if proof == nil {
			t.Fatal("attachSupervisedProof returned a nil proof for the real Seatbelt backend; want a best-effort prover")
		}
		reporter, ok := proof.(lifetimeReporter)
		if !ok {
			t.Fatal("darwin proof must implement lifetimeReporter")
		}
		if got := reporter.lifetimeContainment(); got != LifetimeContainmentBestEffort {
			t.Fatalf("lifetimeContainment() = %v, want LifetimeContainmentBestEffort", got)
		}
		if _, ok := proof.(pidArmer); !ok {
			t.Fatal("darwin proof must implement pidArmer, armed post-Start by processTree.start")
		}
		if cmd.Process != nil {
			t.Fatal("attachSupervisedProof must never itself spawn a process")
		}
		proof.close()
	})

	t.Run("newProcessTree attaches the best-effort proof, never rejecting, before cmd.Start is ever reached", func(t *testing.T) {
		cmd := exec.Command("true")
		tree, err := newProcessTree(cmd, processTreeOptions{Supervised: true, Backend: darwin.NewBackend()})
		if err != nil {
			t.Fatalf("newProcessTree error = %v, want nil: darwin's best-effort prover never fails closed", err)
		}
		if tree == nil {
			t.Fatal("newProcessTree returned a nil tree alongside a nil error")
		}
		if tree.proof == nil {
			t.Fatal("newProcessTree did not attach a containment proof for the real Seatbelt backend")
		}
		if cmd.Process != nil {
			t.Fatal("newProcessTree must never itself spawn a process")
		}
		tree.close()
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
			t.Fatalf("newProcessTree (non-Supervised) = %v, want nil: Task 4 does not touch the synchronous path", err)
		}
		if tree == nil {
			t.Fatal("newProcessTree (non-Supervised) returned a nil tree")
		}
		if tree.proof != nil {
			t.Fatal("a non-Supervised process tree unexpectedly carries a containment proof")
		}
	})
}

// TestAttachSupervisedProofSeatbeltBestEffort is the plan's own illustrative
// test: a focused, single-assertion-block check that attachSupervisedProof's
// real-Seatbelt-backend result is armable and self-reports best-effort
// containment. TestDarwinLifetimeCapabilityBestEffort above covers the same
// ground as part of its broader scoping table; this stands alone so the
// exact contract can be run in isolation (see this file's package doc-level
// Step 2 verification command).
func TestAttachSupervisedProofSeatbeltBestEffort(t *testing.T) {
	cmd := exec.Command("/usr/bin/true")
	proof, err := attachSupervisedProof(cmd, processTreeOptions{
		Supervised: true,
		Backend:    darwin.NewBackend(),
	})
	if err != nil {
		t.Fatalf("attachSupervisedProof: %v", err)
	}
	if proof == nil {
		t.Fatal("expected a best-effort prover, got nil")
	}
	reporter, ok := proof.(lifetimeReporter)
	if !ok || reporter.lifetimeContainment() != LifetimeContainmentBestEffort {
		t.Fatal("prover must report best-effort containment")
	}
	if _, ok := proof.(pidArmer); !ok {
		t.Fatal("prover must be armable post-Start")
	}
	proof.close()
}

// stubZeroProver is a minimal zeroProver that deliberately does NOT
// implement lifetimeReporter, used by TestProcessTreeLifetimeDelegation to
// exercise processTree.lifetimeContainment's fallback-to-Enforced branch:
// any non-nil proof with no self-reported answer is treated as
// kernel-enforced, mirroring the real Linux namespace/cgroup provers
// (process_tree_linux.go), which don't implement lifetimeReporter either.
type stubZeroProver struct{}

func (stubZeroProver) terminateAndWait() (error, error) { return nil, nil }
func (stubZeroProver) close()                           {}

// TestProcessTreeLifetimeDelegation proves processTree.lifetimeContainment's
// platform-neutral delegation semantics (process_tree_unix.go) across all
// three branches: a proofless tree — the zero value, standing in for any
// non-Supervised spawn or a Supervised spawn on a platform/backend with no
// proof attached — answers Unspecified; a proof that implements
// lifetimeReporter (darwinBestEffortProof, exercised here directly rather
// than via attachSupervisedProof, since lifetimeContainment() never touches
// its cmd/tracker fields) delegates to that proof's own answer; and a proof
// with no lifetimeReporter implementation (stubZeroProver, above) falls back
// to Enforced. This lives in the darwin-tagged test file (process_tree_unix.go
// itself, and the method under test, build on darwin || linux) per the plan's
// own note that a darwin file is fine for this platform-neutral case.
func TestProcessTreeLifetimeDelegation(t *testing.T) {
	t.Run("nil proof reports Unspecified", func(t *testing.T) {
		tree := &processTree{}
		if got := tree.lifetimeContainment(); got != LifetimeContainmentUnspecified {
			t.Fatalf("nil-proof tree = %v, want unspecified", got)
		}
	})

	t.Run("a lifetimeReporter proof delegates to its own answer", func(t *testing.T) {
		tree := &processTree{proof: &darwinBestEffortProof{}}
		if got := tree.lifetimeContainment(); got != LifetimeContainmentBestEffort {
			t.Fatalf("reporter-proof tree = %v, want best-effort (delegated from darwinBestEffortProof.lifetimeContainment)", got)
		}
	})

	t.Run("a non-reporter proof falls back to Enforced", func(t *testing.T) {
		tree := &processTree{proof: stubZeroProver{}}
		if got := tree.lifetimeContainment(); got != LifetimeContainmentEnforced {
			t.Fatalf("non-reporter-proof tree = %v, want enforced", got)
		}
	})
}
