//go:build linux

package exec

import (
	"errors"
	"os/exec"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/linux"
)

// TestProcessTreeLinuxContainmentPlan is Task 12b's queued phase-gate
// selector test: it proves the Linux containment SELECTION itself — Rung 1 ->
// PID-namespace proof (no cgroup touched), Rung 2 with a delegated cgroup v2
// pids ancestor -> a real lifetime cgroup scope joined onto the spawn's
// SysProcAttr, Rung 2 with NO delegated ancestor -> a fail-closed rejection
// before spawn, and a non-Linux/unconfined backend -> no containment claim at
// all. It exercises attachSupervisedProof directly (the exact function
// newProcessTree calls for a Supervised spawn) so the plan can be asserted
// without spawning a real process.
func TestProcessTreeLinuxContainmentPlan(t *testing.T) {
	t.Run("Rung 1 selects PID-namespace containment with no cgroup", func(t *testing.T) {
		cmd := exec.Command("true")
		proof, err := attachSupervisedProof(cmd, processTreeOptions{
			Supervised: true,
			Backend:    &linux.Backend{Rung: linux.RungOne, CgroupPids: "/sys/fs/cgroup/irrelevant"},
		})
		if err != nil {
			t.Fatalf("attachSupervisedProof (Rung 1) = %v, want nil error", err)
		}
		if proof == nil {
			t.Fatal("attachSupervisedProof (Rung 1) returned a nil proof; want linuxNamespaceProof")
		}
		if _, ok := proof.(linuxNamespaceProof); !ok {
			t.Fatalf("proof type = %T, want linuxNamespaceProof", proof)
		}
		// The exact, already-complete proof for Rung 1 requires no polling and
		// no cgroup: terminateAndWait must return cleanly with nothing to do.
		if terminateErr, proofErr := proof.terminateAndWait(); terminateErr != nil || proofErr != nil {
			t.Fatalf("Rung-1 proof.terminateAndWait() = (%v, %v), want (nil, nil)", terminateErr, proofErr)
		}
		proof.close()
	})

	t.Run("Rung 2 with a delegated cgroup selects and retains a lifetime scope", func(t *testing.T) {
		ancestor := requireLifetimeCgroupForExecTest(t)
		cmd := exec.Command("true")
		proof, err := attachSupervisedProof(cmd, processTreeOptions{
			Supervised: true,
			Backend:    &linux.Backend{Rung: linux.RungTwo, CgroupPids: ancestor},
		})
		if err != nil {
			t.Fatalf("attachSupervisedProof (Rung 2, delegated) = %v, want nil error", err)
		}
		if proof == nil {
			t.Fatal("attachSupervisedProof (Rung 2, delegated) returned a nil proof")
		}
		if _, ok := proof.(*linuxCgroupProof); !ok {
			t.Fatalf("proof type = %T, want *linuxCgroupProof", proof)
		}
		if cmd.SysProcAttr == nil || !cmd.SysProcAttr.UseCgroupFD {
			t.Fatal("Rung-2 delegated containment did not join the spawn onto the lifetime cgroup (UseCgroupFD unset)")
		}
		if cmd.SysProcAttr.CgroupFD < 0 {
			t.Fatalf("Rung-2 delegated containment set an invalid CgroupFD = %d", cmd.SysProcAttr.CgroupFD)
		}
		// Nothing was ever joined into the scope (no real spawn happened), so
		// its own KillAndWait proof is immediately empty — proving the exact,
		// mandatory proof this containment depends on.
		if _, proofErr := proof.terminateAndWait(); proofErr != nil {
			t.Fatalf("Rung-2 proof.terminateAndWait() = %v, want nil (nothing was ever joined)", proofErr)
		}
		proof.close()
	})

	t.Run("Rung 2 without a delegated cgroup rejects the supervised spawn before it starts", func(t *testing.T) {
		cmd := exec.Command("true")
		proof, err := attachSupervisedProof(cmd, processTreeOptions{
			Supervised: true,
			Backend:    &linux.Backend{Rung: linux.RungTwo, CgroupPids: ""},
		})
		if err == nil {
			t.Fatal("attachSupervisedProof (Rung 2, no delegation) succeeded; want a fail-closed error")
		}
		if proof != nil {
			t.Fatalf("attachSupervisedProof (Rung 2, no delegation) returned a non-nil proof alongside an error: %v", proof)
		}
		if !errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Errorf("error = %v, want it to wrap enforce.ErrLifetimeContainmentUnavailable", err)
		}
		if cmd.SysProcAttr != nil && cmd.SysProcAttr.UseCgroupFD {
			t.Error("a rejected containment plan must not join the spawn onto any cgroup")
		}
	})

	t.Run("a non-Linux backend attaches no containment claim", func(t *testing.T) {
		cmd := exec.Command("true")
		proof, err := attachSupervisedProof(cmd, processTreeOptions{
			Supervised: true,
			Backend:    enforce.NewNull(),
		})
		if err != nil {
			t.Fatalf("attachSupervisedProof (non-Linux backend) = %v, want nil error", err)
		}
		if proof != nil {
			t.Fatalf("attachSupervisedProof (non-Linux backend) returned a proof %T; want nil", proof)
		}
	})

	t.Run("newProcessTree propagates a rejected containment plan as a spawn failure", func(t *testing.T) {
		cmd := exec.Command("true")
		_, err := newProcessTree(cmd, processTreeOptions{
			Supervised: true,
			Backend:    &linux.Backend{Rung: linux.RungTwo, CgroupPids: ""},
		})
		if !errors.Is(err, enforce.ErrLifetimeContainmentUnavailable) {
			t.Fatalf("newProcessTree error = %v, want it to wrap enforce.ErrLifetimeContainmentUnavailable", err)
		}
	})

	t.Run("a non-Supervised spawn never consults the containment plan", func(t *testing.T) {
		cmd := exec.Command("true")
		tree, err := newProcessTree(cmd, processTreeOptions{
			Supervised: false,
			Backend:    &linux.Backend{Rung: linux.RungTwo, CgroupPids: ""},
		})
		if err != nil {
			t.Fatalf("newProcessTree (non-Supervised) = %v, want nil (the synchronous path is unaffected by 12b)", err)
		}
		if tree.proof != nil {
			t.Fatal("a non-Supervised process tree unexpectedly carries a containment proof")
		}
	})
}

// requireLifetimeCgroupForExecTest mirrors internal/linux's own
// requireLifetimeCgroup skip discipline for this package's containment-plan
// test, without duplicating cgroup delegation-probing logic: it defers
// directly to linux.ProbeDelegatedPidsAncestor, the exact probe
// linux.Backend.CgroupPids itself is populated from.
func requireLifetimeCgroupForExecTest(t *testing.T) string {
	t.Helper()
	ancestor := linux.ProbeDelegatedPidsAncestor()
	if ancestor == "" {
		t.Skip("cgroup v2 pids delegation unavailable on this host; Rung-2 lifetime containment plan cannot run")
	}
	return ancestor
}
