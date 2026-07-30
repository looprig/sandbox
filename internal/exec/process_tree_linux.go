//go:build linux

package exec

import (
	"context"
	"errors"
	"os/exec"
	"syscall"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/linux"
)

// This file selects the exact Linux process-tree containment mechanism a
// Supervised spawn (processTreeOptions.Supervised — see process_tree_unix.go)
// requires (SPEC Task 12b): Rung 1's fresh PID namespace when the compiled
// backend selected it, or a delegated cgroup v2 lifetime scope otherwise.
// Neither available (Rung 2 with no delegated cgroup v2 pids ancestor) fails
// the spawn CLOSED before it ever starts — a process-group signal-and-poll
// fallback is exactly the escapable mechanism this microtask exists to
// replace for a supervised spawn (see processTree.proof's doc, and the
// darwin stub in process_tree_darwin.go for the platform this does NOT yet
// cover).

// linuxNamespaceProof is the Rung-1 zeroProver: no cgroup, no polling. The
// stage-2 target is clone'd as PID 1 of a fresh PID namespace by the Linux
// backend's own configure closure (linux.ConfigureRung1SysProcAttr, applied
// to cmd.SysProcAttr before newProcessTree/attachSupervisedProof ever runs —
// it is a static property of an Executor whose backend.Rung == RungOne, so
// every spawn from it gets these cloneflags unconditionally). The kernel
// guarantees that once a PID namespace's init process has exited, every
// other process inside that namespace has already been force-killed — and
// every caller of terminateAndWait has already reaped the direct child via
// Process.Wait/cmd.Wait before calling it (process.go's supervise,
// executor.go's run), so by construction there is nothing left to poll for:
// the direct child being reaped IS the exact, already-complete proof.
type linuxNamespaceProof struct{}

func (linuxNamespaceProof) terminateAndWait() (error, error) { return nil, nil }
func (linuxNamespaceProof) close()                           {}

// linuxCgroupProof is the Rung-2 zeroProver: a dedicated delegated cgroup v2
// lifetime scope (linux.LifetimeScope), independent of any policy.Limits
// resource-limit cgroup. terminateAndWait defers entirely to
// LifetimeScope.KillAndWait, the mandatory result-bearing proof (cgroup.kill
// plus a successful cgroup.procs-empty read); a failed/indeterminate proof
// keeps the scope's directory and join fd retained (KillAndWait's own
// contract) so a later retry — this module's existing process-level
// quarantine, which already retries terminateAndWait via
// quarantinedSpawn.reapOnce — can call it again.
type linuxCgroupProof struct {
	scope linux.LifetimeScope
}

func (p *linuxCgroupProof) terminateAndWait() (error, error) {
	if p == nil || p.scope == nil {
		return nil, nil
	}
	return nil, p.scope.KillAndWait(context.Background())
}

func (p *linuxCgroupProof) close() {}

// attachSupervisedProof selects and, for the cgroup case, wires this spawn's
// exact containment mechanism. It is called from newProcessTree
// (process_tree_unix.go) after the backend's own configure closure has
// already run on cmd — so a Rung-1 cmd.SysProcAttr already carries its
// namespace cloneflags, and any best-effort resource-limit cgroup join
// configure may have set is still visible on cmd.SysProcAttr and gets
// overridden here for the Rung-2 case (see LifetimeScope.Join's doc: a
// supervised spawn's lifetime join always wins the single clone3
// CLONE_INTO_CGROUP slot).
//
// options.Backend not asserting to *linux.Backend (an unconfined executor, or
// a backend pinned by a non-Linux-backend test seam) attaches nothing and
// returns no error: there is no Linux-specific containment claim to make for
// a spawn this package didn't compile through the Linux backend.
func attachSupervisedProof(cmd *exec.Cmd, options processTreeOptions) (zeroProver, error) {
	lb, ok := options.Backend.(*linux.Backend)
	if !ok || lb == nil {
		return nil, nil
	}
	switch lb.Rung {
	case linux.RungOne:
		return linuxNamespaceProof{}, nil
	case linux.RungTwo:
		scope, err := linux.NewLifetimeScope(lb.CgroupPids)
		if err != nil {
			return nil, errors.Join(enforce.ErrLifetimeContainmentUnavailable, err)
		}
		if cmd.SysProcAttr == nil {
			cmd.SysProcAttr = &syscall.SysProcAttr{}
		}
		scope.Join(cmd.SysProcAttr)
		return &linuxCgroupProof{scope: scope}, nil
	default:
		return nil, enforce.ErrLifetimeContainmentUnavailable
	}
}
