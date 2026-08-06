//go:build darwin || linux

package exec

import (
	"errors"
	"os/exec"
	"syscall"
	"time"
)

// processTree owns one dedicated Unix process group. The group ID is the
// immediate child's PID, so cancellation and normal completion can revoke every
// descendant that remains in the run's group before the execution lease ends.
//
// proof, when non-nil, is a platform-exact containment zeroProver attached by
// a Supervised spawn (see processTreeOptions.Supervised, attachSupervisedProof
// in process_tree_linux.go / process_tree_darwin.go): SPEC Task 12b requires
// every supervised spawn to select a mechanism the kernel itself enforces
// (Linux Rung 1's PID namespace or a delegated cgroup v2 scope) rather than
// this type's own process-group signal-and-poll, which a setsid or
// double-fork descendant can escape undetected. When proof is nil (every
// non-Supervised spawn, and every spawn on a platform with no exact mechanism
// wired yet) terminateAndWait keeps its original process-group behavior
// unchanged.
type processTree struct {
	cmd   *exec.Cmd
	pgid  int
	proof zeroProver
}

func newProcessTree(cmd *exec.Cmd, options processTreeOptions) (*processTree, error) {
	if cmd == nil {
		return nil, errors.New("sandbox: nil command process tree")
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	// A PTY-backed spawn (startConfined's TTY branch, process.go) already set
	// Setsid — via prepareTerminalSysProcAttr, terminal_unix.go — before this
	// function ever runs. POSIX forbids a session leader from also being
	// setpgid'd (its own setpgid call fails EPERM unconditionally, confirmed
	// empirically on this codebase's darwin target: `fork/exec: operation not
	// permitted`), so this must not layer Setpgid on top of an
	// already-requested Setsid. Nothing downstream needs it to: setsid(2)
	// already makes the child's process group id equal its own pid as an
	// intrinsic side effect — the exact pgid-equals-pid outcome
	// Setpgid+Pgid:0 exists to produce below — and every containment
	// primitive this type owns (signalGroup, terminateAndWait) keys off
	// cmd.Process.Pid, which is identical either way.
	if !cmd.SysProcAttr.Setsid {
		cmd.SysProcAttr.Setpgid = true
	}
	tree := &processTree{cmd: cmd}
	cmd.Cancel = tree.terminate
	if options.Supervised {
		proof, err := attachSupervisedProof(cmd, options)
		if err != nil {
			return nil, err
		}
		tree.proof = proof
	}
	return tree, nil
}

func (tree *processTree) start(cmd *exec.Cmd) error {
	if tree == nil || cmd == nil || cmd != tree.cmd {
		return errors.New("sandbox: invalid command process tree")
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	tree.pgid = cmd.Process.Pid
	return nil
}

// terminate delivers SIGKILL to this run's whole process group. It is the
// group-signal primitive every other signal (sendInterrupt/sendTerminate/
// sendKill, lifetime_unix.go) shares via signalGroup, and cmd.Cancel's own
// unconditional kill on context cancellation.
func (tree *processTree) terminate() error {
	return tree.signalGroup(syscall.SIGKILL)
}

// signalGroup delivers sig to this run's whole Unix process group (the
// negative of the immediate child's PID, which Setpgid makes the group ID).
// cmd.Process is published by exec.Cmd before it starts the context watcher
// that may call Cancel, so reading it directly here — rather than tree.pgid,
// which start() alone sets — avoids a race with Start. ESRCH (the group is
// already gone) is success, not an error: it is exactly the outcome a signal
// aimed at an already-exited target should report.
func (tree *processTree) signalGroup(sig syscall.Signal) error {
	if tree == nil || tree.cmd == nil || tree.cmd.Process == nil {
		return nil
	}
	pgid := tree.cmd.Process.Pid
	if pgid <= 0 {
		return nil
	}
	err := syscall.Kill(-pgid, sig)
	if errors.Is(err, syscall.ESRCH) {
		return nil
	}
	return err
}

// terminateAndWait proves this run's process tree is fully gone.
//
// When tree.proof is set (a Supervised spawn with an exact platform proof
// attached — see the processTree.proof doc above) it defers entirely to that
// proof after one defensive group SIGKILL: the direct child has already been
// reaped by every caller of terminateAndWait (Process.Wait/cmd.Wait always
// runs first — see process.go's supervise and executor.go's run), so for
// Rung 1 the kernel's own PID-namespace-teardown-on-init-exit guarantee is
// already exact by the time this runs, and for a delegated cgroup the proof
// is transientCgroup.KillAndWait's cgroup.kill + cgroup.procs-empty read.
//
// Otherwise (every non-Supervised spawn, and any Supervised spawn on a
// platform with no exact mechanism wired yet) it keeps the original
// process-group signal-and-poll behavior unchanged.
func (tree *processTree) terminateAndWait() (error, error) {
	if tree == nil {
		return nil, nil
	}
	if tree.proof != nil {
		terminateErr := tree.terminate()
		_, proofErr := tree.proof.terminateAndWait()
		return terminateErr, proofErr
	}
	if tree.pgid <= 0 {
		return nil, nil
	}
	for {
		reapProcessGroup(tree.pgid)
		active, err := processGroupActive(tree.pgid)
		if err != nil {
			// Inspection failure is not evidence that the group is gone. Keep the
			// lease and every backing resource live until absence can be verified.
			time.Sleep(time.Millisecond)
			continue
		}
		if !active {
			return nil, nil
		}
		// Cancellation may already have delivered SIGKILL while the group is in
		// the exit transition. Darwin can report EPERM for a redundant kill during
		// that window. No kill error proves absence, so retain authority and retry
		// after inspecting the group again.
		_ = tree.terminate()
		time.Sleep(time.Millisecond)
	}
}

func (tree *processTree) close() {
	if tree == nil || tree.proof == nil {
		return
	}
	tree.proof.close()
}
