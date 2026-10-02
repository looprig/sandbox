package exec

import "fmt"

// LifetimeContainment reports which process-tree teardown contract a
// Supervised spawn actually received — achieved enforcement, not requested
// policy (the same honesty rule as profile.Guarantees).
type LifetimeContainment uint8

const (
	// LifetimeContainmentUnspecified (zero value): the spawn carries no
	// lifetime containment claim at all — an Unconfined/null-backend or
	// test-double spawn, whose teardown is the escapable process-group
	// signal-and-poll sweep. Deliberately NOT Enforced: reporting kernel
	// enforcement for a spawn that has none would violate the honesty rule.
	LifetimeContainmentUnspecified LifetimeContainment = iota
	// LifetimeContainmentEnforced: the kernel itself guarantees teardown —
	// Linux Rung 1 PID namespace, Linux Rung 2 delegated cgroup v2, or the
	// Windows elevated tier's Job, whose dedicated sandbox account and private
	// desktop close the same-user broker channels a process could otherwise
	// use to be created outside it. No descendant can escape it.
	LifetimeContainmentEnforced
	// LifetimeContainmentBestEffort: teardown reaches every process the
	// spawn's own tree contains, but a descendant can get a process created
	// outside it. Darwin Seatbelt: process-group SIGKILL plus proc-table
	// closure descendant tracking, so a descendant that daemonizes through a
	// tracking gap survives as an orphan — still fully confined by the
	// spawn's Seatbelt profile, but outliving the session. Windows restricted
	// tier: a kill-on-close Job with no breakaway, but the child runs as the
	// caller's own user and can ask a same-user broker (WMI
	// Win32_Process.Create, a COM local server) to start a process outside
	// the Job and outside the restricted token. See
	// docs/lifetime-containment.md.
	LifetimeContainmentBestEffort
)

// String never panics. An unrecognized value (out-of-range constructions
// are possible since LifetimeContainment is a public alias,
// sandbox.LifetimeContainment) reports as LifetimeContainment(N) rather
// than silently aliasing to a real member's string, so it surfaces as
// visibly wrong instead of misreporting a containment contract.
func (c LifetimeContainment) String() string {
	switch c {
	case LifetimeContainmentUnspecified:
		return "unspecified"
	case LifetimeContainmentEnforced:
		return "enforced"
	case LifetimeContainmentBestEffort:
		return "best-effort"
	default:
		return fmt.Sprintf("LifetimeContainment(%d)", uint8(c))
	}
}

// lifetimeReporter is the single optional self-description seam: a
// zeroProver that knows its contract implements it, and each platform's
// process tree implements it to surface the spawn-level answer
// (process_tree_unix.go delegates to its proof; process_tree_windows.go
// answers BestEffort for the restricted tier, Unspecified when Unconfined;
// the Windows elevated tier's backend-owned Launch path answers Enforced in
// process.go). process.go type-asserts the processTreeBoundary —
// never widen processTreeBoundary itself (the test fakes would break).
type lifetimeReporter interface {
	lifetimeContainment() LifetimeContainment
}

// pidArmer is the optional post-Start hook a zeroProver can carry; a prover
// that must observe the live root pid (the darwin descendant tracker)
// implements it and processTree.start invokes it right after cmd.Start().
type pidArmer interface {
	armPID(pid int) error
}
