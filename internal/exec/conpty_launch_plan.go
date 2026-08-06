package exec

import (
	"errors"
	"fmt"
)

// This file is Task 22A's platform-neutral ConPTY launch plan: the ordered
// data shape a later, Windows-only implementation (Task 22B's
// terminal_windows.go — not part of this file) will drive to actually call
// CreatePseudoConsole and CreateProcess. It deliberately contains no Windows
// API call and imports nothing beyond the standard library — see
// ConPTYPipes's own doc comment for why even the handle-shaped fields below
// are plain uintptr rather than golang.org/x/sys/windows.Handle or any
// internal/windows package type. That keeps this file compiling and its
// tests runnable on every platform, including this Darwin development
// machine, exactly like terminal.go (the Unix PTY vocabulary's own
// platform-neutral counterpart) already does for PTY mode.
//
// The ordering this plan enforces extends the existing Windows restricted/
// elevated precedent verbatim, never inventing a second, unconfined path:
// process_tree_windows.go's own processTree (the restricted/non-broker path)
// already creates its child CREATE_SUSPENDED, assigns it to a Job, and only
// then resumes it (see that file's own package doc comment: "the child is
// created suspended, assigned before resume, and retained until...");
// internal/windows/elevated_runner_launcher_windows.go's
// elevatedRunnerLauncher.Launch (the elevated/broker path) drives the
// identical CreateSuspended -> Assign -> Resume order using a broker-issued
// restricted token and a private desktop. A ConPTY-backed launch must
// compose with either path rather than create an unconfined side path, so
// this plan's ordering is exactly that same suspended-create -> Job-assign
// -> resume sequence, with the two ConPTY-specific steps (allocating the
// pipe pair ConPTY reads/writes, and turning that pair into the
// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE attribute CreateProcess itself needs)
// required strictly before the suspended create they feed.

// ConPTYLaunchStep identifies one distinguishable stage of a ConPTY-backed
// Windows process launch. Values name the same operations this package's
// existing Windows paths already perform — AllocatePipes and
// CreatePseudoConsole are new to ConPTY, but CreateSuspended, AssignJob, and
// Resume are the exact vocabulary process_tree_windows.go and
// internal/windows/elevated_runner_launcher_windows.go already use
// (CreateSuspended, Job.Assign/api.Assign, ntResumeProcess/api.Resume).
type ConPTYLaunchStep uint8

const (
	// conPTYStepUnspecified is the zero value: never a valid member of a
	// launch order, so a caller-constructed ConPTYLaunchStep slice that
	// leaves a slot unset is rejected by validateConPTYLaunchStepOrder
	// instead of silently treated as a real step.
	conPTYStepUnspecified ConPTYLaunchStep = iota

	// ConPTYStepAllocatePipes creates the two pipe pairs a pseudo console
	// needs — one endpoint of each handed to CreatePseudoConsole
	// (ConPTYStepCreatePseudoConsole), the other retained by the parent for
	// the process's whole lifetime, exactly like openProcessTerminal
	// (terminal_unix.go) retains the PTY master while handing the slave to
	// the child.
	ConPTYStepAllocatePipes

	// ConPTYStepCreatePseudoConsole turns the pipe endpoints
	// ConPTYStepAllocatePipes produced into the
	// PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE attribute (ConPTYAttribute, below)
	// the eventual CreateProcess call attaches. Must run after pipes exist
	// and before the suspended create that consumes it.
	ConPTYStepCreatePseudoConsole

	// ConPTYStepCreateSuspended creates the child process with
	// CREATE_SUSPENDED, exactly like the restricted path's own
	// newProcessTree (process_tree_windows.go, which ORs
	// windows.CREATE_SUSPENDED into cmd.SysProcAttr.CreationFlags) and the
	// elevated path's own CreateSuspended
	// (internal/windows/elevated_runner_native_windows.go, which passes
	// win.CREATE_SUSPENDED to CreateProcessAsUser). Must run after
	// ConPTYStepCreatePseudoConsole, since a ConPTY-backed create attaches
	// that attribute at creation time, and before ConPTYStepAssignJob: a
	// process is never meaningfully Job-assignable once it may already be
	// running unconfined code.
	ConPTYStepCreateSuspended

	// ConPTYStepAssignJob assigns the still-suspended child to its Job
	// Object, exactly like processTree.start's tree.job.Assign call
	// (process_tree_windows.go) and elevatedRunnerLauncher.Launch's
	// api.Assign call
	// (internal/windows/elevated_runner_launcher_windows.go). Must run
	// before ConPTYStepResume — this is the one invariant
	// TestConPTYLaunchPlanOrdersJobBeforeResume exists to prove is enforced
	// by this type's own logic, not merely documented here.
	ConPTYStepAssignJob

	// ConPTYStepResume resumes the child's main thread, exactly like
	// processTree.start's ntResumeProcess.Call (process_tree_windows.go) and
	// elevatedRunnerLauncher.Launch's api.Resume call
	// (internal/windows/elevated_runner_launcher_windows.go). A process must
	// never run a single instruction of its own code before it is already
	// contained by its Job — that is the entire reason this step is ordered
	// last.
	ConPTYStepResume

	// conPTYStepCount is a sentinel one past the last real step, used only
	// to bound valid ConPTYLaunchStep values; never itself a valid step.
	conPTYStepCount
)

// String supports readable failure messages from validateConPTYLaunchStepOrder
// and %v formatting in tests, never anything platform-specific.
func (step ConPTYLaunchStep) String() string {
	switch step {
	case ConPTYStepAllocatePipes:
		return "AllocatePipes"
	case ConPTYStepCreatePseudoConsole:
		return "CreatePseudoConsole"
	case ConPTYStepCreateSuspended:
		return "CreateSuspended"
	case ConPTYStepAssignJob:
		return "AssignJob"
	case ConPTYStepResume:
		return "Resume"
	default:
		return fmt.Sprintf("ConPTYLaunchStep(%d)", uint8(step))
	}
}

// conPTYRequiredSteps is every step a launch order must contain exactly
// once, already listed in the one correct order: canonicalConPTYLaunchOrder
// (below) is the only production source of a launch order and returns
// exactly this sequence, while validateConPTYLaunchStepOrder treats this
// array as an unordered required set (it recomputes each step's actual
// position from whatever slice it is given, independently of this array's
// own order).
var conPTYRequiredSteps = [...]ConPTYLaunchStep{
	ConPTYStepAllocatePipes,
	ConPTYStepCreatePseudoConsole,
	ConPTYStepCreateSuspended,
	ConPTYStepAssignJob,
	ConPTYStepResume,
}

// conPTYOrderedStepPairs is every (earlier, later) adjacency
// validateConPTYLaunchStepOrder enforces. It is exactly the chain
// AllocatePipes -> CreatePseudoConsole -> CreateSuspended -> AssignJob ->
// Resume documented on each ConPTYLaunchStep constant above; expressing it
// as pairs (rather than only comparing adjacent slice entries) means a
// non-adjacent violation — e.g. Resume placed two positions before
// AssignJob rather than immediately before it — is rejected exactly like an
// adjacent one.
var conPTYOrderedStepPairs = [][2]ConPTYLaunchStep{
	{ConPTYStepAllocatePipes, ConPTYStepCreatePseudoConsole},
	{ConPTYStepCreatePseudoConsole, ConPTYStepCreateSuspended},
	{ConPTYStepCreateSuspended, ConPTYStepAssignJob},
	{ConPTYStepAssignJob, ConPTYStepResume},
}

// canonicalConPTYLaunchOrder returns a fresh copy of the one correct launch
// order — the order NewConPTYLaunchPlan itself always builds. Returning a
// fresh copy on every call (rather than a shared backing array) means a
// caller — including this package's own tests, which mutate a copy into a
// specific invalid permutation to exercise validateConPTYLaunchStepOrder's
// rejection paths — can never corrupt another caller's view of "the
// canonical order" by mutating the slice it was handed.
func canonicalConPTYLaunchOrder() []ConPTYLaunchStep {
	return append([]ConPTYLaunchStep(nil), conPTYRequiredSteps[:]...)
}

// validateConPTYLaunchStepOrder rejects any candidate step sequence unless
// it contains every required step (conPTYRequiredSteps) exactly once, and
// every step's position obeys the fixed dependency chain
// conPTYOrderedStepPairs encodes: AllocatePipes before CreatePseudoConsole,
// before CreateSuspended, before AssignJob, before Resume. This is the one
// function TestConPTYLaunchPlanOrdersJobBeforeResume calls directly — as
// well as transitively, through ConPTYLaunchPlan.Validate — to prove
// Job-before-Resume is enforced by logic, not by a doc comment: a
// caller-supplied steps slice that puts ConPTYStepResume at or before
// ConPTYStepAssignJob's own position is rejected here unconditionally, for
// every caller, including one that bypasses NewConPTYLaunchPlan entirely and
// builds a ConPTYLaunchPlan literal directly (both reachable from within
// this package's own tests).
func validateConPTYLaunchStepOrder(steps []ConPTYLaunchStep) error {
	if len(steps) != len(conPTYRequiredSteps) {
		return fmt.Errorf("sandbox: ConPTY launch order has %d steps, want %d", len(steps), len(conPTYRequiredSteps))
	}
	position := make(map[ConPTYLaunchStep]int, len(steps))
	for i, step := range steps {
		if step == conPTYStepUnspecified || step >= conPTYStepCount {
			return fmt.Errorf("sandbox: ConPTY launch order has an invalid step at position %d: %v", i, step)
		}
		if _, seen := position[step]; seen {
			return fmt.Errorf("sandbox: ConPTY launch order repeats step %v", step)
		}
		position[step] = i
	}
	for _, required := range conPTYRequiredSteps {
		if _, ok := position[required]; !ok {
			return fmt.Errorf("sandbox: ConPTY launch order is missing required step %v", required)
		}
	}
	// Each pair is (earlier, later): earlier's position must be strictly
	// less than later's. A tied ("concurrent") position can never actually
	// occur in a slice — every index is unique by construction — but ">="
	// rather than a reversed-only "<" check rejects that case too, on the
	// off chance a future representation could ever produce one.
	for _, pair := range conPTYOrderedStepPairs {
		earlier, later := pair[0], pair[1]
		if position[earlier] >= position[later] {
			return fmt.Errorf("sandbox: ConPTY launch order requires %v before %v, got positions %d and %d",
				earlier, later, position[earlier], position[later])
		}
	}
	return nil
}

// ConPTYPipes holds the two pipe pairs a ConPTY-backed launch allocates
// before creating the pseudo console: one for the console's input (the
// parent writes; the pseudo console reads), one for its output (the pseudo
// console writes; the parent reads). Each field is the OS pipe handle as a
// plain uintptr — exactly the representation the standard library's own
// os.Process.WithHandle callback already uses for a live process handle
// (func(handle uintptr)) — never a golang.org/x/sys/windows.Handle or any
// internal/windows package type, so this file never imports a Windows-only
// package (see this file's own top-of-file doc comment). Task 22B
// (terminal_windows.go — not part of this file) is what will populate these
// from a real CreatePipe call and drive the actual ReadFile/WriteFile
// traffic through them; this type only records the shape and non-zero-ness
// of what a real launch needs.
type ConPTYPipes struct {
	// ConsoleInputRead is the pipe's read endpoint, handed to
	// CreatePseudoConsole as its input source; the pseudo console reads
	// from it. Closed by the parent once ConPTYStepCreatePseudoConsole has
	// handed it off, exactly like openProcessTerminal's closeSlave
	// (terminal_unix.go) drops the parent's own slave reference once the
	// child holds its inherited copy.
	ConsoleInputRead uintptr
	// ConsoleInputWrite is the pipe's write endpoint, retained by the parent
	// for the process's whole lifetime — the eventual terminalStdin
	// (terminal.go) write target, mirroring terminalMaster's role on Unix.
	ConsoleInputWrite uintptr
	// ConsoleOutputRead is the pipe's read endpoint, retained by the parent
	// for the process's whole lifetime — the eventual pumpPTYOutput
	// (process.go) drain source, mirroring terminalMaster's role on Unix.
	ConsoleOutputRead uintptr
	// ConsoleOutputWrite is the pipe's write endpoint, handed to
	// CreatePseudoConsole as its output target; the pseudo console writes
	// rendered output to it. Closed by the parent once handed off, exactly
	// like ConsoleInputRead above.
	ConsoleOutputWrite uintptr
}

// valid reports whether every pipe endpoint is a non-zero handle. A zero
// value is never a valid OS handle on any platform this package targets —
// see the identical convention job_windows.go's own Job.Assign ("process ==
// 0") and elevated_execution_bridge_windows.go's own "issued.Handle == 0"
// check already use for the same reason.
func (pipes ConPTYPipes) valid() bool {
	return pipes.ConsoleInputRead != 0 && pipes.ConsoleInputWrite != 0 &&
		pipes.ConsoleOutputRead != 0 && pipes.ConsoleOutputWrite != 0
}

// ConPTYAttribute is the PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE attribute a
// ConPTY-backed CreateProcess call must attach, sourced from a real
// CreatePseudoConsole result. See ConPTYPipes's own doc comment for why this
// is a plain uintptr rather than a Windows-only handle type.
type ConPTYAttribute struct {
	PseudoConsoleHandle uintptr
}

func (attribute ConPTYAttribute) valid() bool {
	return attribute.PseudoConsoleHandle != 0
}

// ConPTYJobAssignment names the Job Object a ConPTY-backed child must be
// assigned to before it is ever resumed — the identical Job
// process_tree_windows.go's own newProcessTree already creates and
// configures via internal/windows.NewJob before any child exists. This plan
// never creates, configures, or closes that Job itself; it only records
// which one ConPTYStepAssignJob targets.
type ConPTYJobAssignment struct {
	JobHandle uintptr
}

func (job ConPTYJobAssignment) valid() bool {
	return job.JobHandle != 0
}

// ConPTYBrokerCredentials is the restricted primary token and private
// desktop name the elevated broker path already threads through
// elevatedRunnerLaunch.Token/Desktop
// (internal/windows/elevated_runner_launcher_windows.go) — reproduced here
// as this package's own neutral fields rather than an import of that
// Windows-only package or its win.Token type (see this file's own
// top-of-file doc comment). The zero value means "no broker": a ConPTY-
// backed launch under the restricted (non-elevated) path,
// process_tree_windows.go's own processTree, never receives a broker token
// or desktop at all, and must stay just as valid a plan as the elevated,
// broker-backed case.
type ConPTYBrokerCredentials struct {
	TokenHandle uintptr
	Desktop     string
}

// valid reports whether the credentials are consistently either both unset
// (the restricted, non-broker path) or both set (the elevated, broker
// path) — never one without the other, which would be neither shape any
// existing launch path actually produces.
func (broker ConPTYBrokerCredentials) valid() bool {
	if broker.TokenHandle == 0 && broker.Desktop == "" {
		return true
	}
	return broker.TokenHandle != 0 && broker.Desktop != ""
}

// ConPTYLaunchPlan is the immutable, validated description of one ConPTY-
// backed Windows launch: the pipe pair, the pseudo-console attribute, the
// Job it must be assigned to, its optional broker credentials, and the
// fixed order those pieces are consumed in. NewConPTYLaunchPlan is the only
// production constructor and never returns a plan that fails its own
// Validate; every field is unexported and every accessor below returns a
// value or a defensive copy, so a caller holding a *ConPTYLaunchPlan can
// never mutate it into something Validate would reject.
type ConPTYLaunchPlan struct {
	pipes     ConPTYPipes
	attribute ConPTYAttribute
	job       ConPTYJobAssignment
	broker    ConPTYBrokerCredentials
	steps     []ConPTYLaunchStep
}

// NewConPTYLaunchPlan validates pipes, attribute, and job as non-zero,
// validates broker's all-or-nothing shape, and builds the one canonical
// step order (allocate pipes, create the pseudo-console attribute, create
// suspended, assign the Job, resume) before returning. It always calls
// Validate on the result before returning it, so a caller never observes a
// plan this constructor itself would consider invalid.
func NewConPTYLaunchPlan(pipes ConPTYPipes, attribute ConPTYAttribute, job ConPTYJobAssignment, broker ConPTYBrokerCredentials) (*ConPTYLaunchPlan, error) {
	plan := &ConPTYLaunchPlan{
		pipes:     pipes,
		attribute: attribute,
		job:       job,
		broker:    broker,
		steps:     canonicalConPTYLaunchOrder(),
	}
	if err := plan.Validate(); err != nil {
		return nil, err
	}
	return plan, nil
}

// Pipes returns the plan's pipe endpoints.
func (plan *ConPTYLaunchPlan) Pipes() ConPTYPipes {
	if plan == nil {
		return ConPTYPipes{}
	}
	return plan.pipes
}

// Attribute returns the plan's pseudo-console attribute.
func (plan *ConPTYLaunchPlan) Attribute() ConPTYAttribute {
	if plan == nil {
		return ConPTYAttribute{}
	}
	return plan.attribute
}

// Job returns the plan's Job assignment target.
func (plan *ConPTYLaunchPlan) Job() ConPTYJobAssignment {
	if plan == nil {
		return ConPTYJobAssignment{}
	}
	return plan.job
}

// Broker returns the plan's broker credentials — the zero value when this
// plan targets the restricted (non-broker) path.
func (plan *ConPTYLaunchPlan) Broker() ConPTYBrokerCredentials {
	if plan == nil {
		return ConPTYBrokerCredentials{}
	}
	return plan.broker
}

// Steps returns a defensive copy of the plan's launch order: mutating the
// returned slice can never reach back into the plan's own immutable state,
// and mutating the plan's own backing array (impossible from outside this
// package, since steps is unexported) is likewise never observable through
// a previously returned copy.
func (plan *ConPTYLaunchPlan) Steps() []ConPTYLaunchStep {
	if plan == nil {
		return nil
	}
	return append([]ConPTYLaunchStep(nil), plan.steps...)
}

// Validate reports whether this plan's fields and step order are both
// internally consistent: pipes, attribute, and job must each be non-zero;
// broker must be all-or-nothing; and steps must satisfy
// validateConPTYLaunchStepOrder. It is exported so a later Windows-only
// consumer (Task 22B) can re-check a plan it did not itself construct —
// e.g. one received across a boundary — and so this package's own tests can
// prove the type's own logic rejects a bad order directly, rather than
// relying only on NewConPTYLaunchPlan ever calling it.
func (plan *ConPTYLaunchPlan) Validate() error {
	if plan == nil {
		return errors.New("sandbox: nil ConPTY launch plan")
	}
	if !plan.pipes.valid() {
		return errors.New("sandbox: ConPTY launch plan has an invalid pipe endpoint")
	}
	if !plan.attribute.valid() {
		return errors.New("sandbox: ConPTY launch plan has an invalid pseudo-console attribute")
	}
	if !plan.job.valid() {
		return errors.New("sandbox: ConPTY launch plan has an invalid Job assignment target")
	}
	if !plan.broker.valid() {
		return errors.New("sandbox: ConPTY launch plan has inconsistent broker credentials")
	}
	return validateConPTYLaunchStepOrder(plan.steps)
}
