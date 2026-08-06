package exec

import "testing"

// validConPTYPipes returns a ConPTYPipes value with every endpoint set to a
// distinct non-zero placeholder handle — enough to satisfy
// ConPTYPipes.valid without this platform-neutral test file ever opening a
// real OS pipe.
func validConPTYPipes() ConPTYPipes {
	return ConPTYPipes{
		ConsoleInputRead:   1,
		ConsoleInputWrite:  2,
		ConsoleOutputRead:  3,
		ConsoleOutputWrite: 4,
	}
}

func validConPTYAttribute() ConPTYAttribute {
	return ConPTYAttribute{PseudoConsoleHandle: 5}
}

func validConPTYJobAssignment() ConPTYJobAssignment {
	return ConPTYJobAssignment{JobHandle: 6}
}

// indexOfConPTYStep returns step's position in steps, or -1 if absent.
func indexOfConPTYStep(steps []ConPTYLaunchStep, step ConPTYLaunchStep) int {
	for i, candidate := range steps {
		if candidate == step {
			return i
		}
	}
	return -1
}

// swapConPTYSteps returns a copy of steps with left and right's positions
// exchanged, leaving the input slice untouched.
func swapConPTYSteps(steps []ConPTYLaunchStep, left, right ConPTYLaunchStep) []ConPTYLaunchStep {
	out := append([]ConPTYLaunchStep(nil), steps...)
	li, ri := indexOfConPTYStep(out, left), indexOfConPTYStep(out, right)
	if li < 0 || ri < 0 {
		return out
	}
	out[li], out[ri] = out[ri], out[li]
	return out
}

// removeConPTYStep returns a copy of steps with every occurrence of step
// dropped, leaving the input slice untouched.
func removeConPTYStep(steps []ConPTYLaunchStep, step ConPTYLaunchStep) []ConPTYLaunchStep {
	out := make([]ConPTYLaunchStep, 0, len(steps))
	for _, candidate := range steps {
		if candidate != step {
			out = append(out, candidate)
		}
	}
	return out
}

// TestConPTYLaunchPlanOrdersJobBeforeResume is Task 22A's queued phase-gate
// test: it must prove that a ConPTYLaunchPlan's own validation/construction
// logic enforces Job assignment strictly before resume — not merely a doc
// comment's claim — for every path that can produce a plan, including one
// that bypasses NewConPTYLaunchPlan entirely.
func TestConPTYLaunchPlanOrdersJobBeforeResume(t *testing.T) {
	t.Run("a plan built by the constructor orders Job assignment before resume", func(t *testing.T) {
		plan, err := NewConPTYLaunchPlan(validConPTYPipes(), validConPTYAttribute(), validConPTYJobAssignment(), ConPTYBrokerCredentials{})
		if err != nil {
			t.Fatalf("NewConPTYLaunchPlan: %v", err)
		}
		steps := plan.Steps()
		assignAt := indexOfConPTYStep(steps, ConPTYStepAssignJob)
		resumeAt := indexOfConPTYStep(steps, ConPTYStepResume)
		if assignAt < 0 || resumeAt < 0 {
			t.Fatalf("canonical plan is missing a required step: %v", steps)
		}
		if assignAt >= resumeAt {
			t.Fatalf("Job assignment (position %d) must precede resume (position %d): %v", assignAt, resumeAt, steps)
		}
	})

	t.Run("validateConPTYLaunchStepOrder rejects resume ordered before Job assignment", func(t *testing.T) {
		steps := swapConPTYSteps(canonicalConPTYLaunchOrder(), ConPTYStepAssignJob, ConPTYStepResume)
		if err := validateConPTYLaunchStepOrder(steps); err == nil {
			t.Fatalf("expected resume-before-assign order to be rejected, got nil error for %v", steps)
		}
	})

	t.Run("validateConPTYLaunchStepOrder rejects resume with no Job assignment to follow", func(t *testing.T) {
		// Dropping AssignJob entirely leaves Resume with no assignment step
		// to be ordered after at all — the degenerate case of "concurrent":
		// nothing in the sequence establishes that assignment ever happened
		// relative to resume.
		steps := removeConPTYStep(canonicalConPTYLaunchOrder(), ConPTYStepAssignJob)
		if err := validateConPTYLaunchStepOrder(steps); err == nil {
			t.Fatalf("expected resume with a missing Job assignment to be rejected, got nil error for %v", steps)
		}
	})

	t.Run("a hand-built plan bypassing the constructor still fails its own Validate", func(t *testing.T) {
		plan := &ConPTYLaunchPlan{
			pipes:     validConPTYPipes(),
			attribute: validConPTYAttribute(),
			job:       validConPTYJobAssignment(),
			steps:     swapConPTYSteps(canonicalConPTYLaunchOrder(), ConPTYStepAssignJob, ConPTYStepResume),
		}
		if err := plan.Validate(); err == nil {
			t.Fatalf("expected a hand-built plan with resume before Job assignment to fail Validate")
		}
	})
}

func TestNewConPTYLaunchPlanRejectsInvalidFields(t *testing.T) {
	cases := map[string]struct {
		pipes     ConPTYPipes
		attribute ConPTYAttribute
		job       ConPTYJobAssignment
		broker    ConPTYBrokerCredentials
	}{
		"zero pipes":     {ConPTYPipes{}, validConPTYAttribute(), validConPTYJobAssignment(), ConPTYBrokerCredentials{}},
		"zero attribute": {validConPTYPipes(), ConPTYAttribute{}, validConPTYJobAssignment(), ConPTYBrokerCredentials{}},
		"zero job":       {validConPTYPipes(), validConPTYAttribute(), ConPTYJobAssignment{}, ConPTYBrokerCredentials{}},
		"token without desktop": {
			validConPTYPipes(), validConPTYAttribute(), validConPTYJobAssignment(),
			ConPTYBrokerCredentials{TokenHandle: 7},
		},
		"desktop without token": {
			validConPTYPipes(), validConPTYAttribute(), validConPTYJobAssignment(),
			ConPTYBrokerCredentials{Desktop: `\Sandbox\Desktop`},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewConPTYLaunchPlan(tc.pipes, tc.attribute, tc.job, tc.broker); err == nil {
				t.Fatalf("expected NewConPTYLaunchPlan to reject %s", name)
			}
		})
	}
}

func TestNewConPTYLaunchPlanAcceptsBrokerOrRestrictedPath(t *testing.T) {
	t.Run("no broker (restricted path)", func(t *testing.T) {
		if _, err := NewConPTYLaunchPlan(validConPTYPipes(), validConPTYAttribute(), validConPTYJobAssignment(), ConPTYBrokerCredentials{}); err != nil {
			t.Fatalf("NewConPTYLaunchPlan: %v", err)
		}
	})
	t.Run("broker token and desktop (elevated path)", func(t *testing.T) {
		broker := ConPTYBrokerCredentials{TokenHandle: 42, Desktop: `\Sandbox\Desktop`}
		plan, err := NewConPTYLaunchPlan(validConPTYPipes(), validConPTYAttribute(), validConPTYJobAssignment(), broker)
		if err != nil {
			t.Fatalf("NewConPTYLaunchPlan: %v", err)
		}
		if got := plan.Broker(); got != broker {
			t.Fatalf("Broker() = %+v, want %+v", got, broker)
		}
	})
}

func TestConPTYLaunchPlanStepsIsDefensiveCopy(t *testing.T) {
	plan, err := NewConPTYLaunchPlan(validConPTYPipes(), validConPTYAttribute(), validConPTYJobAssignment(), ConPTYBrokerCredentials{})
	if err != nil {
		t.Fatalf("NewConPTYLaunchPlan: %v", err)
	}
	steps := plan.Steps()
	steps[0] = ConPTYStepResume
	if again := plan.Steps(); again[0] != ConPTYStepAllocatePipes {
		t.Fatalf("mutating a returned Steps() slice leaked into the plan: %v", again)
	}
	if err := plan.Validate(); err != nil {
		t.Fatalf("plan.Validate() after mutating a returned copy: %v", err)
	}
}

func TestConPTYLaunchPlanNilReceiverAccessorsAreSafe(t *testing.T) {
	var plan *ConPTYLaunchPlan
	if got := plan.Pipes(); got != (ConPTYPipes{}) {
		t.Fatalf("nil Pipes() = %+v, want zero value", got)
	}
	if got := plan.Attribute(); got != (ConPTYAttribute{}) {
		t.Fatalf("nil Attribute() = %+v, want zero value", got)
	}
	if got := plan.Job(); got != (ConPTYJobAssignment{}) {
		t.Fatalf("nil Job() = %+v, want zero value", got)
	}
	if got := plan.Broker(); got != (ConPTYBrokerCredentials{}) {
		t.Fatalf("nil Broker() = %+v, want zero value", got)
	}
	if got := plan.Steps(); got != nil {
		t.Fatalf("nil Steps() = %v, want nil", got)
	}
	if err := plan.Validate(); err == nil {
		t.Fatalf("expected nil plan Validate() to return an error")
	}
}

func TestValidateConPTYLaunchStepOrderRejectsDuplicatesAndWrongLength(t *testing.T) {
	t.Run("duplicate step", func(t *testing.T) {
		steps := canonicalConPTYLaunchOrder()
		steps[len(steps)-1] = steps[0]
		if err := validateConPTYLaunchStepOrder(steps); err == nil {
			t.Fatalf("expected a duplicated step to be rejected: %v", steps)
		}
	})
	t.Run("wrong length", func(t *testing.T) {
		steps := canonicalConPTYLaunchOrder()[:len(canonicalConPTYLaunchOrder())-1]
		if err := validateConPTYLaunchStepOrder(steps); err == nil {
			t.Fatalf("expected a short order to be rejected: %v", steps)
		}
	})
	t.Run("canonical order accepted", func(t *testing.T) {
		if err := validateConPTYLaunchStepOrder(canonicalConPTYLaunchOrder()); err != nil {
			t.Fatalf("expected the canonical order to be accepted: %v", err)
		}
	})
}
