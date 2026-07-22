package windows

// RestrictedRuntime coordinates crash-recovery state for every restricted
// backend owned by one ExecutorSet. Construction is side-effect free; the
// platform implementation opens and sweeps its journal lazily at most once.
type RestrictedRuntime struct {
	scratchRoot string
	state       restrictedRuntimeState
}

// NewRestrictedRuntime constructs one unregistered coordinator, primarily for
// focused package tests. ExecutorSet construction uses AcquireRestrictedRuntime
// so concurrent same-root sets share a live coordinator.
func NewRestrictedRuntime(scratchRoot string) *RestrictedRuntime {
	return &RestrictedRuntime{
		scratchRoot: scratchRoot,
		state:       newRestrictedRuntimeState(),
	}
}
