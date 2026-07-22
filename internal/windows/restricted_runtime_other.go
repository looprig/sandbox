//go:build !windows

package windows

// The portable state is intentionally empty: selecting Windows confinement on
// another OS is rejected before it can perform filesystem work.
type restrictedRuntimeState struct{}

func newRestrictedRuntimeState() restrictedRuntimeState { return restrictedRuntimeState{} }

// AcquireRestrictedRuntime is a side-effect-free portability stub. Non-Windows
// platform selection rejects Windows mechanisms before the runtime is used.
func AcquireRestrictedRuntime(scratchRoot string) (*RestrictedRuntime, func()) {
	return NewRestrictedRuntime(scratchRoot), func() {}
}
