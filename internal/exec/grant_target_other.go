//go:build !windows

package exec

func validateGrantTargetAvailability(_, _, _ string) error { return nil }
