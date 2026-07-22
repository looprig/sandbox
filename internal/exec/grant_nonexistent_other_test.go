//go:build !windows

package exec

// Linux can retain the nearest existing ancestor and resolve the exact leaf
// relative to that identity at grant consumption time.
func nonexistentExactPathGrantsSupported() bool { return true }
