//go:build !linux

package exec

// dispatchReexec is a no-op off linux, where nothing re-execs. See the linux
// variant for why this exists at all.
func dispatchReexec() {}
