//go:build !windows

package enforce

// ShellArgv normalizes a command string through the platform shell. Backends
// wrap this argv and never select a shell themselves.
func ShellArgv(command string) []string { return []string{"/bin/sh", "-c", command} }
