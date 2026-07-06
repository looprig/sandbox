//go:build darwin

package sandbox

// platformBackend selects the OS enforcement backend on darwin: Seatbelt via
// /usr/bin/sandbox-exec (SPEC §7.1). Every non-external NewExecutor on macOS
// compiles its policy to an SBPL profile and wraps each spawn with sandbox-exec.
//
// There is no runtime probe: sandbox-exec is present on every supported macOS, and
// a policy that a given profile cannot fully express is reported honestly via
// Level()/CompileReport rather than by falling back to the null backend (which
// would silently drop all OS enforcement). A test may still pin the null backend
// through the unexported withBackend seam to keep executor UNIT tests
// backend-independent.
func platformBackend() (backend, error) { return newSeatbeltBackend(), nil }
