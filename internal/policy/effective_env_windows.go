//go:build windows

package policy

// BaselineEnvAllowlist returns the environment variable names (and "X_*"
// globs) a scrubbed child inherits from its parent (SPEC §3). It returns a
// fresh slice, so a caller may append to it. On Windows it is
// windowsBaselineEnvAllowlist, which must be matched under EnvNameFold.
func BaselineEnvAllowlist() []string { return windowsBaselineEnvAllowlist() }

// EnvNameFold folds an environment variable name to the key under which two
// names denote the same variable. Windows environment names are
// case-insensitive, so it upper-cases: "Path" and "PATH" fold to one key.
func EnvNameFold(name string) string { return windowsEnvNameFold(name) }
