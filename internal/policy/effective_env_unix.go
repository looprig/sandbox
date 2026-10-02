//go:build !windows

package policy

// BaselineEnvAllowlist returns the environment variable names (and "X_*"
// globs) a scrubbed child inherits from its parent (SPEC §3). It returns a
// fresh slice, so a caller may append to it. On Unix it is
// unixBaselineEnvAllowlist.
func BaselineEnvAllowlist() []string { return unixBaselineEnvAllowlist() }

// EnvNameFold folds an environment variable name to the key under which two
// names denote the same variable. Unix environment names are case-sensitive,
// so it is the identity here.
func EnvNameFold(name string) string { return name }
