//go:build windows

package exec

// Windows ACL grants are projected onto identity-pinned existing objects. A
// nonexistent exact leaf has no object identity to retain and therefore cannot
// be granted before creation.
func nonexistentExactPathGrantsSupported() bool { return false }
