//go:build !darwin && !linux

package policy

import "os"

// directRegularFileRuleSafe has no link count to read off darwin and Linux
// (on Windows an os.FileInfo's Sys() is a Win32FileAttributeData, which
// carries none), so it admits every file. That is not a widening anywhere: the
// predicate exists for Landlock's inode-scoped file rules, and every
// production path that reaches it (ValidateLandlockExactPaths, rule
// enumeration) starts in the Linux backend. Windows refuses a
// multiply-linked exact file from its own owned-handle identity instead
// (winpath.Object.LinkCount, pathhandle_windows.go). The tests that pin the
// single-link rule are therefore built for darwin and Linux only
// (compiled_fs_linkcount_test.go).
func directRegularFileRuleSafe(os.FileInfo) bool {
	return true
}
