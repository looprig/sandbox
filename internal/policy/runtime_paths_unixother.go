//go:build !windows && !linux && !darwin

package policy

// osRuntimeEntries covers the remaining Unix targets. Only the portable
// library locations are claimed; anything distribution-specific belongs in a
// GOOS-specific peer alongside this file.
func osRuntimeEntries() []FSEntry {
	return []FSEntry{
		{Path: "/lib", Access: ReadAccess | ExecAccess},
		{Path: "/usr/lib", Access: ReadAccess | ExecAccess},
		{Path: "/usr/libexec", Access: ReadAccess | ExecAccess},
		{Path: "/etc/ssl/certs", Access: ReadAccess},
	}
}
