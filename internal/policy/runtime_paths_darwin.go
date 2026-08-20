//go:build darwin

package policy

// osRuntimeEntries is the Darwin runtime closure. It reproduces exactly the
// access this package granted before the per-OS split, because the Seatbelt
// backend's profile is generated from these entries and macOS CI already
// proves that profile works; the split exists to stop Linux inheriting
// Darwin-only paths, not to retune Darwin.
func osRuntimeEntries() []FSEntry {
	var entries []FSEntry
	for _, path := range []string{"/usr/libexec", "/usr/lib/git-core", "/lib", "/lib64"} {
		entries = append(entries, FSEntry{Path: path, Access: ReadAccess | ExecAccess})
	}
	for _, path := range []string{
		"/usr/lib", "/usr/lib64", "/System/Library", "/etc/ssl/certs", "/etc/pki",
	} {
		entries = append(entries, FSEntry{Path: path, Access: ReadAccess})
	}
	return append(entries, FSEntry{Path: "/etc/ssl/cert.pem", Access: ReadAccess, Exact: true})
}
