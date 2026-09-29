//go:build linux

package policy

import "os"

// osRuntimeEntries is the Linux runtime closure.
//
// The library directories carry ExecAccess, not merely ReadAccess. Landlock's
// LANDLOCK_ACCESS_FS_EXECUTE governs mapping a file PROT_EXEC as well as
// execve, and on a usr-merged distribution /lib64/ld-linux-*.so.2 resolves
// into /usr/lib/<triplet>/. Granting only read there let the target's own
// binary pass the /usr/bin exec check and then fail when the kernel tried to
// map its ELF interpreter -- surfacing as the "cannot execute" exit code 126
// that Rung 1 reported for a command as trivial as "true".
func osRuntimeEntries() []FSEntry {
	var entries []FSEntry
	for _, path := range []string{
		"/lib", "/lib64", "/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/lib/git-core",
	} {
		entries = append(entries, FSEntry{Path: path, Access: ReadAccess | ExecAccess})
	}
	for _, path := range []string{"/etc/ssl/certs", "/etc/pki"} {
		entries = append(entries, FSEntry{Path: path, Access: ReadAccess})
	}
	return append(entries, FSEntry{Path: "/etc/ld.so.cache", Access: ReadAccess, Exact: true})
}

// runtimePathPresent reports whether a runtime-closure path resolves on this
// host. It follows symlinks, as the Rung-1 mount view does when it binds a root
// (a usr-merged /lib64 is a symlink; a dangling one is as absent as a missing
// path). It is a variable only so a test can simulate another host's layout.
var runtimePathPresent = func(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// presentRuntimeEntries drops runtime-closure entries this host does not have.
// See MinimalRuntimeEntries for why an absent entry is skipped rather than kept.
func presentRuntimeEntries(entries []FSEntry) []FSEntry {
	kept := entries[:0]
	for _, entry := range entries {
		if runtimePathPresent(entry.Path) {
			kept = append(kept, entry)
		}
	}
	return kept
}
