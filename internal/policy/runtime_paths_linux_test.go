//go:build linux

package policy

import "testing"

// TestMinimalRuntimeEntriesLinuxOmitsDarwinPaths pins the defect that made the
// Rung-1 job fail: a Darwin-only path in the shared baseline is not skipped by
// the mount view, it aborts the spawn with "protected path unavailable".
func TestMinimalRuntimeEntriesLinuxOmitsDarwinPaths(t *testing.T) {
	for _, entry := range declaredMinimalRuntimeEntries() {
		switch entry.Path {
		case "/System/Library", "/etc/ssl/cert.pem":
			t.Errorf("Linux runtime baseline claims Darwin-only path %q", entry.Path)
		}
	}
}

// TestMinimalRuntimeEntriesLinuxGrantsLibraryExec pins the exit-126 fix: a
// usr-merged distribution resolves the ELF interpreter through /usr/lib, so
// read access alone leaves every dynamically linked target unable to start.
func TestMinimalRuntimeEntriesLinuxGrantsLibraryExec(t *testing.T) {
	want := map[string]bool{"/lib": false, "/lib64": false, "/usr/lib": false, "/usr/lib64": false}
	for _, entry := range declaredMinimalRuntimeEntries() {
		if _, tracked := want[entry.Path]; !tracked {
			continue
		}
		if entry.Access&ExecAccess == 0 {
			t.Errorf("%s Access = %v, want ExecAccess set", entry.Path, entry.Access)
		}
		want[entry.Path] = true
	}
	for path, seen := range want {
		if !seen {
			t.Errorf("Linux runtime baseline is missing %q", path)
		}
	}
}

// TestMinimalRuntimeEntriesLinuxKeepsLoaderCache guards the one exact-file
// entry libc consults before any library is opened.
func TestMinimalRuntimeEntriesLinuxKeepsLoaderCache(t *testing.T) {
	for _, entry := range declaredMinimalRuntimeEntries() {
		if entry.Path == "/etc/ld.so.cache" {
			if !entry.Exact {
				t.Fatal("/etc/ld.so.cache must be an exact-file entry")
			}
			return
		}
	}
	t.Fatal("Linux runtime baseline is missing /etc/ld.so.cache")
}

// TestMinimalRuntimeEntriesLinuxSkipsAbsentPaths pins that the runtime closure
// is narrowed to the host: a declared loader path the host lacks (arm64 has no
// /lib64) is dropped, not kept as a read-only entry the Rung-1 mount view would
// treat as a protected carveout and refuse the spawn over ("protected path
// "/lib64" unavailable beneath writable bind "/"").
func TestMinimalRuntimeEntriesLinuxSkipsAbsentPaths(t *testing.T) {
	absent := map[string]bool{"/lib64": true, "/usr/lib64": true, "/etc/localtime": true}
	restore := runtimePathPresent
	t.Cleanup(func() { runtimePathPresent = restore })
	runtimePathPresent = func(path string) bool { return !absent[path] }

	got := MinimalRuntimeEntries()
	kept := make(map[string]bool, len(got))
	for _, entry := range got {
		if absent[entry.Path] {
			t.Errorf("MinimalRuntimeEntries kept absent path %q", entry.Path)
		}
		kept[entry.Path] = true
	}
	for _, entry := range declaredMinimalRuntimeEntries() {
		if !absent[entry.Path] && !kept[entry.Path] {
			t.Errorf("MinimalRuntimeEntries dropped present path %q", entry.Path)
		}
	}
}
