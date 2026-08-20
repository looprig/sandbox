//go:build !windows

package policy

import (
	"path/filepath"
	"slices"
	"strings"
)

const (
	NullDevicePath   = "/dev/null"
	pathKeySeparator = "/"
)

func runtimeBaselines() []string { return nil }

func hostRootPaths() ([]string, error) { return []string{string(filepath.Separator)}, nil }

func sortHostRoots(roots []string) { slices.Sort(roots) }

func pathKey(path string) string { return filepath.Clean(path) }

func globPathKey(path string) string { return path }

func globMatches(glob, target string) (bool, bool) {
	re := GlobRegexp(glob)
	return re != nil && re.MatchString(target), re != nil
}

func pathKeyIsRoot(key string) bool { return key == pathKeySeparator }

func pathKeyVolume(string) string { return "" }

func literalPathEqual(left, right string) bool { return left == right }

func literalPathHasComponentPrefix(target, entry string) bool {
	return strings.HasPrefix(target, entry+pathKeySeparator)
}

func literalVolumeEqual(left, right string) bool { return left == right }

// MinimalRuntimeEntries is the operating-system runtime closure a confined
// target needs before it can execute anything at all: the interpreter, the
// shared libraries it maps, and the handful of resolver/TZ/CA files libc reads
// on startup. The set is per-OS because the paths genuinely differ -- a single
// !windows list forced Linux to demand Darwin-only paths such as
// /System/Library, which the Rung-1 mount view rejects outright ("protected
// path unavailable beneath writable bind") rather than skipping.
func MinimalRuntimeEntries() []FSEntry {
	var entries []FSEntry
	for _, path := range []string{"/bin", "/sbin", "/usr/bin", "/usr/sbin"} {
		entries = append(entries, FSEntry{Path: path, Access: ReadAccess | ExecAccess})
	}
	entries = append(entries, osRuntimeEntries()...)
	for _, path := range []string{
		"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/services",
		"/etc/protocols", "/etc/localtime",
	} {
		entries = append(entries, FSEntry{Path: path, Access: ReadAccess, Exact: true})
	}
	return entries
}
