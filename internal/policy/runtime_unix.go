//go:build !windows

package policy

import "path/filepath"

const (
	NullDevicePath   = "/dev/null"
	pathKeySeparator = "/"
)

func runtimeBaselines() []string { return nil }

func hostRootPath(string) string { return string(filepath.Separator) }

func pathKey(path string) string { return filepath.Clean(path) }

func pathKeyIsRoot(key string) bool { return key == pathKeySeparator }

func pathKeyVolume(string) string { return "" }

func MinimalRuntimeEntries() []FSEntry {
	var entries []FSEntry
	for _, path := range []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec",
		"/usr/lib/git-core", "/lib", "/lib64",
	} {
		entries = append(entries, FSEntry{Path: path, Access: ReadAccess | ExecAccess})
	}
	for _, path := range []string{
		"/usr/lib", "/usr/lib64", "/System/Library", "/etc/ssl/certs", "/etc/pki",
	} {
		entries = append(entries, FSEntry{Path: path, Access: ReadAccess})
	}
	for _, path := range []string{
		"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/services",
		"/etc/protocols", "/etc/localtime", "/etc/ld.so.cache", "/etc/ssl/cert.pem",
	} {
		entries = append(entries, FSEntry{Path: path, Access: ReadAccess, Exact: true})
	}
	return entries
}
