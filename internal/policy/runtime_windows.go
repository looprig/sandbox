//go:build windows

package policy

import (
	"path/filepath"
	"strings"
)

const (
	NullDevicePath         = "NUL"
	WindowsRuntimeBaseline = "windows.runtime-baseline"
	pathKeySeparator       = `\`
)

func runtimeBaselines() []string { return []string{WindowsRuntimeBaseline} }

func hostRootPath(workspace string) string {
	volume := filepath.VolumeName(filepath.Clean(workspace))
	if volume == "" {
		return pathKeySeparator
	}
	return volume + pathKeySeparator
}

func pathKey(path string) string {
	path = strings.ReplaceAll(path, "/", pathKeySeparator)
	return strings.ToUpper(filepath.Clean(path))
}

func pathKeyIsRoot(key string) bool {
	volume := filepath.VolumeName(key)
	return volume != "" && key == strings.ToUpper(volume)+pathKeySeparator
}

// MinimalRuntimeEntries is intentionally empty on Windows. The operating-system
// runtime closure is represented by WindowsRuntimeBaseline and audited by the
// Windows backend; policy compilation must not enumerate or alter WRP objects.
func MinimalRuntimeEntries() []FSEntry { return nil }
