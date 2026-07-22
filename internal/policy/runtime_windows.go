//go:build windows

package policy

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/looprig/sandbox/internal/winpath"
)

const (
	NullDevicePath         = "NUL"
	WindowsRuntimeBaseline = "windows.runtime-baseline"
	pathKeySeparator       = `\`
)

func runtimeBaselines() []string { return []string{WindowsRuntimeBaseline} }

func hostRootPaths() ([]string, error) { return winpath.VolumeRoots() }

func sortHostRoots(roots []string) { slices.SortFunc(roots, winpath.Compare) }

func pathKey(path string) string {
	path = strings.ReplaceAll(path, "/", pathKeySeparator)
	return strings.ToUpper(filepath.Clean(path))
}

func pathKeyIsRoot(key string) bool {
	volume := filepath.VolumeName(key)
	return volume != "" && key == strings.ToUpper(volume)+pathKeySeparator
}

func pathKeyVolume(key string) string { return strings.ToUpper(filepath.VolumeName(key)) }

// MinimalRuntimeEntries is intentionally empty on Windows. The operating-system
// runtime closure is represented by WindowsRuntimeBaseline and audited by the
// Windows backend; policy compilation must not enumerate or alter WRP objects.
func MinimalRuntimeEntries() []FSEntry { return nil }
