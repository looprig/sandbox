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
	return filepath.Clean(path)
}

func globPathKey(path string) string { return strings.ReplaceAll(path, "/", pathKeySeparator) }

func pathKeyIsRoot(key string) bool {
	volume := filepath.VolumeName(key)
	return volume != "" && literalPathEqual(key, volume+pathKeySeparator)
}

func pathKeyVolume(key string) string { return filepath.VolumeName(key) }

func literalPathEqual(left, right string) bool { return winpath.Compare(left, right) == 0 }

func literalPathHasComponentPrefix(target, entry string) bool {
	return winpath.HasPrefix(target, strings.TrimSuffix(entry, pathKeySeparator)+pathKeySeparator)
}

func literalVolumeEqual(left, right string) bool { return winpath.Compare(left, right) == 0 }

// MinimalRuntimeEntries is intentionally empty on Windows. The operating-system
// runtime closure is represented by WindowsRuntimeBaseline and audited by the
// Windows backend; policy compilation must not enumerate or alter WRP objects.
func MinimalRuntimeEntries() []FSEntry { return nil }
