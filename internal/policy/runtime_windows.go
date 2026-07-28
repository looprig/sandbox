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

// globMatches implements Windows wildcard matching over path keys. Literal
// units and bracket ranges use the same CompareStringOrdinal-backed comparison
// as literal Windows paths; wildcard matching therefore cannot disagree with
// ACL planning merely because a path's case differs from the policy spelling.
func globMatches(glob, target string) (bool, bool) {
	pattern, err := parseGlob(glob)
	value := []rune(globPathKey(target))
	if err != nil {
		return false, false
	}

	// CompareStringOrdinal is an OS call. Cache each distinct rune pair so a
	// repeated literal (the adversarial and common filename case) pays for the
	// exact Windows comparison once without substituting linguistic folding.
	type runePair struct{ left, right rune }
	comparisons := make(map[runePair]int)
	compare := func(left, right rune) int {
		pair := runePair{left, right}
		if result, ok := comparisons[pair]; ok {
			return result
		}
		result := winpath.Compare(string(left), string(right))
		comparisons[pair] = result
		return result
	}

	// Rolling-row DP implements star as either zero characters (next[vi]) or
	// one character while remaining on the star (current[vi+1]). Iterating the
	// target right-to-left makes both dependencies available, giving O(m*n)
	// work and O(n) state without recursive stacks or hash-map state overhead.
	next := make([]bool, len(value)+1)
	current := make([]bool, len(value)+1)
	next[len(value)] = true
	for pi := len(pattern) - 1; pi >= 0; pi-- {
		token := pattern[pi]
		for vi := len(value); vi >= 0; vi-- {
			switch token.kind {
			case globStar, globTreeStar:
				current[vi] = next[vi]
				if !current[vi] && vi < len(value) && (token.kind == globTreeStar || value[vi] != '\\') {
					current[vi] = current[vi+1]
				}
			case globQuestion:
				current[vi] = vi < len(value) && value[vi] != '\\' && next[vi+1]
			case globClass:
				current[vi] = windowsGlobClass(token, value, vi, compare) && next[vi+1]
			case globLiteral:
				current[vi] = vi < len(value) && compare(token.literal, value[vi]) == 0 && next[vi+1]
			}
		}
		next, current = current, next
	}
	return next[0], true
}

func windowsGlobClass(class globToken, value []rune, valueIndex int, compare func(rune, rune) int) bool {
	if valueIndex >= len(value) || value[valueIndex] == '\\' {
		return false
	}
	candidate := value[valueIndex]
	matched := false
	for _, part := range class.parts {
		matched = matched || compare(part.first, candidate) <= 0 &&
			compare(candidate, part.last) <= 0
	}
	if class.negated {
		matched = !matched
	}
	return matched
}

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
