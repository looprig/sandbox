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
	pattern := []rune(globPathKey(glob))
	value := []rune(globPathKey(target))
	// Reuse the canonical compiler as the syntax validator so malformed ranges
	// retain ResolveFS's fail-closed allow/deny behavior.
	if GlobRegexp(glob) == nil {
		return false, false
	}
	type state struct{ pattern, value int }
	memo := make(map[state]bool)
	seen := make(map[state]bool)
	var match func(int, int) (bool, bool)
	match = func(pi, vi int) (bool, bool) {
		key := state{pi, vi}
		if seen[key] {
			return memo[key], true
		}
		seen[key] = true
		if pi == len(pattern) {
			memo[key] = vi == len(value)
			return memo[key], true
		}
		switch pattern[pi] {
		case '*':
			crossesSeparators := pi+1 < len(pattern) && pattern[pi+1] == '*'
			next := pi + 1
			if crossesSeparators {
				next++
			}
			for end := vi; end <= len(value); end++ {
				if end > vi && !crossesSeparators && value[end-1] == '\\' {
					break
				}
				if ok, valid := match(next, end); !valid {
					return false, false
				} else if ok {
					memo[key] = true
					return true, true
				}
			}
			return false, true
		case '?':
			if vi < len(value) && value[vi] != '\\' {
				memo[key], _ = match(pi+1, vi+1)
			}
			return memo[key], true
		case '[':
			end, classMatch, valid := windowsGlobClass(pattern, pi, value, vi)
			if !valid {
				return false, false
			}
			if classMatch {
				memo[key], _ = match(end, vi+1)
			}
			return memo[key], true
		default:
			if vi < len(value) && winpath.Compare(string(pattern[pi]), string(value[vi])) == 0 {
				memo[key], _ = match(pi+1, vi+1)
			}
			return memo[key], true
		}
	}
	return match(0, 0)
}

func windowsGlobClass(pattern []rune, start int, value []rune, valueIndex int) (int, bool, bool) {
	i := start + 1
	negated := false
	if i < len(pattern) && (pattern[i] == '!' || pattern[i] == '^') {
		negated = true
		i++
	}
	classStart := i
	if i < len(pattern) && pattern[i] == ']' {
		i++
	}
	for i < len(pattern) && pattern[i] != ']' {
		i++
	}
	if i == len(pattern) {
		return 0, false, false
	}
	if valueIndex >= len(value) || value[valueIndex] == '\\' {
		return i + 1, false, true
	}
	candidate := string(value[valueIndex])
	matched := false
	for j := classStart; j < i; {
		if j+2 < i && pattern[j+1] == '-' {
			matched = matched || winpath.Compare(string(pattern[j]), candidate) <= 0 &&
				winpath.Compare(candidate, string(pattern[j+2])) <= 0
			j += 3
			continue
		}
		matched = matched || winpath.Compare(string(pattern[j]), candidate) == 0
		j++
	}
	if negated {
		matched = !matched
	}
	return i + 1, matched, true
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
