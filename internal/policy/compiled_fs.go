package policy

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ReservedSpecFD is fd 3, on which the Linux re-exec parent passes the sealed
// stage-2 spec to its child. FirstPathHandleChildFD is the first descriptor a
// grant path handle may occupy, one above it: stdio holds 0-2 and the spec
// holds 3. Both live next to FSRule compilation so descriptor collision is
// impossible even though this pure compiler is also built on non-Linux hosts,
// and so the Linux stage-2 entry point and the rule enumerator cannot drift.
const (
	ReservedSpecFD         = 3
	FirstPathHandleChildFD = ReservedSpecFD + 1
)

func ValidateLandlockExactPaths(entries []FSEntry, handles []*PathHandle) error {
	for _, entry := range entries {
		if !entry.Exact || !entry.Canonical || entry.Access == 0 {
			continue
		}
		if MatchingPathHandleAncestor(handles, filepath.Clean(entry.Path), true) >= 0 {
			continue
		}
		info, err := os.Lstat(entry.Path)
		if err != nil {
			return fmt.Errorf("%w: Landlock exact path %q must already exist", ErrUnsupportedClass, entry.Path)
		}
		if info.IsDir() {
			return fmt.Errorf("%w: Landlock exact path %q is a directory", ErrUnsupportedClass, entry.Path)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: Landlock exact path %q is a symlink", ErrUnsupportedClass, entry.Path)
		}
	}
	return nil
}

type FSAllow struct {
	Path   string
	Access FSAccess
	Exact  bool
}

func (a FSAllow) writable() bool { return a.Access&WriteAccess != 0 }

type FSDeny struct {
	Path   string
	Access FSAccess
	Exact  bool
}

type CompiledFS struct {
	Allows []FSAllow
	Denies []FSDeny
}

func CompileFS(entries []FSEntry) CompiledFS {
	return CompileFSWithPathHandles(entries, nil)
}

func CompileFSWithPathHandles(entries []FSEntry, handles []*PathHandle) CompiledFS {
	var compiled CompiledFS
	for _, entry := range entries {
		if strings.ContainsAny(entry.Path, GlobMeta) {
			continue
		}
		path := filepath.Clean(entry.Path)
		if entry.Access != 0 {
			compiled.Allows = append(compiled.Allows, FSAllow{
				Path: path, Access: entry.Access, Exact: entry.Exact,
			})
		}
		if denied := NormalizedDenied(entry); denied != 0 {
			compiled.Denies = append(compiled.Denies, FSDeny{Path: path, Access: denied, Exact: entry.Exact})
		}
	}
	return compiled
}

// MatchingPathHandleAncestor returns the longest identity-pinned handle that can
// resolve path. Exact-file handles match only their exact target; directory
// handles match their target and descendants. Equal targets retain scope-shape
// compatibility so an exact directory rule cannot silently become a tree.
func MatchingPathHandleAncestor(handles []*PathHandle, path string, exact bool) int {
	path = filepath.Clean(path)
	best := -1
	bestLen := -1
	for index, handle := range handles {
		if handle == nil || handle.file == nil {
			continue
		}
		switch {
		case handle.target == path:
			if handle.exact != exact {
				continue
			}
		case handle.exact || !PathUnder(handle.target, path):
			continue
		}
		if len(handle.target) > bestLen {
			best = index
			bestLen = len(handle.target)
		}
	}
	return best
}

func MatchingPathHandleIdentityAncestor(handles []*PathHandle, path string) int {
	path = filepath.Clean(path)
	best := -1
	bestLen := -1
	for index, handle := range handles {
		if handle == nil || handle.file == nil {
			continue
		}
		if handle.target != path && (handle.exact || !PathUnder(handle.target, path)) {
			continue
		}
		if len(handle.target) > bestLen {
			best = index
			bestLen = len(handle.target)
		}
	}
	return best
}

// Resolve reports the access this compiled policy grants at path.
func (compiled CompiledFS) Resolve(path string) FSAccess {
	entries := make([]FSEntry, 0, len(compiled.Allows)+len(compiled.Denies))
	for _, allow := range compiled.Allows {
		entries = append(entries, FSEntry{Path: allow.Path, Access: allow.Access, Exact: allow.Exact})
	}
	for _, deny := range compiled.Denies {
		entries = append(entries, FSEntry{Path: deny.Path, Denied: deny.Access, Exact: deny.Exact})
	}
	return ResolveFS(entries, path)
}

// HasLiteralDeny reports whether any literal deny rule survived compilation.
func (compiled CompiledFS) HasLiteralDeny() bool { return len(compiled.Denies) > 0 }

// HasCarveout reports whether a writable allow contains a nested write deny.
func (compiled CompiledFS) HasCarveout() bool {
	for _, allow := range compiled.Allows {
		if !allow.writable() {
			continue
		}
		for _, deny := range compiled.Denies {
			if !allow.Exact && deny.Access&WriteAccess != 0 && PathUnder(allow.Path, deny.Path) {
				return true
			}
		}
	}
	return false
}

func PathUnder(parent, path string) bool {
	parent = filepath.Clean(parent)
	path = filepath.Clean(path)
	if parent == path {
		return false
	}
	if parent == string(filepath.Separator) {
		return filepath.IsAbs(path)
	}
	return strings.HasPrefix(path, parent+string(filepath.Separator))
}

type FSRule struct {
	Path           string
	Target         string
	ParentFD       int
	Access         FSAccess
	LandlockAccess uint64
	IsDir          bool
}

func (rule FSRule) writable() bool { return rule.Access&WriteAccess != 0 }

func EnumerateFSRules(compiled CompiledFS) []FSRule {
	rules, files, _ := EnumerateFSRulesWithPathHandles(compiled, nil)
	CloseRuleFiles(files)
	return rules
}

func EnumerateFSRulesWithPathHandles(compiled CompiledFS, handles []*PathHandle) ([]FSRule, []*os.File, error) {
	accumulator := ruleAcc{seen: make(map[string]FSRule)}
	resolver := NewPinnedPathResolver(handles, FirstPathHandleChildFD+len(handles))
	for _, allow := range compiled.Allows {
		for _, bit := range []FSAccess{ReadAccess, ExecAccess, WriteAccess} {
			if allow.Access&bit == 0 || deniedAtSamePath(allow, bit, compiled.Denies) {
				continue
			}
			excludes := excludesForAllowAxis(allow.Path, bit, compiled.Denies)
			pinnedAncestor := MatchingPathHandleAncestor(handles, allow.Path, allow.Exact) >= 0
			resolved, pinned, err := resolver.resolve(allow.Path, allow.Exact)
			if err != nil {
				CloseRuleFiles(resolver.files)
				return nil, nil, err
			}
			if pinnedAncestor {
				if !pinned {
					continue
				}
				if len(excludes) == 0 {
					accumulator.add(FSRule{
						Target:   allow.Path,
						ParentFD: resolved.ChildFD,
						Access:   bit,
						IsDir:    resolved.IsDir,
					})
					continue
				}
				rules, err := enumeratePinnedTree(resolved.File, allow.Path, bit, excludes, resolver.addFile, resolver)
				if err != nil {
					CloseRuleFiles(resolver.files)
					return nil, nil, err
				}
				for _, rule := range rules {
					accumulator.add(rule)
				}
				continue
			}
			if len(excludes) == 0 {
				info, err := os.Stat(allow.Path)
				if err == nil {
					accumulator.add(FSRule{Path: allow.Path, Access: bit, IsDir: info.IsDir()})
				}
				continue
			}
			carveGrant(allow.Path, bit, excludes, accumulator.add)
		}
	}
	return accumulator.sorted(), resolver.files, nil
}

func CloseRuleFiles(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

func deniedAtSamePath(allow FSAllow, bit FSAccess, denies []FSDeny) bool {
	for _, deny := range denies {
		if deny.Path == allow.Path && deny.Access&bit != 0 && (!allow.Exact || deny.Exact) {
			return true
		}
	}
	return false
}

func excludesForAllowAxis(path string, bit FSAccess, denies []FSDeny) []string {
	var excludes []string
	for _, deny := range denies {
		if deny.Access&bit != 0 && PathUnder(path, deny.Path) {
			excludes = append(excludes, deny.Path)
		}
	}
	return excludes
}

func carveGrant(dir string, access FSAccess, excludes []string, emit func(FSRule)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		child := filepath.Join(dir, entry.Name())
		if slices.Contains(excludes, child) {
			continue
		}
		info, err := os.Lstat(child)
		if err != nil || info.Mode()&fs.ModeSymlink != 0 {
			continue
		}
		nested := excludesUnder(excludes, child)
		if len(nested) == 0 {
			emit(FSRule{Path: child, Access: access, IsDir: info.IsDir()})
			continue
		}
		if info.IsDir() {
			carveGrant(child, access, nested, emit)
		}
	}
}

func excludesUnder(excludes []string, parent string) []string {
	var nested []string
	for _, exclude := range excludes {
		if PathUnder(parent, exclude) {
			nested = append(nested, exclude)
		}
	}
	return nested
}

type ruleAcc struct{ seen map[string]FSRule }

func (accumulator ruleAcc) add(rule FSRule) {
	key := rule.Path
	if rule.ParentFD != 0 {
		key = fmt.Sprintf("fd:%d", rule.ParentFD)
	}
	if previous, ok := accumulator.seen[key]; ok {
		previous.Access |= rule.Access
		if previous.Target == "" {
			previous.Target = rule.Target
		}
		accumulator.seen[key] = previous
		return
	}
	accumulator.seen[key] = rule
}

func (accumulator ruleAcc) sorted() []FSRule {
	rules := make([]FSRule, 0, len(accumulator.seen))
	for _, rule := range accumulator.seen {
		rules = append(rules, rule)
	}
	slices.SortFunc(rules, func(left, right FSRule) int {
		if left.ParentFD != right.ParentFD {
			return left.ParentFD - right.ParentFD
		}
		return strings.Compare(left.Path, right.Path)
	})
	return rules
}
