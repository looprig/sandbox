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
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: Landlock exact path %q is not a regular file", ErrUnsupportedClass, entry.Path)
		}
		if !directRegularFileRuleSafe(info) {
			return fmt.Errorf("%w: Landlock exact path %q has multiple hard links", ErrUnsupportedClass, entry.Path)
		}
	}
	return nil
}

type FSAllow struct {
	Path   string
	Access FSAccess
	Exact  bool
}

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

// SnapshotAxes reports the access axes for which a recursive allow contains a
// narrower literal deny. It also includes write when read or execute is denied:
// granting directory write would permit pathname replacement around the denied
// axis, so recursive denied scopes derive write denial throughout their subtree.
// Landlock must enumerate existing unaffected children instead of granting the
// covering allow root on each returned axis.
func (compiled CompiledFS) SnapshotAxes() FSAccess {
	var axes FSAccess
	for _, allow := range compiled.Allows {
		if allow.Exact {
			continue
		}
		overlappingAccess := allowedAccessOverlappingTree(compiled.Allows, allow.Path)
		for _, deny := range compiled.Denies {
			nested := PathUnder(allow.Path, deny.Path)
			equal := allow.Path == deny.Path
			covered := !deny.Exact && PathUnder(deny.Path, allow.Path)
			if nested || equal && deny.Exact {
				axes |= allow.Access & deny.Access
			}
			if allow.Access&WriteAccess != 0 &&
				((overlappingAccess&deny.Access&(ReadAccess|ExecAccess) != 0 &&
					(nested || equal && (deny.Exact || deny.Access&WriteAccess == 0))) ||
					covered && deny.Access&(ReadAccess|ExecAccess) != 0) {
				axes |= WriteAccess
			}
		}
	}
	return axes
}

func allowedAccessOverlappingTree(allows []FSAllow, path string) FSAccess {
	var access FSAccess
	for _, allow := range allows {
		if allow.Path == path || PathUnder(path, allow.Path) ||
			!allow.Exact && PathUnder(allow.Path, path) {
			access |= allow.Access
		}
	}
	return access
}

// HasCarveout reports whether a writable allow contains a nested write deny.
func (compiled CompiledFS) HasCarveout() bool {
	for _, allow := range compiled.Allows {
		if allow.Exact || allow.Access&WriteAccess == 0 {
			continue
		}
		for _, deny := range compiled.Denies {
			if deny.Access&WriteAccess != 0 && PathUnder(allow.Path, deny.Path) {
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

// EnumerateFSRules compiles only path-backed directory rules for callers that
// cannot retain descriptors. Direct regular-file rules require
// EnumerateFSRulesWithPathHandles so their checked inode remains bound until
// stage 2. Other direct filesystem node classes are omitted fail-narrow.
func EnumerateFSRules(compiled CompiledFS) []FSRule {
	rules, files, _ := EnumerateFSRulesWithPathHandles(compiled, nil)
	CloseRuleFiles(files)
	kept := rules[:0]
	for _, rule := range rules {
		if rule.ParentFD == 0 {
			kept = append(kept, rule)
		}
	}
	return kept
}

func EnumerateFSRulesWithPathHandles(compiled CompiledFS, handles []*PathHandle) ([]FSRule, []*os.File, error) {
	resolver := NewPinnedPathResolver(handles, FirstPathHandleChildFD+len(handles))
	return enumerateFSRulesWithResolver(compiled, handles, resolver)
}

func enumerateFSRulesWithResolver(compiled CompiledFS, handles []*PathHandle, resolver *PinnedPathResolver) ([]FSRule, []*os.File, error) {
	accumulator := ruleAcc{seen: make(map[string]FSRule)}
	for _, allow := range compiled.Allows {
		for _, bit := range []FSAccess{ReadAccess, ExecAccess, WriteAccess} {
			if allow.Access&bit == 0 || deniedAtSamePath(allow, bit, compiled.Denies) ||
				deniedByRecursiveTopology(allow, bit, compiled.Denies) {
				continue
			}
			excludes := excludesForAllowAxis(allow, bit, compiled.Allows, compiled.Denies)
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
					if !resolved.IsDir {
						info, err := resolved.File.Stat()
						if err != nil {
							CloseRuleFiles(resolver.files)
							return nil, nil, fmt.Errorf("%w: stat pinned file %q: %v", ErrUnsupportedClass, allow.Path, err)
						}
						if !directRegularFileRuleSafe(info) {
							continue
						}
					}
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
				info, err := os.Lstat(allow.Path)
				if err == nil && info.Mode()&fs.ModeSymlink == 0 {
					rule, ok, err := resolver.directRule(allow.Path, bit, info)
					if err != nil {
						CloseRuleFiles(resolver.files)
						return nil, nil, err
					}
					if ok {
						accumulator.add(rule)
					}
				}
				continue
			}
			err = carveGrant(allow.Path, bit, excludes, func(path string, access FSAccess, info os.FileInfo) error {
				rule, ok, err := resolver.directRule(path, access, info)
				if err != nil {
					return err
				}
				if ok {
					accumulator.add(rule)
				}
				return nil
			})
			if err != nil {
				CloseRuleFiles(resolver.files)
				return nil, nil, err
			}
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
		if deny.Path == allow.Path && deny.Exact == allow.Exact && deny.Access&bit != 0 {
			return true
		}
	}
	return false
}

func deniedByRecursiveTopology(allow FSAllow, bit FSAccess, denies []FSDeny) bool {
	if bit != WriteAccess || allow.Exact {
		return false
	}
	for _, deny := range denies {
		if !deny.Exact && deny.Access&(ReadAccess|ExecAccess) != 0 &&
			(deny.Path == allow.Path || PathUnder(deny.Path, allow.Path)) {
			return true
		}
	}
	return false
}

type fsExclude struct {
	Path  string
	Exact bool
	Deny  bool
}

func excludesForAllowAxis(allow FSAllow, bit FSAccess, allows []FSAllow, denies []FSDeny) []fsExclude {
	var excludes []fsExclude
	overlappingAccess := allowedAccessOverlappingTree(allows, allow.Path)
	for _, deny := range denies {
		nested := PathUnder(allow.Path, deny.Path)
		equal := allow.Path == deny.Path
		deniesAxis := deny.Access&bit != 0 && (nested || equal && !allow.Exact && deny.Exact)
		topologyBarrier := bit == WriteAccess && !allow.Exact &&
			overlappingAccess&deny.Access&(ReadAccess|ExecAccess) != 0 &&
			(nested || equal)
		if deniesAxis || topologyBarrier {
			excludes = append(excludes, fsExclude{
				Path: deny.Path, Exact: deny.Exact,
				Deny: deniesAxis || topologyBarrier && !deny.Exact,
			})
		}
	}
	return excludes
}

func carveGrant(dir string, access FSAccess, excludes []fsExclude, emit func(string, FSAccess, os.FileInfo) error) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	for _, entry := range entries {
		child := filepath.Join(dir, entry.Name())
		denyRecursive, denyExact := exclusionAt(excludes, child)
		if denyRecursive {
			continue
		}
		info, err := os.Lstat(child)
		if err != nil || info.Mode()&fs.ModeSymlink != 0 {
			continue
		}
		nested := excludesUnder(excludes, child)
		if denyExact {
			if info.IsDir() {
				if err := carveGrant(child, access, nested, emit); err != nil {
					return err
				}
			}
			continue
		}
		if len(nested) == 0 {
			if err := emit(child, access, info); err != nil {
				return err
			}
			continue
		}
		if info.IsDir() {
			if err := carveGrant(child, access, nested, emit); err != nil {
				return err
			}
		}
	}
	return nil
}

func exclusionAt(excludes []fsExclude, path string) (recursive, exact bool) {
	for _, exclude := range excludes {
		if exclude.Path != path || !exclude.Deny {
			continue
		}
		if exclude.Exact {
			exact = true
		} else {
			recursive = true
		}
	}
	return recursive, exact
}

func excludesUnder(excludes []fsExclude, parent string) []fsExclude {
	var nested []fsExclude
	for _, exclude := range excludes {
		if PathUnder(parent, exclude.Path) {
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
