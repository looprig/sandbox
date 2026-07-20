package sandbox

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// firstGrantPathChildFD is fd 4: stdio occupies 0-2 and Linux reserves fd 3
// for the sealed stage-2 spec. Keeping this constant next to fsRule compilation
// makes descriptor collision impossible even though this pure compiler is also
// built on non-Linux hosts.
const firstGrantPathChildFD = 4

func validateLandlockExactPaths(entries []fsEntry, handles []*grantPathHandle) error {
	for _, entry := range entries {
		if !entry.Exact || !entry.Canonical || entry.Access == 0 {
			continue
		}
		if matchingGrantPathAncestor(handles, filepath.Clean(entry.Path), true) >= 0 {
			continue
		}
		info, err := os.Lstat(entry.Path)
		if err != nil {
			return fmt.Errorf("%w: Landlock exact path %q must already exist", ErrGrantUnsupported, entry.Path)
		}
		if info.IsDir() {
			return fmt.Errorf("%w: Landlock exact path %q is a directory", ErrGrantUnsupported, entry.Path)
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("%w: Landlock exact path %q is a symlink", ErrGrantUnsupported, entry.Path)
		}
	}
	return nil
}

type fsAllow struct {
	path   string
	access fsAccess
	exact  bool
}

func (a fsAllow) writable() bool { return a.access&writeFSAccess != 0 }

type fsDeny struct {
	path   string
	access fsAccess
	exact  bool
}

type compiledFS struct {
	allows []fsAllow
	denies []fsDeny
}

func compileFSPolicy(entries []fsEntry) compiledFS {
	return compileFSPolicyWithGrantPaths(entries, nil)
}

func compileFSPolicyWithGrantPaths(entries []fsEntry, handles []*grantPathHandle) compiledFS {
	var compiled compiledFS
	for _, entry := range entries {
		if strings.ContainsAny(entry.Path, globMeta) {
			continue
		}
		path := filepath.Clean(entry.Path)
		if entry.Access != 0 {
			compiled.allows = append(compiled.allows, fsAllow{
				path: path, access: entry.Access, exact: entry.Exact,
			})
		}
		if denied := normalizedDenied(entry); denied != 0 {
			compiled.denies = append(compiled.denies, fsDeny{path: path, access: denied, exact: entry.Exact})
		}
	}
	return compiled
}

// matchingGrantPathAncestor returns the longest identity-pinned handle that can
// resolve path. Exact-file handles match only their exact target; directory
// handles match their target and descendants. Equal targets retain scope-shape
// compatibility so an exact directory rule cannot silently become a tree.
func matchingGrantPathAncestor(handles []*grantPathHandle, path string, exact bool) int {
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
		case handle.exact || !pathUnder(handle.target, path):
			continue
		}
		if len(handle.target) > bestLen {
			best = index
			bestLen = len(handle.target)
		}
	}
	return best
}

func matchingGrantPathIdentityAncestor(handles []*grantPathHandle, path string) int {
	path = filepath.Clean(path)
	best := -1
	bestLen := -1
	for index, handle := range handles {
		if handle == nil || handle.file == nil {
			continue
		}
		if handle.target != path && (handle.exact || !pathUnder(handle.target, path)) {
			continue
		}
		if len(handle.target) > bestLen {
			best = index
			bestLen = len(handle.target)
		}
	}
	return best
}

func (compiled compiledFS) resolve(path string) fsAccess {
	entries := make([]fsEntry, 0, len(compiled.allows)+len(compiled.denies))
	for _, allow := range compiled.allows {
		entries = append(entries, fsEntry{Path: allow.path, Access: allow.access, Exact: allow.exact})
	}
	for _, deny := range compiled.denies {
		entries = append(entries, fsEntry{Path: deny.path, Denied: deny.access, Exact: deny.exact})
	}
	return resolveFS(entries, path)
}

func (compiled compiledFS) hasLiteralDeny() bool { return len(compiled.denies) > 0 }

func (compiled compiledFS) hasCarveout() bool {
	for _, allow := range compiled.allows {
		if !allow.writable() {
			continue
		}
		for _, deny := range compiled.denies {
			if !allow.exact && deny.access&writeFSAccess != 0 && pathUnder(allow.path, deny.path) {
				return true
			}
		}
	}
	return false
}

func pathUnder(parent, path string) bool {
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

type fsRule struct {
	Path           string
	Target         string
	ParentFD       int
	Access         fsAccess
	LandlockAccess uint64
	IsDir          bool
}

func (rule fsRule) writable() bool { return rule.Access&writeFSAccess != 0 }

func enumerateFSRules(compiled compiledFS) []fsRule {
	rules, files, _ := enumerateFSRulesWithGrantPaths(compiled, nil)
	closeGrantRuleFiles(files)
	return rules
}

func enumerateFSRulesWithGrantPaths(compiled compiledFS, handles []*grantPathHandle) ([]fsRule, []*os.File, error) {
	accumulator := ruleAcc{seen: make(map[string]fsRule)}
	resolver := newPinnedPathResolver(handles, firstGrantPathChildFD+len(handles))
	for _, allow := range compiled.allows {
		for _, bit := range []fsAccess{readFSAccess, execFSAccess, writeFSAccess} {
			if allow.access&bit == 0 || deniedAtSamePath(allow, bit, compiled.denies) {
				continue
			}
			excludes := excludesForAllowAxis(allow.path, bit, compiled.denies)
			pinnedAncestor := matchingGrantPathAncestor(handles, allow.path, allow.exact) >= 0
			resolved, pinned, err := resolver.resolve(allow.path, allow.exact)
			if err != nil {
				closeGrantRuleFiles(resolver.files)
				return nil, nil, err
			}
			if pinnedAncestor {
				if !pinned {
					continue
				}
				if len(excludes) == 0 {
					accumulator.add(fsRule{
						Target:   allow.path,
						ParentFD: resolved.childFD,
						Access:   bit,
						IsDir:    resolved.isDir,
					})
					continue
				}
				rules, err := enumeratePinnedTree(resolved.file, allow.path, bit, excludes, resolver.addFile, resolver)
				if err != nil {
					closeGrantRuleFiles(resolver.files)
					return nil, nil, err
				}
				for _, rule := range rules {
					accumulator.add(rule)
				}
				continue
			}
			if len(excludes) == 0 {
				info, err := os.Stat(allow.path)
				if err == nil {
					accumulator.add(fsRule{Path: allow.path, Access: bit, IsDir: info.IsDir()})
				}
				continue
			}
			carveGrant(allow.path, bit, excludes, accumulator.add)
		}
	}
	return accumulator.sorted(), resolver.files, nil
}

func closeGrantRuleFiles(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

func deniedAtSamePath(allow fsAllow, bit fsAccess, denies []fsDeny) bool {
	for _, deny := range denies {
		if deny.path == allow.path && deny.access&bit != 0 && (!allow.exact || deny.exact) {
			return true
		}
	}
	return false
}

func excludesForAllowAxis(path string, bit fsAccess, denies []fsDeny) []string {
	var excludes []string
	for _, deny := range denies {
		if deny.access&bit != 0 && pathUnder(path, deny.path) {
			excludes = append(excludes, deny.path)
		}
	}
	return excludes
}

func carveGrant(dir string, access fsAccess, excludes []string, emit func(fsRule)) {
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
			emit(fsRule{Path: child, Access: access, IsDir: info.IsDir()})
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
		if pathUnder(parent, exclude) {
			nested = append(nested, exclude)
		}
	}
	return nested
}

type ruleAcc struct{ seen map[string]fsRule }

func (accumulator ruleAcc) add(rule fsRule) {
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

func (accumulator ruleAcc) sorted() []fsRule {
	rules := make([]fsRule, 0, len(accumulator.seen))
	for _, rule := range accumulator.seen {
		rules = append(rules, rule)
	}
	slices.SortFunc(rules, func(left, right fsRule) int {
		if left.ParentFD != right.ParentFD {
			return left.ParentFD - right.ParentFD
		}
		return strings.Compare(left.Path, right.Path)
	})
	return rules
}
