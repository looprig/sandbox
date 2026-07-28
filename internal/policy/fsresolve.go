package policy

import (
	"path/filepath"
	"regexp"
	"strings"
)

// ResolveFS computes the effective FSAccess a policy grants to an absolute target
// path, applying the SPEC §5.1 precedence model. It is a pure function: it makes
// no OS or filesystem calls and only reasons over the entries and the path
// string, so it is a faithful statement of policy intent shared by the OS
// backends and the ReadGuard adapter.
//
// The model resolves read, execute, and write independently. For each bit, the
// most-specific matching entry wins; explicit deny wins a true tie. Exact paths
// outrank trees at the same spelling, so an approved exact object can open
// without opening children. Glob denies remain hard fail-closed overrides
// because backend glob masking cannot safely restore narrower descendants. If
// no entry controls a bit, that bit is denied.
//
// Contract: target must be an absolute, canonical, symlink-resolved path.
// ResolveFS is purely lexical — it does no symlink resolution and performs only
// the platform path-key normalization used by literal matches plus
// filepath.Clean. Windows keys fold case and separators; Unix keys remain byte
// and separator sensitive. Passing an unresolved path could let a deny be
// bypassed via a symlink or a case variant on macOS.
func ResolveFS(entries []FSEntry, path string) FSAccess {
	target := pathKey(filepath.Clean(path))
	var globDenied FSAccess
	for _, entry := range entries {
		if strings.ContainsAny(entry.Path, GlobMeta) && denyMatches(entry, target) {
			globDenied |= NormalizedDenied(entry)
		}
	}

	var result FSAccess
	for _, bit := range []FSAccess{ReadAccess, ExecAccess, WriteAccess} {
		bestSpec := -1
		allowed := false
		denied := false
		for _, entry := range entries {
			entryDenied := NormalizedDenied(entry)
			if entry.Access&bit == 0 && entryDenied&bit == 0 {
				continue
			}
			matches := entryMatches(entry, target)
			if entryDenied&bit != 0 {
				matches = denyMatches(entry, target)
			}
			if !matches {
				continue
			}
			spec := EntryPrecedence(entry)
			switch {
			case spec > bestSpec:
				bestSpec = spec
				allowed = entry.Access&bit != 0
				denied = entryDenied&bit != 0
			case spec == bestSpec:
				allowed = allowed || entry.Access&bit != 0
				denied = denied || entryDenied&bit != 0
			}
		}
		if bestSpec >= 0 && allowed && !denied {
			result |= bit
		}
	}
	return result &^ globDenied
}

func NormalizedDenied(entry FSEntry) FSAccess {
	if entry.Access == 0 && entry.Denied == 0 {
		return AllAccess
	}
	return entry.Denied
}

// GlobMeta are the glob metacharacters whose presence makes an entry a glob
// rather than a literal path.
const GlobMeta = "*?["

// entryMatches reports whether an ALLOW entry's Path matches an already-cleaned
// target path, dispatching on whether the entry is a glob or a literal. It fails
// closed by under-granting: an uncompilable allow glob (GlobRegexp == nil)
// simply grants nothing, so a malformed allow never widens access.
func entryMatches(entry FSEntry, target string) bool {
	if strings.ContainsAny(entry.Path, GlobMeta) {
		matched, valid := globMatches(entry.Path, target)
		return valid && matched
	}
	return LiteralMatches(entry.Path, target, entry.Exact)
}

// denyMatches reports whether a DENY entry matches an already-cleaned target
// path. Unlike entryMatches it fails closed by over-denying: an uncompilable
// deny glob (GlobRegexp == nil) is treated as a MATCH so a malformed pattern
// over-denies rather than silently letting the path through. A deny that
// silently does not deny is the one failure mode this resolver must never have.
func denyMatches(entry FSEntry, target string) bool {
	if strings.ContainsAny(entry.Path, GlobMeta) {
		matched, valid := globMatches(entry.Path, target)
		return !valid || matched
	}
	return LiteralMatches(entry.Path, target, entry.Exact)
}

// LiteralMatches reports whether target is entryPath or is nested under it at a
// path boundary, so "/work/repo" matches "/work/repo" and "/work/repo/src" but
// not "/work/repository". A platform volume root matches everything on that
// volume.
func LiteralMatches(entryPath, target string, exact bool) bool {
	ep := pathKey(entryPath)
	target = pathKey(target)
	if exact {
		return literalPathEqual(target, ep)
	}
	if pathKeyIsRoot(ep) {
		return rootMatchesVolume(pathKeyVolume(ep), pathKeyVolume(target))
	}
	if literalPathEqual(target, ep) {
		return true
	}
	return literalPathHasComponentPrefix(target, ep)
}

func rootMatchesVolume(entryVolume, targetVolume string) bool {
	return entryVolume == "" || literalVolumeEqual(entryVolume, targetVolume)
}

// entrySpecificity is the length of an entry's matched literal prefix: the
// cleaned path for a literal, or the cleaned substring before the first glob
// metacharacter for a glob. Longer means more specific. Cleaning both forms
// keeps the ranking symmetric so a non-canonical glob prefix cannot over-count.
func entrySpecificity(entryPath string) int {
	prefix := entryPath
	if i := strings.IndexAny(entryPath, GlobMeta); i >= 0 {
		prefix = entryPath[:i]
	}
	if prefix == "" {
		// A glob with no literal prefix (e.g. "**/.env*") is maximally
		// unspecific; filepath.Clean("") would misleadingly report "." (len 1).
		return 0
	}
	return len(pathKey(prefix))
}

// EntryPrecedence refines lexical specificity with scope shape. An exact path
// controls only one object and therefore outranks a recursive tree rooted at
// the same spelling, without opening any child of that tree.
func EntryPrecedence(entry FSEntry) int {
	precedence := entrySpecificity(entry.Path) * 2
	if entry.Exact {
		precedence++
	}
	return precedence
}

// GlobRegexp compiles a glob pattern into an anchored regexp implementing the
// §5.1 glob semantics: "**" crosses directory separators, "*" and "?" stay
// within a single segment, and all other characters are matched literally. It
// returns nil if the pattern cannot be compiled (a malformed bracket
// expression). The nil is not itself a match verdict: callers decide the
// fail-closed direction — denyMatches treats nil as a match (over-deny), while
// entryMatches treats nil as a non-match (under-grant on the allow side).
func GlobRegexp(glob string) *regexp.Regexp {
	tokens, err := parseGlob(glob)
	if err != nil {
		return nil
	}
	re, err := regexp.Compile(globRegexpSource(tokens))
	if err != nil {
		return nil
	}
	return re
}

// GlobToRegexp translates a glob into an anchored regexp source string.
// filepath.Match has no "**", so the translation is done by hand: "**" -> ".*",
// "*" and "?" stay within the current platform's path separator, bracket
// expressions are emitted from the canonical rune representation (with a
// leading "!" negation rewritten to regexp "^"), and every literal rune is
// escaped via regexp.QuoteMeta so metacharacters such as "." match literally.
func GlobToRegexp(glob string) string {
	tokens, err := parseGlob(glob)
	if err != nil {
		// Preserve the public helper's contract as a regexp source. GlobRegexp
		// performs canonical validation before compiling, so consumers which
		// need a verdict must use it rather than compiling this sentinel.
		return "(?!)"
	}
	return globRegexpSource(tokens)
}
