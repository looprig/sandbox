package sandbox

import (
	"path/filepath"
	"regexp"
	"strings"
)

// Resolve computes the effective FSAccess a policy grants to an absolute target
// path, applying the SPEC §5.1 precedence model. It is a pure function: it makes
// no OS or filesystem calls and only reasons over the entries and the path
// string, so it is a faithful statement of policy intent shared by the OS
// backends and the ReadGuard adapter.
//
// The reconciled model (deny > write > read, longest-path wins within a class)
// is:
//
//  1. If any deny entry (Access == DenyAccess) matches the path — a literal
//     ancestor or a matching glob — the result is DenyAccess. Deny is a hard
//     override; a more specific allow does not rescue it.
//  2. Otherwise, among the matching allow entries the most specific wins.
//     Specificity is the length of the matched literal prefix: the cleaned path
//     for a literal entry, or the substring before the first glob metacharacter
//     for a glob entry. On an exact specificity tie the results union (OR).
//  3. If nothing matches, the result is DenyAccess (fail-closed).
//
// This yields the §5.1 carveout: a read-only ".git" entry nested inside a
// writable root is a longer allow than the root, so it wins and the workspace's
// history stays read-only — while a "**/.env*" deny still overrides that same
// writable root because deny is checked first.
func Resolve(entries []FSEntry, path string) FSAccess {
	target := filepath.Clean(path)

	// Rule 1: any matching deny entry is a hard override.
	for _, e := range entries {
		if e.Access == DenyAccess && entryMatches(e.Path, target) {
			return DenyAccess
		}
	}

	// Rule 2: among matching allow entries, the most specific wins; exact
	// specificity ties union their bits.
	var best FSAccess
	bestSpec := -1
	for _, e := range entries {
		if e.Access == DenyAccess || !entryMatches(e.Path, target) {
			continue
		}
		switch spec := entrySpecificity(e.Path); {
		case spec > bestSpec:
			bestSpec, best = spec, e.Access
		case spec == bestSpec:
			best |= e.Access
		}
	}
	if bestSpec < 0 {
		// Rule 3: nothing matched — fail closed.
		return DenyAccess
	}
	return best
}

// globMeta are the glob metacharacters whose presence makes an entry a glob
// rather than a literal path.
const globMeta = "*?["

// entryMatches reports whether an entry's Path matches an already-cleaned target
// path, dispatching on whether the entry is a glob or a literal.
func entryMatches(entryPath, target string) bool {
	if strings.ContainsAny(entryPath, globMeta) {
		re := globRegexp(entryPath)
		return re != nil && re.MatchString(target)
	}
	return literalMatches(entryPath, target)
}

// literalMatches reports whether target is entryPath or is nested under it at a
// path boundary, so "/work/repo" matches "/work/repo" and "/work/repo/src" but
// not "/work/repository". The root "/" matches everything.
func literalMatches(entryPath, target string) bool {
	ep := filepath.Clean(entryPath)
	if ep == "/" {
		return true
	}
	if target == ep {
		return true
	}
	return strings.HasPrefix(target, ep+"/")
}

// entrySpecificity is the length of an entry's matched literal prefix: the
// cleaned path for a literal, or the substring before the first glob
// metacharacter for a glob. Longer means more specific.
func entrySpecificity(entryPath string) int {
	if i := strings.IndexAny(entryPath, globMeta); i >= 0 {
		return i
	}
	return len(filepath.Clean(entryPath))
}

// globRegexp compiles a glob pattern into an anchored regexp implementing the
// §5.1 glob semantics: "**" crosses directory separators, "*" and "?" stay
// within a single segment, and all other characters are matched literally. It
// returns nil if the pattern cannot be compiled (a malformed bracket
// expression), in which case the entry simply does not match — mirroring how
// filepath.Match surfaces such patterns as an error rather than a match.
func globRegexp(glob string) *regexp.Regexp {
	re, err := regexp.Compile(globToRegexp(glob))
	if err != nil {
		return nil
	}
	return re
}

// globToRegexp translates a glob into an anchored regexp source string.
// filepath.Match has no "**", so the translation is done by hand: "**" -> ".*",
// "*" -> "[^/]*", "?" -> "[^/]", bracket expressions are carried through (with a
// leading "!" negation rewritten to regexp "^"), and every other byte is escaped
// via regexp.QuoteMeta so metacharacters such as "." match literally.
func globToRegexp(glob string) string {
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(glob); {
		switch c := glob[i]; c {
		case '*':
			if i+1 < len(glob) && glob[i+1] == '*' {
				b.WriteString(".*") // cross-directory
				i += 2
			} else {
				b.WriteString("[^/]*") // within a single segment
				i++
			}
		case '?':
			b.WriteString("[^/]")
			i++
		case '[':
			if class, next, ok := scanClass(glob, i); ok {
				b.WriteString(class)
				i = next
			} else {
				// Unterminated "[": treat it as a literal character.
				b.WriteString(regexp.QuoteMeta("["))
				i++
			}
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
			i++
		}
	}
	b.WriteByte('$')
	return b.String()
}

// scanClass reads a bracket expression starting at glob[start] == '['. On
// success it returns the regexp-equivalent class, the index just past the
// closing ']', and true. A leading "!" (glob negation) becomes regexp "^"; a "]"
// immediately after the opener (optionally after the negation) is a literal
// member per glob rules. It returns ok == false if there is no closing bracket.
func scanClass(glob string, start int) (class string, next int, ok bool) {
	j := start + 1
	if j < len(glob) && (glob[j] == '!' || glob[j] == '^') {
		j++
	}
	if j < len(glob) && glob[j] == ']' { // literal ']' as first member
		j++
	}
	for j < len(glob) && glob[j] != ']' {
		j++
	}
	if j >= len(glob) {
		return "", 0, false
	}
	body := glob[start+1 : j]
	if strings.HasPrefix(body, "!") {
		body = "^" + body[1:]
	}
	return "[" + body + "]", j + 1, true
}
