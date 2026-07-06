//go:build linux

package sandbox

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// This file compiles a Policy's filesystem axis into a go-landlock ruleset for
// the rung-2 backend (SPEC §7.2, §7.5). Landlock is ADDITIVE (allowlist-only, no
// deny rules), so a fixed-path deny compiles by ENUMERATED SIBLING ALLOWS: at
// spawn, grant the siblings of a denied path instead of the parent, inode-pinned
// with snapshot semantics (entries created after the spawn-time enumeration are
// inaccessible for that command — which errs narrow, §7.5).
//
// Two-phase design across the re-exec:
//   - compile time (once, in linuxBackend.compile): distil the Policy's FS axis
//     into a compiledFS — the literal ALLOW entries with their access bits and
//     the literal DENY paths. Globs are not expressible at rung 2 and are
//     dropped here (recorded in the CompileReport).
//   - spawn time (per spawn, in the wrap/configure closure): enumerateFSRules
//     walks the live filesystem, carving each deny/read-only-carveout out of its
//     covering allow, and produces a flat []fsRule. That slice is gob-encoded
//     into the stage2Spec and rebuilt into a go-landlock ruleset by the stage-2
//     child (applyLandlockRules), which restricts itself BEFORE execve.
//
// Enumeration is deliberately at SPAWN time (a fresh snapshot each spawn), not at
// compile time: a secret that exists when a command starts is masked, and the
// only escape is a file the command itself creates mid-run — which by
// construction holds no pre-existing secret (§7.5).
//
// Deny paths must name the REAL (symlink-resolved) path. Landlock enforces by
// inode, so a deny at a symlink path protects only that symlink entry, not the
// symlink's target reached via a different path; and a deny whose ancestor is a
// symlink is enumerated on the symlink, not its target. The §5.3 default secret
// denies are canonical ($HOME-anchored), so this is a caveat for hand-authored
// deny globs/paths, not the presets. A consumer feeding user paths should
// filepath.EvalSymlinks them first (mirrors the fsresolve.go Task-4 carry-forward).

// fsRule is one compiled, spawn-time-enumerated Landlock allow. It crosses the
// re-exec via encoding/gob, so every field is exported and a concrete type
// (Access is a uint8 alias; IsDir a bool). The stage-2 child maps each fsRule to
// a go-landlock RODirs/ROFiles/RWDirs/RWFiles by IsDir and the WriteAccess bit.
type fsRule struct {
	// Path is the absolute, cleaned path this rule grants.
	Path string
	// Access is the granted access; only the WriteAccess bit is consulted when
	// rebuilding the go-landlock rule (RODirs already bundles read+exec).
	Access FSAccess
	// IsDir selects a directory rule (RODirs/RWDirs) vs a file rule
	// (ROFiles/RWFiles), determined by an os.Stat at enumeration time.
	IsDir bool
}

// writable reports whether the rule grants write access (RW* vs RO*).
func (r fsRule) writable() bool { return r.Access&WriteAccess != 0 }

// fsAllow is a single literal ALLOW entry after compile-time distillation: an
// absolute cleaned path with its granted access bits.
type fsAllow struct {
	path   string
	access FSAccess
}

// writable reports whether the allow grants write access.
func (a fsAllow) writable() bool { return a.access&WriteAccess != 0 }

// compiledFS is the rung-2 filesystem intent distilled from a Policy at compile
// time: the literal ALLOW entries and the literal DENY paths. Globs (allow or
// deny) are not carried — Landlock cannot express them at rung 2 — and their
// presence in the source policy is recorded separately in the CompileReport.
type compiledFS struct {
	// allows are the literal ALLOW entries (Access != DenyAccess), cleaned.
	allows []fsAllow
	// denies are the literal DENY paths (Access == DenyAccess), cleaned.
	denies []string
}

// compileFSPolicy distils a Policy's FS entries into a compiledFS. Literal allow
// entries and literal deny paths are carried; glob entries (either kind) are
// dropped — Landlock's additive model cannot express a glob deny at rung 2, and
// a glob allow is not present in the presets. Dropping is the fail-secure
// direction for allows (under-grant) and is separately recorded for denies.
func compileFSPolicy(entries []FSEntry) compiledFS {
	var cfs compiledFS
	for _, e := range entries {
		clean := filepath.Clean(e.Path)
		if strings.ContainsAny(e.Path, globMeta) {
			// A glob entry is inexpressible in Landlock at rung 2; skip it. Deny
			// globs are recorded unenforced by the CompileReport; allow globs (none
			// in the presets) simply under-grant, which is fail secure.
			continue
		}
		if e.Access == DenyAccess {
			cfs.denies = append(cfs.denies, clean)
			continue
		}
		cfs.allows = append(cfs.allows, fsAllow{path: clean, access: e.Access})
	}
	return cfs
}

// hasLiteralDeny reports whether any enforceable fixed-path deny is present.
func (c compiledFS) hasLiteralDeny() bool { return len(c.denies) > 0 }

// hasCarveout reports whether any read-only ALLOW sits strictly under a writable
// ALLOW — the .git/.looprig carveout shape that forces snapshot semantics on its
// writable root (the root is enumerated, not granted whole).
func (c compiledFS) hasCarveout() bool {
	for _, a := range c.allows {
		if !a.writable() {
			continue
		}
		for _, b := range c.allows {
			if b.path != a.path && !b.writable() && pathUnder(a.path, b.path) {
				return true
			}
		}
	}
	return false
}

// enumerateFSRules walks the live filesystem to produce the flat Landlock
// allowlist for one spawn (a fresh snapshot). Each ALLOW entry is granted
// directly when nothing must be carved out of it; otherwise carveGrant walks the
// tree, granting the siblings of every excluded path (deny subtrees, and
// read-only carveouts nested under a writable root) but never the excluded path
// itself. Excludes are existence-gated: a deny or carveout that does not exist on
// disk at spawn is not carved (there is nothing to protect, and a path the
// command later creates is the accepted §7.5 self-created residual).
func enumerateFSRules(cfs compiledFS) []fsRule {
	acc := ruleAcc{seen: make(map[string]fsRule)}
	for _, a := range cfs.allows {
		// Deny is a HARD OVERRIDE (fsresolve.go / SPEC §5.1): a literal deny that is
		// an ancestor-or-equal of an allow overrides that allow entirely. Drop such
		// an allow — granting it would be WIDER than the policy (a proven fail-open
		// for deny==allow, and the same class for a deny above a nested allow). The
		// denied subtree still gets carved out of any broader allow (e.g. the "/"
		// read), so the net result is correctly "no access" = deny wins. A deny
		// strictly UNDER the allow is handled by carveGrant below, not here.
		if deniedAtOrUnder(a.path, cfs.denies) {
			continue
		}
		excl := excludesForAllow(a, cfs)
		if len(excl) == 0 {
			// Straightforward allow: stat the path to classify dir vs file and to
			// drop a nonexistent path (fail secure — never grant what is not there).
			st, err := os.Stat(a.path)
			if err != nil {
				continue
			}
			acc.add(fsRule{Path: a.path, Access: a.access, IsDir: st.IsDir()})
			continue
		}
		// Deny/carveout nested under this allow: grant everything under a.path
		// except the excluded subtrees, by enumerated sibling allows.
		carveGrant(a.path, a.access, excl, acc.add)
	}
	return acc.sorted()
}

// excludesForAllow computes the set of paths that must be carved OUT of allow a:
// every literal deny strictly under a, plus — when a itself grants write — every
// read-only ALLOW strictly under a (the carveout). Both are existence-gated so a
// path that is not on disk at spawn is not carved (nothing to protect). A wider
// or equally-wide nested allow is NOT carved: unioning it back on top of a never
// exceeds the policy for that subtree.
func excludesForAllow(a fsAllow, cfs compiledFS) []string {
	var excl []string
	for _, d := range cfs.denies {
		if pathUnder(a.path, d) && pathExists(d) {
			excl = append(excl, d)
		}
	}
	if a.writable() {
		for _, b := range cfs.allows {
			if b.path == a.path || b.writable() {
				continue
			}
			if pathUnder(a.path, b.path) && pathExists(b.path) {
				excl = append(excl, b.path)
			}
		}
	}
	return excl
}

// carveGrant grants access on every entry under dir EXCEPT the excluded subtrees,
// recursing only into the children that actually lead to an exclude (so
// unaffected siblings are granted with a single rule each). dir itself is never
// granted — that is what yields the snapshot semantics for a carved writable root
// (a file created at the root after this enumeration is not covered, §7.5). All
// excludes are == or strictly under dir. Symlinked children are skipped (never
// follow a symlink out of the enumerated tree — fail secure; a symlink's real
// target is granted through its own real path when the policy covers it).
func carveGrant(dir string, access FSAccess, excludes []string, emit func(fsRule)) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		// Cannot enumerate: grant nothing under dir (fail secure / narrow).
		return
	}
	for _, de := range entries {
		child := filepath.Join(dir, de.Name())
		if containsPath(excludes, child) {
			continue // fully excluded subtree — grant nothing
		}
		info, lerr := os.Lstat(child)
		if lerr != nil {
			continue // vanished between ReadDir and Lstat (TOCTOU) — skip
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			continue // do not follow a symlink out of the tree — fail secure
		}
		sub := excludesUnder(excludes, child)
		if len(sub) == 0 {
			emit(fsRule{Path: child, Access: access, IsDir: info.IsDir()})
			continue
		}
		if info.IsDir() {
			carveGrant(child, access, sub, emit)
		}
		// A non-directory cannot have excludes nested under it — drop.
	}
}

// deniedAtOrUnder reports whether path is at-or-under any deny — i.e. some deny
// is an ancestor of path OR equals it. This is the "deny is a hard override"
// rule (fsresolve.go): such a path must not be granted directly, because deny
// beats any allow at or below the deny path.
func deniedAtOrUnder(path string, denies []string) bool {
	for _, d := range denies {
		if d == path || pathUnder(d, path) {
			return true
		}
	}
	return false
}

// pathUnder reports whether path is strictly nested under parent at a path
// boundary (parent != path). Both are cleaned. The root "/" is the parent of
// every other absolute path.
func pathUnder(parent, path string) bool {
	parent = filepath.Clean(parent)
	path = filepath.Clean(path)
	if parent == path {
		return false
	}
	if parent == "/" {
		return strings.HasPrefix(path, "/") && path != "/"
	}
	return strings.HasPrefix(path, parent+"/")
}

// containsPath reports whether list contains p exactly (both already cleaned).
func containsPath(list []string, p string) bool {
	return slices.Contains(list, p)
}

// excludesUnder returns the subset of excludes that lie strictly under parent.
func excludesUnder(excludes []string, parent string) []string {
	var out []string
	for _, e := range excludes {
		if pathUnder(parent, e) {
			out = append(out, e)
		}
	}
	return out
}

// pathExists reports whether path exists on disk (via Lstat, so a symlink or a
// broken symlink counts as existing — a deny at a symlink path is still carved
// rather than followed).
func pathExists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// ruleAcc accumulates emitted rules, de-duplicating by path and OR-ing access
// bits so a path covered by two allows (e.g. a broad read plus a writable root)
// gets the union, and each Landlock path is added at most once.
type ruleAcc struct {
	seen map[string]fsRule
}

// add records a rule, merging access with any prior rule for the same path.
func (a ruleAcc) add(r fsRule) {
	if prev, ok := a.seen[r.Path]; ok {
		prev.Access |= r.Access
		// IsDir is a property of the path, identical across emits; keep prev.
		a.seen[r.Path] = prev
		return
	}
	a.seen[r.Path] = r
}

// sorted returns the accumulated rules in a stable path order (deterministic
// output across spawns and for tests).
func (a ruleAcc) sorted() []fsRule {
	out := make([]fsRule, 0, len(a.seen))
	for _, r := range a.seen {
		out = append(out, r)
	}
	slices.SortFunc(out, func(x, y fsRule) int { return strings.Compare(x.Path, y.Path) })
	return out
}

// applyLandlockRules rebuilds a go-landlock ruleset from the spawn-time
// enumerated allowlist and restricts the CURRENT process (and everything it
// subsequently execve's) to it, using the exact ABI v4 config (SPEC §7.2 rung 2).
// It is called by the stage-2 child BEFORE chdir/execve; a non-nil return makes
// the child fail closed so the target never runs unconfined.
//
// The exact landlock.V4 config (not BestEffort) is deliberate: a kernel missing
// ABI v4 makes RestrictPaths error — a hard fail-closed — rather than silently
// no-op'ing the confinement. Rung 2 is only selected when ABI >= 4, so on the
// selecting host this always enforces. Every rule is IgnoreIfMissing so a path
// removed between enumeration and application (TOCTOU) is skipped (narrower)
// rather than aborting the whole ruleset.
func applyLandlockRules(rules []fsRule) error {
	landRules := make([]landlock.Rule, 0, len(rules))
	for _, r := range rules {
		landRules = append(landRules, landlockRule(r))
	}
	return landlock.V4.RestrictPaths(landRules...)
}

// landlockRule maps one fsRule to a go-landlock rule via PathAccess, honoring
// each of the Read/Exec/Write bits INDEPENDENTLY so the compiled access is never
// WIDER than the policy entry (SPEC §7.5). The canned RODirs/RWDirs helpers bundle
// execute into every read grant, which would over-grant execute on a read-only
// (no-Exec) entry — e.g. a `.git` carveout or a hand-authored read-only path.
// PathAccess with a precisely-assembled AccessFSSet avoids that; it also clamps
// the set to the ABI's supported subset, so the mapping is kernel-version-safe.
func landlockRule(r fsRule) landlock.Rule {
	return landlock.PathAccess(landlockAccessSet(r.Access, r.IsDir), r.Path).IgnoreIfMissing()
}

// landlockAccessSet assembles the Landlock AccessFSSet for the given policy
// access bits and node kind. Read → read-file (+ read-dir for a directory);
// Exec → execute; Write → the mutation rights (matching go-landlock's own
// accessFSWrite set), with the directory-entry rights (make*/remove*) applied
// only to a directory rule. Bits absent from the policy access are never set, so
// a read-only entry grants no execute and no write.
func landlockAccessSet(access FSAccess, isDir bool) landlock.AccessFSSet {
	var set landlock.AccessFSSet
	if access&ReadAccess != 0 {
		set |= llsys.AccessFSReadFile
		if isDir {
			set |= llsys.AccessFSReadDir
		}
	}
	if access&ExecAccess != 0 {
		set |= llsys.AccessFSExecute
	}
	if access&WriteAccess != 0 {
		set |= llsys.AccessFSWriteFile | llsys.AccessFSTruncate
		if isDir {
			// make*/remove* operate on entries within a directory, so a writable
			// directory needs them to create/delete children; a writable file does
			// not. This mirrors go-landlock's accessFSWrite (config.go).
			set |= llsys.AccessFSRemoveDir | llsys.AccessFSRemoveFile |
				llsys.AccessFSMakeChar | llsys.AccessFSMakeDir | llsys.AccessFSMakeReg |
				llsys.AccessFSMakeSock | llsys.AccessFSMakeFifo | llsys.AccessFSMakeBlock |
				llsys.AccessFSMakeSym
		}
	}
	return set
}
