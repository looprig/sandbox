//go:build linux

package linux

import (
	"errors"
	"fmt"
	"github.com/looprig/sandbox/internal/policy"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// This file compiles a policy.Effective's filesystem axis into the RUNG-1 bind-mount VIEW
// (SPEC §7.2 Rung 1, §7.5) and carries the stage-2 mechanism that materializes
// it inside the child's mount namespace. Where Rung 2 (landlock_linux.go)
// enforces the FS axis by an ENUMERATED Landlock allowlist against the live
// filesystem, Rung 1 builds a NEW root and bind-mounts only the policy's roots
// into it, then pivot_roots into that new root — so any host path NOT bound is
// INVISIBLE (restricted-read = invisibility, the Rung-1 property Rung 2 cannot
// provide). Deny-inside-allow (carveouts + fixed-path secret denies) is Enforced
// by MOUNT RE-MASKING (§7.5): a read-only bind for a carveout, an empty
// read-only bind for a secret — no sibling enumeration, unlike Rung 2. Glob
// denies (§7.5) compile by spawn-time bounded enumeration (ScanGlobDenies) and
// mask each match with an empty read-only bind.
//
// CRITICAL — CI-verified, not host-verified. The enforcement mechanism
// (applyMountView: Private-remount → binds → masks → /proc → pivot_root) needs
// an unprivileged user+mount namespace with an EFFECTIVE CAP_SYS_ADMIN, which is
// blocked on the authoring host by apparmor_restrict_unprivileged_userns=1. The
// pure compilation (CompileMountView) and the spawn-time enumeration
// (EnumerateMountView / ScanGlobDenies — filesystem walks, no namespaces) are
// unit-tested and run on every host; the actual mounting is exercised only in CI.
//
// Two-phase design across the re-exec, mirroring Rung 2:
//   - compile time (once, in Backend.compileRung1): distil the policy.Effective's FS
//     axis into a MountViewPlan (rw/ro bind roots, safe literal deny masks, glob
//     deny patterns, glob scan roots). The mount view masks only full-path denies
//     with no narrower restoration; Landlock composes the remaining per-axis rules.
//   - spawn time (per spawn, in the wrap/configure closure): EnumerateMountView
//     stats each root (dir vs file, dropping nonexistent — fail secure) and
//     re-runs the glob scan, producing a MountViewSpec that is gob-encoded into
//     the Stage2Spec and applied by the stage-2 child (applyMountView) BEFORE
//     Landlock. Enumeration is at SPAWN time so the mask set is a fresh snapshot:
//     a secret present when the command starts is masked; the only escape is a
//     file the command itself creates mid-run (§7.5 residual — sound, does not
//     demote Level).

// GlobScanMaxDepth bounds the spawn-time glob-deny scan (SPEC §7.5). It mirrors
// Codex's glob_scan_max_depth precedent: deep enough to reach a repo-local
// `.env` a few directories down, shallow enough that the per-spawn scan of the
// workspace + $HOME stays cheap and bounded (a glob mask is spawn-time work on
// the hot path). A match below this depth is not masked for that spawn; the
// residual is recorded, never silently widened.
const GlobScanMaxDepth = 8

// mountViewOp is the Stage2Error.Op for every Rung-1 mount-view failure, so the
// whole view construction fails CLOSED under one recognizable label (SPEC §7.2).
const mountViewOp = "mount-view"

// emptyMaskFile is the scratch empty regular file (created on the new-root
// tmpfs) bound read-only over each masked FILE (a secret deny or a glob match),
// hiding the real file's contents behind an empty one. Directory masks use a
// fresh empty read-only tmpfs instead (applyMask).
const emptyMaskFile = ".lrsandbox-empty"

// oldRootDir is the pivot_root put_old directory (created on the new-root
// tmpfs). After pivot_root the previous root is detached from here (MNT_DETACH),
// which is what makes every host path NOT bound into the new root INVISIBLE.
const oldRootDir = ".lrsandbox-oldroot"

// MountViewPlan is the Rung-1 filesystem intent distilled from a policy.Effective at
// compile time (SPEC §7.2 Rung 1, §7.5). It holds bind ROOTS and deny intent,
// not stat'd entries: the dir/file classification and the glob scan are redone
// per spawn (EnumerateMountView) so the view is a fresh snapshot each time.
type MountViewPlan struct {
	// RWBinds are the writable allow roots (policy.WriteAccess) — bound rw into the view.
	RWBinds []string
	// ROBinds are the read-only allow roots (policy.ReadAccess, no policy.WriteAccess) — bound
	// ro. Carveouts (a policy.ReadAccess allow nested under a writable root, e.g. .git)
	// are ordinary ROBinds; nesting is resolved by applying binds parents-first so
	// the ro carveout re-masks the rw root it sits under.
	ROBinds []string
	// DenyMasks are literal (non-glob) fixed-path denies that have no
	// higher-precedence restoration and can therefore use a coarse empty
	// read-only mask. Restored literal precedence composes through Landlock.
	DenyMasks []string
	// GlobDenies are the glob deny patterns (e.g. **/.env*), Enforced by spawn-time
	// bounded enumeration (ScanGlobDenies) into empty read-only masks.
	GlobDenies []string
	// scanRoots are the roots scanned for GlobDenies (workspace + writable roots +
	// $HOME, §7.5). Bounded to GlobScanMaxDepth.
	scanRoots []string
	// grantBinds maps a granted canonical target to the inherited descriptor
	// index and type captured atomically by the executor.
	grantBinds map[string]grantMountSource
	// exactDenyMasks preserves scope shape for literal denies. An exact file can
	// be masked directly; an exact directory cannot, because overmounting the
	// directory would also hide descendants that the policy may retain.
	exactDenyMasks map[string]bool
	hasLiteralDeny bool
}

type grantMountSource struct {
	index int
	isDir bool
}

// hasDenies reports whether the plan carries any fixed or glob read-deny,
// including restored literal precedence enforced by composed Landlock rules.
func (p MountViewPlan) hasDenies() bool {
	return p.hasLiteralDeny || len(p.GlobDenies) > 0
}

// rung1Plan is the compiled Rung-1 confinement beyond the shared Landlock/Seccomp
// axes: the bind-mount view and the in-Netns nftables plan. It is closed over by
// the per-spawn wrap closure (linuxWrap) — nil for a Rung-2 spawn.
type rung1Plan struct {
	mount MountViewPlan
	nft   compiledNftPlan
}

// CompileMountView distils a policy.Effective's FS entries into a MountViewPlan (SPEC §7.2
// Rung 1). Literal allow roots become rw or ro binds; literal denies become
// masks when they deny every axis and have no narrower restoration; glob denies
// are carried for the spawn-time scan. Allow globs are dropped — a mount cannot
// express a glob allow, and dropping under-grants (fail secure). Landlock is
// layered over the mount view to enforce partial-axis and restored descendants.
func CompileMountView(p policy.Effective) MountViewPlan {
	return compileMountViewWithGrantPaths(p, nil)
}

func compileMountViewWithGrantPaths(p policy.Effective, handles []*policy.PathHandle) MountViewPlan {
	var plan MountViewPlan
	plan.grantBinds = make(map[string]grantMountSource)
	plan.exactDenyMasks = make(map[string]bool)
	type literalDeny struct {
		path      string
		exactOnly bool
	}
	var literalDenies []literalDeny
	denyIndex := make(map[string]int)

	// First pass: aggregate full-path denies by path. Duplicate exact + recursive
	// denies have recursive scope; only an all-exact group retains exact scope.
	// Partial-axis denies are Enforced by Landlock, which composes on top.
	for _, e := range p.FS {
		if policy.NormalizedDenied(e) != policy.AllAccess || e.Access != 0 {
			continue
		}
		if strings.ContainsAny(e.Path, policy.GlobMeta) {
			plan.GlobDenies = append(plan.GlobDenies, e.Path)
			continue
		}
		path := filepath.Clean(e.Path)
		plan.hasLiteralDeny = true
		if index, ok := denyIndex[path]; ok {
			literalDenies[index].exactOnly = literalDenies[index].exactOnly && e.Exact
			continue
		}
		denyIndex[path] = len(literalDenies)
		literalDenies = append(literalDenies, literalDeny{path: path, exactOnly: e.Exact})
	}

	// Second pass: merge allow entries by path (OR access bits) preserving first-
	// seen order, so a path granted read then write is bound rw exactly once. A
	// deny removes bits only at the same path AND scope shape: a strict descendant
	// allow is more specific, and an exact allow outranks a recursive deny at the
	// same spelling. Glob denies remain hard overrides enforced by masks/Landlock.
	merged := make(map[string]policy.FSAccess)
	var order []string
	for _, e := range p.FS {
		if e.Access == policy.DenyAccess || strings.ContainsAny(e.Path, policy.GlobMeta) {
			continue
		}
		clean := filepath.Clean(e.Path)
		access := survivingAllowAccess(p.FS, e)
		if access == 0 {
			continue
		}
		if _, ok := merged[clean]; !ok {
			order = append(order, clean)
		}
		merged[clean] |= access
		if index := policy.MatchingPathHandleAncestor(handles, clean, e.Exact); index >= 0 {
			plan.grantBinds[clean] = grantMountSource{index: index, isDir: handles[index].IsDir()}
		}
	}
	for _, deny := range literalDenies {
		if !denyHasRestoration(p.FS, deny.path, deny.exactOnly) {
			plan.DenyMasks = append(plan.DenyMasks, deny.path)
			if deny.exactOnly {
				plan.exactDenyMasks[deny.path] = true
			}
		}
	}
	for _, path := range order {
		if merged[path]&policy.WriteAccess != 0 {
			plan.RWBinds = append(plan.RWBinds, path)
		} else {
			plan.ROBinds = append(plan.ROBinds, path)
		}
	}

	// Glob scan roots: the writable roots plus the workspace and $HOME (§7.5).
	roots := append([]string(nil), plan.RWBinds...)
	if p.Workspace != "" {
		roots = appendUniquePath(roots, filepath.Clean(p.Workspace))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = appendUniquePath(roots, filepath.Clean(home))
	}
	plan.scanRoots = roots
	return plan
}

func survivingAllowAccess(entries []policy.FSEntry, allow policy.FSEntry) policy.FSAccess {
	access := allow.Access
	path := filepath.Clean(allow.Path)
	for _, entry := range entries {
		if filepath.Clean(entry.Path) == path && entry.Exact == allow.Exact {
			access &^= policy.NormalizedDenied(entry)
		}
	}
	return access
}

func denyHasRestoration(entries []policy.FSEntry, denyPath string, exactOnly bool) bool {
	if exactOnly {
		for _, allow := range entries {
			if allow.Access == 0 || allow.Exact || strings.ContainsAny(allow.Path, policy.GlobMeta) {
				continue
			}
			allowPath := filepath.Clean(allow.Path)
			if (allowPath == denyPath || policy.PathUnder(allowPath, denyPath)) &&
				survivingAllowAccess(entries, allow) != 0 {
				return true
			}
		}
		return false
	}
	for _, allow := range entries {
		if allow.Access == 0 || strings.ContainsAny(allow.Path, policy.GlobMeta) {
			continue
		}
		allowPath := filepath.Clean(allow.Path)
		higherPrecedence := policy.PathUnder(denyPath, allowPath) || allowPath == denyPath && allow.Exact
		if higherPrecedence && survivingAllowAccess(entries, allow) != 0 {
			return true
		}
	}
	return false
}

// appendUniquePath appends p to list if not already present (both cleaned).
func appendUniquePath(list []string, p string) []string {
	if slices.Contains(list, p) {
		return list
	}
	return append(list, p)
}

// BindSpec is one bind mount in the Rung-1 view, gob-encoded across the re-exec
// (exported concrete type). Target equals the host Source path, so the view
// preserves absolute paths — Landlock rules and chdir(workspace) still resolve
// after pivot_root. ReadOnly re-masks the bind read-only (carveouts, read roots).
type BindSpec struct {
	Source   string // host path bound into the view
	Target   string // absolute path inside the new root (== Source)
	ReadOnly bool   // remount the bind read-only after binding
	IsDir    bool   // directory (bind a dir) vs regular file (bind a file)
}

// MaskSpec is an empty read-only mask over a path (a fixed-path secret deny or a
// glob-deny match), gob-encoded. It hides the real path's contents behind an
// empty dir/file so a deny beats any covering allow (§7.5). Applied after every
// bind so the mask always wins.
type MaskSpec struct {
	Target string // absolute path to mask (host path)
	IsDir  bool   // empty tmpfs (dir) vs empty file bind (file)
}

// MountViewSpec is the fully enumerated Rung-1 bind-mount view for one spawn,
// gob-encoded into the Stage2Spec (SPEC §7.2 Rung 1, §7.5). Binds are ordered
// parents-first (EnumerateMountView sorts them) so a nested ro carveout re-masks
// the rw root it sits under; Masks are applied after all Binds so a deny wins.
type MountViewSpec struct {
	Binds []BindSpec
	Masks []MaskSpec
}

// EnumerateMountView turns a compile-time MountViewPlan into a spawn-time
// MountViewSpec: it stats each bind root (classifying dir vs file), sorts the
// binds parents-first so nesting re-masks correctly, and re-runs the glob scan
// for a fresh mask snapshot. An absent protected child under an active writable
// bind is an error: silently dropping its ro bind or mask would let the target
// create and reach it after launch. It walks the live filesystem but touches no
// namespaces, so it runs on every host and is unit-testable.
func EnumerateMountView(plan MountViewPlan) (MountViewSpec, error) {
	return enumerateMountViewWithGrantPaths(plan, nil, nil)
}

func enumerateMountViewWithGrantPaths(plan MountViewPlan, grantRules []policy.FSRule, handles []*policy.PathHandle) (MountViewSpec, error) {
	var spec MountViewSpec
	type absentProtectedPath struct {
		path string
		err  error
	}
	var absentProtected []absentProtectedPath
	resolver := policy.NewPinnedPathResolver(handles, policy.FirstPathHandleChildFD+len(handles))
	defer policy.CloseRuleFiles(resolver.Files())
	add := func(path string, ro bool) {
		if _, ok := plan.grantBinds[path]; ok {
			return
		}
		st, err := os.Stat(path)
		if err != nil {
			if ro {
				absentProtected = append(absentProtected, absentProtectedPath{path: path, err: err})
			}
			return
		}
		spec.Binds = append(spec.Binds, BindSpec{
			Source:   path,
			Target:   path,
			ReadOnly: ro,
			IsDir:    st.IsDir(),
		})
	}
	for _, p := range plan.RWBinds {
		add(p, false)
	}
	for _, p := range plan.ROBinds {
		add(p, true)
	}
	grantBindByTarget := make(map[string]BindSpec)
	for root := range plan.grantBinds {
		for _, rule := range grantRules {
			if rule.ParentFD == 0 || rule.Target == "" || rule.Target != root && !policy.PathUnder(root, rule.Target) {
				continue
			}
			current, ok := grantBindByTarget[rule.Target]
			if !ok || rule.ParentFD < procFDNumber(current.Source) {
				grantBindByTarget[rule.Target] = BindSpec{
					Source: "/proc/self/fd/" + strconv.Itoa(rule.ParentFD),
					Target: rule.Target,
					IsDir:  rule.IsDir,
				}
			}
		}
	}
	// A grant bind's own read-only-ness is decided by its OWN rule(s) only,
	// never by an ancestor's write grant elsewhere in the same pinned-handle
	// tree: the whole point of a nested carveout (mirrored from the plain,
	// non-grant RWBinds/ROBinds path above, and the "parents-first...
	// re-masking" bind-order design this file already documents) is that a
	// narrower nested grant overrides a broader ancestor grant, not inherits
	// its permissions. Security-relevant fix: a prior ancestor-inheritance
	// disjunct here (`rule.IsDir && policy.PathUnder(rule.Target, target)`)
	// silently bound a read-only nested grant (e.g. write root + read-only
	// child carveout) as WRITABLE whenever an ancestor in the same grant tree
	// had a write rule, defeating the narrower grant.
	for target, bind := range grantBindByTarget {
		bind.ReadOnly = true
		for _, rule := range grantRules {
			if rule.Access&policy.WriteAccess != 0 && rule.Target == target {
				bind.ReadOnly = false
				break
			}
		}
		spec.Binds = append(spec.Binds, bind)
	}
	for _, path := range plan.ROBinds {
		if _, pinned := plan.grantBinds[path]; !pinned {
			continue
		}
		materialized := false
		for _, bind := range spec.Binds {
			if bind.ReadOnly && bind.Target == path {
				materialized = true
				break
			}
		}
		if !materialized {
			absentProtected = append(absentProtected, absentProtectedPath{path: path, err: fs.ErrNotExist})
		}
	}
	// Parents-first: a lexical path sort places a parent before its children (the
	// parent is a prefix), so a nested ro carveout is bound AFTER — re-masking —
	// the rw root beneath it, and a rw root is bound after a broader ro root.
	slices.SortFunc(spec.Binds, func(a, b BindSpec) int { return strings.Compare(a.Target, b.Target) })

	for _, d := range plan.DenyMasks {
		if plan.exactDenyMasks[d] && !mountPathVisible(spec.Binds, d) {
			continue
		}
		if policy.MatchingPathHandleIdentityAncestor(handles, d) >= 0 {
			resolved, ok, err := resolver.ResolveAny(d)
			if err != nil {
				return MountViewSpec{}, err
			}
			if ok {
				if plan.exactDenyMasks[d] && resolved.IsDir {
					return MountViewSpec{}, fmt.Errorf(
						"%s: exact directory deny %q cannot be represented without hiding descendants",
						mountViewOp, d,
					)
				}
				spec.Masks = append(spec.Masks, MaskSpec{Target: d, IsDir: resolved.IsDir})
			} else {
				absentProtected = append(absentProtected, absentProtectedPath{path: d, err: fs.ErrNotExist})
			}
			continue
		}
		st, err := os.Lstat(d)
		if err != nil {
			absentProtected = append(absentProtected, absentProtectedPath{path: d, err: err})
			continue
		}
		if plan.exactDenyMasks[d] && st.IsDir() {
			return MountViewSpec{}, fmt.Errorf(
				"%s: exact directory deny %q cannot be represented without hiding descendants",
				mountViewOp, d,
			)
		}
		spec.Masks = append(spec.Masks, MaskSpec{Target: d, IsDir: st.IsDir()})
	}
	for _, absent := range absentProtected {
		for _, bind := range spec.Binds {
			if !bind.ReadOnly && (bind.Target == absent.path || policy.PathUnder(bind.Target, absent.path)) {
				return MountViewSpec{}, fmt.Errorf(
					"%s: protected path %q unavailable beneath writable bind %q: %w",
					mountViewOp, absent.path, bind.Target, absent.err,
				)
			}
		}
	}
	spec.Masks = append(spec.Masks, scanGlobDeniesWithGrantPaths(plan.scanRoots, plan.GlobDenies, GlobScanMaxDepth, handles, resolver)...)
	slices.SortFunc(spec.Masks, func(a, b MaskSpec) int { return strings.Compare(a.Target, b.Target) })
	return spec, nil
}

func mountPathVisible(binds []BindSpec, path string) bool {
	for _, bind := range binds {
		if bind.Target == path || policy.PathUnder(bind.Target, path) || policy.PathUnder(path, bind.Target) {
			return true
		}
	}
	return false
}

func procFDNumber(path string) int {
	value, err := strconv.Atoi(strings.TrimPrefix(path, "/proc/self/fd/"))
	if err != nil {
		return int(^uint(0) >> 1)
	}
	return value
}

// ScanGlobDenies bounded-walks each root to maxDepth, masking every entry whose
// BASENAME matches a glob-deny pattern (SPEC §7.5). A pattern like **/.env* is
// reduced to its final segment (.env*) and matched against each entry name at
// any depth. Symlinks are never followed (fail secure — do not chase a link out
// of the scanned tree). Matches are de-duplicated across roots. This is a
// filesystem walk only (no namespaces), so it runs on every host.
func ScanGlobDenies(roots, globs []string, maxDepth int) []MaskSpec {
	return scanGlobDeniesWithGrantPaths(roots, globs, maxDepth, nil, nil)
}

func scanGlobDeniesWithGrantPaths(roots, globs []string, maxDepth int, handles []*policy.PathHandle, resolver *policy.PinnedPathResolver) []MaskSpec {
	if len(globs) == 0 {
		return nil
	}
	pats := make([]string, 0, len(globs))
	for _, g := range globs {
		pats = append(pats, globBasename(g))
	}
	seen := make(map[string]bool)
	var out []MaskSpec
	for _, root := range roots {
		if policy.MatchingPathHandleIdentityAncestor(handles, root) >= 0 {
			resolved, ok, err := resolver.ResolveAny(root)
			if err == nil && ok && resolved.IsDir {
				scanGlobRootAt(int(resolved.File.Fd()), root, pats, maxDepth, seen, &out)
			}
			continue
		}
		scanGlobRoot(root, pats, maxDepth, seen, &out)
	}
	return out
}

func scanGlobRootAt(dirFD int, dir string, pats []string, depthLeft int, seen map[string]bool, out *[]MaskSpec) {
	if depthLeft < 0 {
		return
	}
	readFD, err := unix.Openat2(dirFD, ".", &unix.OpenHow{
		Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
		Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS),
	})
	if err != nil {
		return
	}
	readDir := os.NewFile(uintptr(readFD), "sandbox-grant-glob-scan")
	if readDir == nil {
		_ = unix.Close(readFD)
		return
	}
	entries, err := readDir.ReadDir(-1)
	_ = readDir.Close()
	if err != nil {
		return
	}
	for _, entry := range entries {
		childFD, err := unix.Openat2(dirFD, entry.Name(), &unix.OpenHow{
			Flags: uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC),
			Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS |
				unix.RESOLVE_NO_MAGICLINKS),
		})
		if err != nil {
			continue
		}
		child := os.NewFile(uintptr(childFD), "sandbox-grant-glob-child")
		if child == nil {
			_ = unix.Close(childFD)
			continue
		}
		info, err := child.Stat()
		if err != nil || info.Mode()&fs.ModeSymlink != 0 {
			_ = child.Close()
			continue
		}
		full := filepath.Join(dir, entry.Name())
		for _, pat := range pats {
			if ok, _ := filepath.Match(pat, entry.Name()); ok {
				if !seen[full] {
					seen[full] = true
					*out = append(*out, MaskSpec{Target: full, IsDir: info.IsDir()})
				}
				break
			}
		}
		if info.IsDir() && depthLeft > 0 {
			scanGlobRootAt(int(child.Fd()), full, pats, depthLeft-1, seen, out)
		}
		_ = child.Close()
	}
}

// globBasename returns the final path segment of a glob pattern (the part after
// the last '/'), which is what ScanGlobDenies matches against entry names. For
// **/.env* this is .env*; for a pattern with no '/', the pattern itself.
func globBasename(glob string) string {
	if i := strings.LastIndexByte(glob, '/'); i >= 0 {
		return glob[i+1:]
	}
	return glob
}

// scanGlobRoot recursively walks dir up to depthLeft levels, appending a MaskSpec
// for each entry whose name matches a pattern. It skips symlinks (never follows
// them) and stops descending at depth 0. Errors (unreadable dir, vanished entry)
// are skipped — the scan is best-effort masking; an unscannable subtree simply
// yields no mask there (the covering bind, if any, still applies).
func scanGlobRoot(dir string, pats []string, depthLeft int, seen map[string]bool, out *[]MaskSpec) {
	if depthLeft < 0 {
		return
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, de := range entries {
		info, err := de.Info()
		if err != nil {
			continue // vanished between ReadDir and Info (TOCTOU) — skip
		}
		if info.Mode()&fs.ModeSymlink != 0 {
			continue // do not follow a symlink out of the scanned tree — fail secure
		}
		full := filepath.Join(dir, de.Name())
		for _, pat := range pats {
			if ok, _ := filepath.Match(pat, de.Name()); ok {
				if !seen[full] {
					seen[full] = true
					*out = append(*out, MaskSpec{Target: full, IsDir: de.IsDir()})
				}
				break
			}
		}
		if de.IsDir() && depthLeft > 0 {
			scanGlobRoot(full, pats, depthLeft-1, seen, out)
		}
	}
}

// ConfigureRung1SysProcAttr sets the Rung-1 namespace cloneflags and the uid/gid
// maps on the spawn's SysProcAttr (SPEC §7.2 Rung 1). The stage-2 child is
// clone'd into a fresh user + mount + pid namespace (+ net namespace only when
// egress is Confined — an OPEN policy must keep host networking, so isolating
// the Netns would sever it). The caller maps to root inside the user namespace
// so the child holds (subject to host policy) CAP_SYS_ADMIN for the mount view
// and CAP_NET_ADMIN for the in-Netns nftables. It EXTENDS the passed SysProcAttr
// (it only sets these fields), so the existing cgroup UseCgroupFD wiring and the
// spec pipe coexist on the same struct.
func ConfigureRung1SysProcAttr(attr *syscall.SysProcAttr, netConfined bool) {
	flags := syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID
	if netConfined {
		flags |= syscall.CLONE_NEWNET
	}
	attr.Cloneflags = uintptr(flags)
	// Map the caller's uid/gid to root inside the new user namespace so the child
	// holds the Rung-1 capabilities. GidMappingsEnableSetgroups defaults to false,
	// so Go writes "deny" to /proc/<pid>/setgroups before gid_map (required for an
	// unprivileged map) — mirrors probeNamespaceCap and the M4 spike.
	attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
	attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
}

// applyMountView materializes the Rung-1 bind-mount view inside the stage-2
// child's mount namespace and pivot_roots into it (SPEC §7.2 Rung 1, §7.5). It
// runs ONLY in the child (after the clone, before Landlock/Seccomp/exec) and is
// the containment-critical step: a missing pivot_root or a failed mask is an
// escape, so EVERY step fails CLOSED via a Stage2Error{Op: mount-view}.
//
// Ordering (load-bearing, §7.2): Private-remount / → new-root tmpfs → binds
// (rw/ro/ro-remask, parents-first) → masks (empty ro binds, deny wins) → fresh
// /proc for the new pid ns → pivot_root → detach the old root (invisibility).
//
// CI-verified: the mount syscalls need an effective CAP_SYS_ADMIN in an
// unprivileged user+mount namespace, blocked on the authoring host.
func applyMountView(spec MountViewSpec) error {
	// 1. Make the whole mount tree Private+recursive so nothing we do here
	//    propagates back to the host mount namespace.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("make-rprivate /: %w", err)}
	}
	// 2. Build a fresh, empty new root on tmpfs. Everything NOT bound into it is
	//    invisible after pivot_root — that is restricted-read at Rung 1.
	newroot, err := os.MkdirTemp("", "lrsandbox-root-")
	if err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("mkdir newroot: %w", err)}
	}
	if err := unix.Mount("tmpfs", newroot, "tmpfs", 0, ""); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("mount tmpfs newroot: %w", err)}
	}
	// 3. Binds (parents-first, so a nested ro carveout re-masks the rw root under
	//    it — deny-inside-allow via mount).
	for _, b := range spec.Binds {
		if err := applyBind(newroot, b); err != nil {
			return err
		}
	}
	// 4. Masks (empty ro binds), AFTER binds so a deny always wins over a covering
	//    allow (fixed-path secrets + glob-deny matches).
	for _, m := range spec.Masks {
		if err := applyMask(newroot, m); err != nil {
			return err
		}
	}
	// 5. A FRESH /proc for the new pid namespace (a bound host /proc would expose
	//    host pids and mismatch the pidns). This is the child's own-namespace proc,
	//    not a host-path leak.
	procTarget := filepath.Join(newroot, "proc")
	if err := os.MkdirAll(procTarget, 0o555); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("mkdir /proc: %w", err)}
	}
	if err := unix.Mount("proc", procTarget, "proc", 0, ""); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("mount /proc: %w", err)}
	}
	// 6. pivot_root into the new root, then detach the old one so host paths not
	//    bound are gone.
	return pivotInto(newroot)
}

// applyBind binds one host root into the new view at the same absolute path,
// creating the mountpoint (a dir or an empty file to bind onto) and, for a
// read-only bind, remounting it MS_RDONLY. Every step fails closed.
func applyBind(newroot string, b BindSpec) error {
	target := filepath.Join(newroot, b.Target)
	if b.IsDir {
		if err := os.MkdirAll(target, 0o755); err != nil {
			return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("mkdir bind target %s: %w", b.Target, err)}
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("mkdir bind parent %s: %w", b.Target, err)}
		}
		if err := touchFile(target); err != nil {
			return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("touch bind target %s: %w", b.Target, err)}
		}
	}
	if err := unix.Mount(b.Source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("bind %s: %w", b.Target, err)}
	}
	if b.ReadOnly {
		// A bind mount ignores MS_RDONLY on the initial call; a second MS_REMOUNT
		// pass makes it read-only. This is TOP-mount-only: a submount under a
		// recursively-bound read root (e.g. /sys, /run under a broad "/" read) keeps
		// its own rw state in the mount view. That is NOT a write-boundary hole,
		// because Rung 1 ALSO applies the Landlock FS allowlist on top of this view
		// (stage2Setup: applyMountView -> ... -> applyLandlockRules), and Landlock
		// grants write only on the policy's writable roots — so a rw submount is
		// still write-denied to the target. The mount view's ro-remount is thus
		// defense-in-depth for writes; its load-bearing jobs are invisibility
		// (unbound paths are gone) and the empty deny-masks. (A future recursive
		// mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY) pass could make the view
		// self-sufficient, but risks EPERM on host-locked submounts under "/", so it
		// is deferred to CI validation.)
		if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("remount ro %s: %w", b.Target, err)}
		}
	}
	return nil
}

// applyMask hides a path behind an empty read-only mount (SPEC §7.5). A masked
// DIR gets a fresh empty read-only tmpfs; a masked FILE gets an empty read-only
// file bind. A mask whose target is not present in the view (never covered by
// any bind) is a no-op: an unbound host path is already invisible. Fails closed
// on any real mount error.
func applyMask(newroot string, m MaskSpec) error {
	target := filepath.Join(newroot, m.Target)
	if _, err := os.Lstat(target); err != nil {
		return nil // not visible in the view — nothing to mask (already hidden)
	}
	if m.IsDir {
		if err := unix.Mount("tmpfs", target, "tmpfs", unix.MS_RDONLY, ""); err != nil {
			return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("mask dir %s: %w", m.Target, err)}
		}
		return nil
	}
	empty := filepath.Join(newroot, emptyMaskFile)
	if err := touchFile(empty); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("mask empty source: %w", err)}
	}
	if err := unix.Mount(empty, target, "", unix.MS_BIND, ""); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("mask file %s: %w", m.Target, err)}
	}
	if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("mask file ro %s: %w", m.Target, err)}
	}
	return nil
}

// pivotInto pivot_roots into newroot and detaches the previous root, so host
// paths not bound into newroot become INVISIBLE (SPEC §7.2 Rung 1). Every step
// fails closed — a partial pivot that left the old root reachable would be a
// containment escape.
func pivotInto(newroot string) error {
	oldroot := filepath.Join(newroot, oldRootDir)
	if err := os.MkdirAll(oldroot, 0o700); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("mkdir put_old: %w", err)}
	}
	if err := unix.PivotRoot(newroot, oldroot); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("pivot_root: %w", err)}
	}
	if err := unix.Chdir("/"); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("chdir new /: %w", err)}
	}
	oldMount := "/" + oldRootDir
	if err := unix.Unmount(oldMount, unix.MNT_DETACH); err != nil {
		return &Stage2Error{Op: mountViewOp, Err: fmt.Errorf("detach old root: %w", err)}
	}
	_ = os.Remove(oldMount) // best-effort: the put_old dir is now empty
	return nil
}

// touchFile ensures a regular-file bind MOUNTPOINT exists at path. It is only
// ever a mountpoint: the bind is laid over it immediately and nothing is ever
// written through this handle.
//
// It therefore must not demand write permission on a target that already
// exists. Opening O_WRONLY unconditionally did exactly that, and failed with
// EACCES whenever the new root resolved onto a tree whose files this user
// namespace's mapped uid may not write -- the Rung-1 mount view hit it on
// /etc/hosts beneath a writable "/" bind, aborting stage 2 and surfacing to
// the caller as the "cannot execute" exit code 126. Create only when absent,
// and treat a concurrent create as success.
func touchFile(path string) error {
	if _, err := os.Lstat(path); err == nil {
		return nil
	} else if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return nil
		}
		return err
	}
	return f.Close()
}
