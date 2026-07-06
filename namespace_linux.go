//go:build linux

package sandbox

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// This file compiles a Policy's filesystem axis into the RUNG-1 bind-mount VIEW
// (SPEC §7.2 rung 1, §7.5) and carries the stage-2 mechanism that materializes
// it inside the child's mount namespace. Where rung 2 (landlock_linux.go)
// enforces the FS axis by an ENUMERATED Landlock allowlist against the live
// filesystem, rung 1 builds a NEW root and bind-mounts only the policy's roots
// into it, then pivot_roots into that new root — so any host path NOT bound is
// INVISIBLE (restricted-read = invisibility, the rung-1 property rung 2 cannot
// provide). Deny-inside-allow (carveouts + fixed-path secret denies) is enforced
// by MOUNT RE-MASKING (§7.5): a read-only bind for a carveout, an empty
// read-only bind for a secret — no sibling enumeration, unlike rung 2. Glob
// denies (§7.5) compile by spawn-time bounded enumeration (scanGlobDenies) and
// mask each match with an empty read-only bind.
//
// CRITICAL — CI-verified, not host-verified. The enforcement mechanism
// (applyMountView: private-remount → binds → masks → /proc → pivot_root) needs
// an unprivileged user+mount namespace with an EFFECTIVE CAP_SYS_ADMIN, which is
// blocked on the authoring host by apparmor_restrict_unprivileged_userns=1. The
// pure compilation (compileMountView) and the spawn-time enumeration
// (enumerateMountView / scanGlobDenies — filesystem walks, no namespaces) are
// unit-tested and run on every host; the actual mounting is exercised only in CI.
//
// Two-phase design across the re-exec, mirroring rung 2:
//   - compile time (once, in linuxBackend.compileRung1): distil the Policy's FS
//     axis into a mountViewPlan (rw/ro bind roots, literal deny masks, glob deny
//     patterns, glob scan roots). Deny is a hard override: an allow at-or-under a
//     literal deny is dropped (granting it would be WIDER than the policy).
//   - spawn time (per spawn, in the wrap/configure closure): enumerateMountView
//     stats each root (dir vs file, dropping nonexistent — fail secure) and
//     re-runs the glob scan, producing a MountViewSpec that is gob-encoded into
//     the stage2Spec and applied by the stage-2 child (applyMountView) BEFORE
//     Landlock. Enumeration is at SPAWN time so the mask set is a fresh snapshot:
//     a secret present when the command starts is masked; the only escape is a
//     file the command itself creates mid-run (§7.5 residual — sound, does not
//     demote Level).

// globScanMaxDepth bounds the spawn-time glob-deny scan (SPEC §7.5). It mirrors
// Codex's glob_scan_max_depth precedent: deep enough to reach a repo-local
// `.env` a few directories down, shallow enough that the per-spawn scan of the
// workspace + $HOME stays cheap and bounded (a glob mask is spawn-time work on
// the hot path). A match below this depth is not masked for that spawn; the
// residual is recorded, never silently widened.
const globScanMaxDepth = 8

// mountViewOp is the stage2Error.Op for every rung-1 mount-view failure, so the
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

// mountViewPlan is the rung-1 filesystem intent distilled from a Policy at
// compile time (SPEC §7.2 rung 1, §7.5). It holds bind ROOTS and deny intent,
// not stat'd entries: the dir/file classification and the glob scan are redone
// per spawn (enumerateMountView) so the view is a fresh snapshot each time.
type mountViewPlan struct {
	// rwBinds are the writable allow roots (WriteAccess) — bound rw into the view.
	rwBinds []string
	// roBinds are the read-only allow roots (ReadAccess, no WriteAccess) — bound
	// ro. Carveouts (a ReadAccess allow nested under a writable root, e.g. .git)
	// are ordinary roBinds; nesting is resolved by applying binds parents-first so
	// the ro carveout re-masks the rw root it sits under.
	roBinds []string
	// denyMasks are the literal (non-glob) fixed-path secret denies — each masked
	// by an empty read-only bind so a deny beats any covering allow (deny-inside-
	// allow via mount, §7.5). Applied AFTER all binds so the mask always wins.
	denyMasks []string
	// globDenies are the glob deny patterns (e.g. **/.env*), enforced by spawn-time
	// bounded enumeration (scanGlobDenies) into empty read-only masks.
	globDenies []string
	// scanRoots are the roots scanned for globDenies (workspace + writable roots +
	// $HOME, §7.5). Bounded to globScanMaxDepth.
	scanRoots []string
}

// hasDenies reports whether the plan carries any read-deny (fixed or glob) the
// mount masks enforce — the condition for the ReadDenies guarantee at rung 1.
func (p mountViewPlan) hasDenies() bool {
	return len(p.denyMasks) > 0 || len(p.globDenies) > 0
}

// rung1Plan is the compiled rung-1 confinement beyond the shared Landlock/seccomp
// axes: the bind-mount view and the in-netns nftables plan. It is closed over by
// the per-spawn wrap closure (linuxWrap) — nil for a rung-2 spawn.
type rung1Plan struct {
	mount mountViewPlan
	nft   compiledNftPlan
}

// compileMountView distils a Policy's FS entries into a mountViewPlan (SPEC §7.2
// rung 1). Literal allow roots become rw or ro binds; literal denies become
// masks; glob denies are carried for the spawn-time scan. Allow globs (none in
// the presets) are dropped — a mount cannot express a glob allow, and dropping
// under-grants (fail secure). Deny is a HARD OVERRIDE: an allow at-or-under a
// literal deny is dropped (deniedAtOrUnder), because binding it would be WIDER
// than the policy; the denied path is still masked out of any broader allow.
func compileMountView(p Policy) mountViewPlan {
	var plan mountViewPlan

	// First pass: collect the deny intent (literal masks vs glob patterns).
	for _, e := range p.FS {
		if e.Access != DenyAccess {
			continue
		}
		if strings.ContainsAny(e.Path, globMeta) {
			plan.globDenies = append(plan.globDenies, e.Path)
			continue
		}
		plan.denyMasks = append(plan.denyMasks, filepath.Clean(e.Path))
	}

	// Second pass: merge allow entries by path (OR access bits) preserving first-
	// seen order, so a path granted read then write is bound rw exactly once.
	merged := make(map[string]FSAccess)
	var order []string
	for _, e := range p.FS {
		if e.Access == DenyAccess || strings.ContainsAny(e.Path, globMeta) {
			continue
		}
		clean := filepath.Clean(e.Path)
		if _, ok := merged[clean]; !ok {
			order = append(order, clean)
		}
		merged[clean] |= e.Access
	}
	for _, path := range order {
		if deniedAtOrUnder(path, plan.denyMasks) {
			continue // deny wins: never bind an allow at-or-under a deny
		}
		if merged[path]&WriteAccess != 0 {
			plan.rwBinds = append(plan.rwBinds, path)
		} else {
			plan.roBinds = append(plan.roBinds, path)
		}
	}

	// Glob scan roots: the writable roots plus the workspace and $HOME (§7.5).
	roots := append([]string(nil), plan.rwBinds...)
	if p.Workspace != "" {
		roots = appendUniquePath(roots, filepath.Clean(p.Workspace))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		roots = appendUniquePath(roots, filepath.Clean(home))
	}
	plan.scanRoots = roots
	return plan
}

// appendUniquePath appends p to list if not already present (both cleaned).
func appendUniquePath(list []string, p string) []string {
	if slices.Contains(list, p) {
		return list
	}
	return append(list, p)
}

// BindSpec is one bind mount in the rung-1 view, gob-encoded across the re-exec
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

// MountViewSpec is the fully enumerated rung-1 bind-mount view for one spawn,
// gob-encoded into the stage2Spec (SPEC §7.2 rung 1, §7.5). Binds are ordered
// parents-first (enumerateMountView sorts them) so a nested ro carveout re-masks
// the rw root it sits under; Masks are applied after all Binds so a deny wins.
type MountViewSpec struct {
	Binds []BindSpec
	Masks []MaskSpec
}

// enumerateMountView turns a compile-time mountViewPlan into a spawn-time
// MountViewSpec: it stats each bind root (classifying dir vs file, DROPPING a
// nonexistent root — fail secure, never bind what is not there), sorts the binds
// parents-first so nesting re-masks correctly, and re-runs the glob scan for a
// fresh mask snapshot. It walks the live filesystem but touches no namespaces,
// so it runs on every host and is unit-testable.
func enumerateMountView(plan mountViewPlan) MountViewSpec {
	var spec MountViewSpec
	add := func(path string, ro bool) {
		st, err := os.Stat(path)
		if err != nil {
			return // nonexistent root: drop (fail secure — never bind what is absent)
		}
		spec.Binds = append(spec.Binds, BindSpec{
			Source:   path,
			Target:   path,
			ReadOnly: ro,
			IsDir:    st.IsDir(),
		})
	}
	for _, p := range plan.rwBinds {
		add(p, false)
	}
	for _, p := range plan.roBinds {
		add(p, true)
	}
	// Parents-first: a lexical path sort places a parent before its children (the
	// parent is a prefix), so a nested ro carveout is bound AFTER — re-masking —
	// the rw root beneath it, and a rw root is bound after a broader ro root.
	slices.SortFunc(spec.Binds, func(a, b BindSpec) int { return strings.Compare(a.Target, b.Target) })

	for _, d := range plan.denyMasks {
		st, err := os.Lstat(d)
		if err != nil {
			continue // deny target absent: nothing to mask (already invisible)
		}
		spec.Masks = append(spec.Masks, MaskSpec{Target: d, IsDir: st.IsDir()})
	}
	spec.Masks = append(spec.Masks, scanGlobDenies(plan.scanRoots, plan.globDenies, globScanMaxDepth)...)
	slices.SortFunc(spec.Masks, func(a, b MaskSpec) int { return strings.Compare(a.Target, b.Target) })
	return spec
}

// scanGlobDenies bounded-walks each root to maxDepth, masking every entry whose
// BASENAME matches a glob-deny pattern (SPEC §7.5). A pattern like **/.env* is
// reduced to its final segment (.env*) and matched against each entry name at
// any depth. Symlinks are never followed (fail secure — do not chase a link out
// of the scanned tree). Matches are de-duplicated across roots. This is a
// filesystem walk only (no namespaces), so it runs on every host.
func scanGlobDenies(roots, globs []string, maxDepth int) []MaskSpec {
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
		scanGlobRoot(root, pats, maxDepth, seen, &out)
	}
	return out
}

// globBasename returns the final path segment of a glob pattern (the part after
// the last '/'), which is what scanGlobDenies matches against entry names. For
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

// configureRung1SysProcAttr sets the rung-1 namespace cloneflags and the uid/gid
// maps on the spawn's SysProcAttr (SPEC §7.2 rung 1). The stage-2 child is
// clone'd into a fresh user + mount + pid namespace (+ net namespace only when
// egress is confined — an OPEN policy must keep host networking, so isolating
// the netns would sever it). The caller maps to root inside the user namespace
// so the child holds (subject to host policy) CAP_SYS_ADMIN for the mount view
// and CAP_NET_ADMIN for the in-netns nftables. It EXTENDS the passed SysProcAttr
// (it only sets these fields), so the existing cgroup UseCgroupFD wiring and the
// spec pipe coexist on the same struct.
func configureRung1SysProcAttr(attr *syscall.SysProcAttr, netConfined bool) {
	flags := syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID
	if netConfined {
		flags |= syscall.CLONE_NEWNET
	}
	attr.Cloneflags = uintptr(flags)
	// Map the caller's uid/gid to root inside the new user namespace so the child
	// holds the rung-1 capabilities. GidMappingsEnableSetgroups defaults to false,
	// so Go writes "deny" to /proc/<pid>/setgroups before gid_map (required for an
	// unprivileged map) — mirrors probeNamespaceCap and the M4 spike.
	attr.UidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}}
	attr.GidMappings = []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}}
}

// applyMountView materializes the rung-1 bind-mount view inside the stage-2
// child's mount namespace and pivot_roots into it (SPEC §7.2 rung 1, §7.5). It
// runs ONLY in the child (after the clone, before Landlock/seccomp/exec) and is
// the containment-critical step: a missing pivot_root or a failed mask is an
// escape, so EVERY step fails CLOSED via a stage2Error{Op: mount-view}.
//
// Ordering (load-bearing, §7.2): private-remount / → new-root tmpfs → binds
// (rw/ro/ro-remask, parents-first) → masks (empty ro binds, deny wins) → fresh
// /proc for the new pid ns → pivot_root → detach the old root (invisibility).
//
// CI-verified: the mount syscalls need an effective CAP_SYS_ADMIN in an
// unprivileged user+mount namespace, blocked on the authoring host.
func applyMountView(spec MountViewSpec) error {
	// 1. Make the whole mount tree private+recursive so nothing we do here
	//    propagates back to the host mount namespace.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("make-rprivate /: %w", err)}
	}
	// 2. Build a fresh, empty new root on tmpfs. Everything NOT bound into it is
	//    invisible after pivot_root — that is restricted-read at rung 1.
	newroot, err := os.MkdirTemp("", "lrsandbox-root-")
	if err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("mkdir newroot: %w", err)}
	}
	if err := unix.Mount("tmpfs", newroot, "tmpfs", 0, ""); err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("mount tmpfs newroot: %w", err)}
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
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("mkdir /proc: %w", err)}
	}
	if err := unix.Mount("proc", procTarget, "proc", 0, ""); err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("mount /proc: %w", err)}
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
			return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("mkdir bind target %s: %w", b.Target, err)}
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("mkdir bind parent %s: %w", b.Target, err)}
		}
		if err := touchFile(target); err != nil {
			return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("touch bind target %s: %w", b.Target, err)}
		}
	}
	if err := unix.Mount(b.Source, target, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("bind %s: %w", b.Target, err)}
	}
	if b.ReadOnly {
		// A bind mount ignores MS_RDONLY on the initial call; a second MS_REMOUNT
		// pass makes it read-only. This is TOP-mount-only: a submount under a
		// recursively-bound read root (e.g. /sys, /run under a broad "/" read) keeps
		// its own rw state in the mount view. That is NOT a write-boundary hole,
		// because rung 1 ALSO applies the Landlock FS allowlist on top of this view
		// (stage2Setup: applyMountView -> ... -> applyLandlockRules), and Landlock
		// grants write only on the policy's writable roots — so a rw submount is
		// still write-denied to the target. The mount view's ro-remount is thus
		// defense-in-depth for writes; its load-bearing jobs are invisibility
		// (unbound paths are gone) and the empty deny-masks. (A future recursive
		// mount_setattr(AT_RECURSIVE, MOUNT_ATTR_RDONLY) pass could make the view
		// self-sufficient, but risks EPERM on host-locked submounts under "/", so it
		// is deferred to CI validation.)
		if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
			return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("remount ro %s: %w", b.Target, err)}
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
			return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("mask dir %s: %w", m.Target, err)}
		}
		return nil
	}
	empty := filepath.Join(newroot, emptyMaskFile)
	if err := touchFile(empty); err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("mask empty source: %w", err)}
	}
	if err := unix.Mount(empty, target, "", unix.MS_BIND, ""); err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("mask file %s: %w", m.Target, err)}
	}
	if err := unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, ""); err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("mask file ro %s: %w", m.Target, err)}
	}
	return nil
}

// pivotInto pivot_roots into newroot and detaches the previous root, so host
// paths not bound into newroot become INVISIBLE (SPEC §7.2 rung 1). Every step
// fails closed — a partial pivot that left the old root reachable would be a
// containment escape.
func pivotInto(newroot string) error {
	oldroot := filepath.Join(newroot, oldRootDir)
	if err := os.MkdirAll(oldroot, 0o700); err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("mkdir put_old: %w", err)}
	}
	if err := unix.PivotRoot(newroot, oldroot); err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("pivot_root: %w", err)}
	}
	if err := unix.Chdir("/"); err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("chdir new /: %w", err)}
	}
	oldMount := "/" + oldRootDir
	if err := unix.Unmount(oldMount, unix.MNT_DETACH); err != nil {
		return &stage2Error{Op: mountViewOp, Err: fmt.Errorf("detach old root: %w", err)}
	}
	_ = os.Remove(oldMount) // best-effort: the put_old dir is now empty
	return nil
}

// touchFile creates an empty regular file (a no-op if it already exists), used
// for file bind mountpoints and the shared empty mask source.
func touchFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	return f.Close()
}
