//go:build linux

package linux

import (
	"errors"
	"fmt"
	"github.com/looprig/sandbox/internal/policy"
	"runtime"
	"syscall"

	"github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
	"golang.org/x/sys/unix"
)

// This file compiles a policy.Effective's filesystem axis into a go-landlock ruleset for
// the Rung-2 backend (SPEC §7.2, §7.5). Landlock is ADDITIVE (allowlist-only, no
// deny rules), so a fixed-path deny compiles by ENUMERATED SIBLING ALLOWS: at
// spawn, grant the siblings of a denied path instead of the parent, inode-pinned
// with snapshot semantics (entries created after the spawn-time enumeration are
// inaccessible for that command — which errs narrow, §7.5).
//
// Two-phase design across the re-exec:
//   - compile time (once, in Backend.compile): distil the policy.Effective's FS axis
//     into a policy.CompiledFS — the literal ALLOW entries with their access bits and
//     the literal DENY paths. Globs are not expressible at Rung 2 and are
//     dropped here (recorded in the profile.CompileReport).
//   - spawn time (per spawn, in the wrap/configure closure): policy.EnumerateFSRules
//     walks the live filesystem, carving each deny/read-only-carveout out of its
//     covering allow, and produces a flat []policy.FSRule. That slice is gob-encoded
//     into the Stage2Spec and rebuilt into a go-landlock ruleset by the stage-2
//     child (applyLandlockRules), which restricts itself BEFORE execve.
//
// Enumeration is deliberately at SPAWN time (a fresh snapshot each spawn), not at
// compile time: a secret that exists when a command starts is masked, and the
// only escape is a file the command itself creates mid-run — which by
// construction holds no pre-existing secret (§7.5).
//
// Grant paths arrive canonical and identity-revalidated. Profile roots are
// canonicalized by NewProfile. Fixed backend paths are trusted constants;
// enumeration skips symlink children rather than following them while carving.

// applyLandlockRules rebuilds a go-landlock ruleset from the spawn-time
// enumerated allowlist and restricts the CURRENT process (and everything it
// subsequently execve's) to it, using the exact ABI v4 config (SPEC §7.2 Rung 2).
// It is called by the stage-2 child BEFORE chdir/execve; a non-nil return makes
// the child fail closed so the target never runs unconfined.
//
// The exact landlock.V4 config (not BestEffort) is deliberate: a kernel missing
// ABI v4 makes RestrictPaths error — a hard fail-closed — rather than silently
// no-op'ing the confinement. Rung 2 is only selected when ABI >= 4, so on the
// selecting host this always enforces. Every rule is IgnoreIfMissing so a path
// removed between enumeration and application (TOCTOU) is skipped (narrower)
// rather than aborting the whole ruleset.
func applyLandlockRules(rules []policy.FSRule) error {
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil || abi < 4 {
		return fmt.Errorf("Landlock ABI v4 unavailable: ABI=%d err=%w", abi, err)
	}
	const handledAccessFS = (1 << 15) - 1
	ruleset, err := llsys.LandlockCreateRuleset(&llsys.RulesetAttr{HandledAccessFS: handledAccessFS}, 0)
	if err != nil {
		return fmt.Errorf("landlock_create_ruleset: %w", err)
	}
	defer syscall.Close(ruleset)

	rules = append(rules, landlockThreadWorkaroundRules()...)
	for _, r := range rules {
		if err := addLandlockFSRule(ruleset, r); err != nil {
			return err
		}
	}
	if abi >= 8 {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
		}
		if err := llsys.LandlockRestrictSelf(ruleset, llsys.FlagRestrictSelfTSync); err != nil {
			return fmt.Errorf("landlock_restrict_self(TSYNC): %w", err)
		}
		return nil
	}
	if err := llsys.AllThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("prctl(PR_SET_NO_NEW_PRIVS): %w", err)
	}
	if err := llsys.AllThreadsLandlockRestrictSelf(ruleset, 0); err != nil {
		return fmt.Errorf("landlock_restrict_self: %w", err)
	}
	return nil
}

func addLandlockFSRule(ruleset int, rule policy.FSRule) error {
	access := uint64(LandlockAccessSet(rule.Access, rule.IsDir))
	if rule.LandlockAccess != 0 {
		access = rule.LandlockAccess
	}
	if access == 0 {
		return nil
	}
	parentFD := rule.ParentFD
	owned := false
	if parentFD == 0 {
		fd, err := openLandlockRulePath(rule.Path, rule.IsDir)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("open Landlock path %q: %w", rule.Path, err)
		}
		parentFD = fd
		owned = true
	}
	if owned {
		defer unix.Close(parentFD)
	}
	retained := rule.ParentFD != 0
	if retained {
		if err := validateRetainedLandlockFD(parentFD, rule.IsDir); err != nil {
			return fmt.Errorf("stat retained Landlock target=%q fd=%d: %w", rule.Target, rule.ParentFD, err)
		}
	}
	attr := llsys.PathBeneathAttr{ParentFd: parentFD, AllowedAccess: access}
	if err := llsys.LandlockAddPathBeneathRule(ruleset, &attr, 0); err != nil {
		return fmt.Errorf("add Landlock rule path=%q fd=%d: %w", rule.Path, rule.ParentFD, err)
	}
	if retained {
		if err := validateRetainedLandlockFD(parentFD, rule.IsDir); err != nil {
			return fmt.Errorf("restat retained Landlock target=%q fd=%d: %w", rule.Target, rule.ParentFD, err)
		}
	}
	return nil
}

func openLandlockRulePath(path string, isDir bool) (int, error) {
	flags := unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW
	if isDir {
		flags |= unix.O_DIRECTORY
	}
	return unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(flags),
		Resolve: uint64(unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS),
	})
}

func validateRetainedLandlockFD(fd int, isDir bool) error {
	var stat unix.Stat_t
	if err := unix.Fstat(fd, &stat); err != nil {
		return err
	}
	if isDir {
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			return fmt.Errorf("descriptor names a non-directory (mode=%#o)", stat.Mode&unix.S_IFMT)
		}
		return nil
	}
	if stat.Mode&unix.S_IFMT != unix.S_IFREG {
		return fmt.Errorf("descriptor names a non-regular file (mode=%#o)", stat.Mode&unix.S_IFMT)
	}
	if stat.Nlink != 1 {
		return fmt.Errorf("descriptor names a multiply-linked file (nlink=%d)", stat.Nlink)
	}
	return nil
}

// landlockRule maps one policy.FSRule to a go-landlock rule via PathAccess, honoring
// each of the Read/Exec/Write bits INDEPENDENTLY so the compiled access is never
// WIDER than the policy entry (SPEC §7.5). The canned RODirs/RWDirs helpers bundle
// execute into every read grant, which would over-grant execute on a read-only
// (no-Exec) entry — e.g. a `.git` carveout or a hand-authored read-only path.
// PathAccess with a precisely-assembled AccessFSSet avoids that; it also clamps
// the set to the ABI's supported subset, so the mapping is kernel-version-safe.
func landlockRule(r policy.FSRule) landlock.Rule {
	return landlock.PathAccess(LandlockAccessSet(r.Access, r.IsDir), r.Path).IgnoreIfMissing()
}

// LandlockAccessSet assembles the Landlock AccessFSSet for the given policy
// access bits and node kind. Read → read-file (+ read-dir for a directory);
// Exec → execute; Write → the mutation rights (matching go-landlock's own
// accessFSWrite set), with the directory-entry rights (make*/remove*) applied
// only to a directory rule. Bits absent from the policy access are never set, so
// a read-only entry grants no execute and no write.
func LandlockAccessSet(access policy.FSAccess, isDir bool) landlock.AccessFSSet {
	var set landlock.AccessFSSet
	if access&policy.ReadAccess != 0 {
		set |= llsys.AccessFSReadFile
		if isDir {
			set |= llsys.AccessFSReadDir
		}
	}
	if access&policy.ExecAccess != 0 {
		set |= llsys.AccessFSExecute
	}
	if access&policy.WriteAccess != 0 {
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
