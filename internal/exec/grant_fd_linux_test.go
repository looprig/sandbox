//go:build linux

package exec

import (
	"context"
	"errors"
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/linux"
	"github.com/looprig/sandbox/internal/policy"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type failingGrantPathBackend struct {
	handles []*policy.PathHandle
}

type trackingGrantPathBackend struct {
	Rung          linux.Rung
	grantCompiles int
	configures    int
	handles       []*policy.PathHandle
	spec          linux.Stage2Spec
}

func (backend *trackingGrantPathBackend) Compile(pol policy.Effective) (enforce.Spec, CompileReport, uint8, uint64, error) {
	return (&linux.Backend{Rung: backend.Rung}).Compile(pol)
}

func (backend *trackingGrantPathBackend) CompileWithPathHandles(pol policy.Effective, handles []*policy.PathHandle) (enforce.Spec, CompileReport, uint8, uint64, error) {
	backend.grantCompiles++
	backend.handles = append([]*policy.PathHandle(nil), handles...)
	spawn, report, level, bits, err := (&linux.Backend{Rung: backend.Rung}).CompileWithPathHandles(pol, handles)
	if err != nil {
		return enforce.Spec{}, CompileReport{}, LevelNone, 0, err
	}
	_, configure, cleanup := spawn.Wrap(pol.Workspace, []string{"/bin/true"})
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = []string{}
	if err := configure(cmd); err != nil {
		cleanup()
		return enforce.Spec{}, CompileReport{}, LevelNone, 0, err
	}
	backend.configures++
	backend.spec, err = linux.DecodeStage2Spec(cmd.ExtraFiles[0])
	cleanup()
	if err != nil {
		return enforce.Spec{}, CompileReport{}, LevelNone, 0, err
	}
	return enforce.Spec{Wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd) error, func()) {
		return argv, nil, nil
	}}, report, level, bits, nil
}

func (backend *failingGrantPathBackend) Compile(policy.Effective) (enforce.Spec, CompileReport, uint8, uint64, error) {
	return enforce.Spec{Wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd) error, func()) {
		return argv, nil, nil
	}}, CompileReport{}, LevelNone, GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub, nil
}

func (backend *failingGrantPathBackend) CompileWithPathHandles(_ policy.Effective, handles []*policy.PathHandle) (enforce.Spec, CompileReport, uint8, uint64, error) {
	backend.handles = append([]*policy.PathHandle(nil), handles...)
	return enforce.Spec{}, CompileReport{}, LevelNone, 0, errors.New("compile failed")
}

func TestLinuxGrantEnforcementCarriesPinnedFDPastPathSwap(t *testing.T) {
	for _, targetKind := range []struct {
		name  string
		exact bool
	}{
		{name: "exact-file", exact: true},
		{name: "tree-directory", exact: false},
	} {
		for _, rung := range []linux.Rung{linux.RungTwo, linux.RungOne} {
			t.Run(targetKind.name+"/linux.Rung-"+strconv.Itoa(int(rung)), func(t *testing.T) {
				root := t.TempDir()
				target := filepath.Join(root, "target")
				outside := filepath.Join(root, "outside")
				if targetKind.exact {
					for _, path := range []string{target, outside} {
						if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
							t.Fatal(err)
						}
					}
				} else {
					for _, path := range []string{target, outside} {
						if err := os.Mkdir(path, 0o700); err != nil {
							t.Fatal(err)
						}
					}
				}
				binding, err := policy.CapturePathBinding(target)
				if err != nil {
					t.Fatal(err)
				}
				handle, err := policy.AcquirePathHandle(&binding, target, targetKind.exact)
				if err != nil {
					t.Fatal(err)
				}
				handle.SetAccess(policy.WriteAccess)
				defer handle.Close()

				if err := os.Rename(target, target+".approved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, target); err != nil {
					t.Fatal(err)
				}

				pol := policy.Effective{FS: []policy.FSEntry{
					{Path: target, Access: policy.ReadAccess, Exact: targetKind.exact},
					{Path: target, Access: policy.WriteAccess, Exact: targetKind.exact, Canonical: true},
				}}
				backend := &linux.Backend{Rung: rung}
				spawn, _, _, _, err := backend.CompileWithPathHandles(pol, []*policy.PathHandle{handle})
				if err != nil {
					t.Fatal(err)
				}
				_, configure, cleanup := spawn.Wrap(root, []string{"/bin/true"})
				defer cleanup()
				cmd := exec.Command("/proc/self/exe")
				cmd.Env = []string{}
				if err := configure(cmd); err != nil {
					t.Fatal(err)
				}
				if len(cmd.ExtraFiles) != 2 {
					t.Fatalf("ExtraFiles = %d, want sealed spec plus one pinned grant FD", len(cmd.ExtraFiles))
				}
				spec, err := linux.DecodeStage2Spec(cmd.ExtraFiles[0])
				if err != nil {
					t.Fatal(err)
				}
				const grantChildFD = linux.Stage2SpecFD + 1
				if len(spec.GrantFDs) != 1 || spec.GrantFDs[0] != grantChildFD {
					t.Fatalf("GrantFDs = %v, want [%d]", spec.GrantFDs, grantChildFD)
				}
				foundLandlockFD := false
				for _, rule := range spec.FSRules {
					if rule.Path == target {
						t.Fatalf("same-target baseline access returned to swapped pathname: %+v", rule)
					}
					if rule.ParentFD == grantChildFD {
						foundLandlockFD = true
						if rule.Path != "" {
							t.Fatalf("FD-bound Landlock rule also carries pathname %q", rule.Path)
						}
					}
				}
				if !foundLandlockFD {
					t.Fatalf("FSRules = %+v, want direct inherited FD %d", spec.FSRules, grantChildFD)
				}
				if rung == linux.RungOne {
					wantSource := "/proc/self/fd/" + strconv.Itoa(grantChildFD)
					foundBindFD := false
					for _, bind := range spec.MountView.Binds {
						if bind.Target == target {
							foundBindFD = bind.Source == wantSource
						}
					}
					if !foundBindFD {
						t.Fatalf("MountView binds = %+v, want target %q sourced from %q", spec.MountView.Binds, target, wantSource)
					}
				}
			})
		}
	}
}

func TestLinuxGrantHandleClosesWhenSpawnCompilationFails(t *testing.T) {
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	target := filepath.Join(workspace, "exact.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	backend := &failingGrantPathBackend{}
	now := time.Now()
	executor, err := newTestExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	token := issueTestGrant(t, executor, now, "compile-failure", "true", workspace,
		"filesystem.write", target, "filesystem.path.write.v1", target)
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "compile-failure", workspace, "true", []string{token}); err == nil {
		t.Fatal("RunCommandWithGrants succeeded despite backend compile failure")
	}
	if len(backend.handles) != 1 {
		t.Fatalf("backend captured %d handles, want 1", len(backend.handles))
	}
	fd := int(backend.handles[0].File().Fd())
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("grant handle fd %d remains open after compile failure: %v", fd, err)
	}
}

func TestLinuxSameTargetGrantIdentityMismatchFailsBeforeCompilation(t *testing.T) {
	for _, rung := range []linux.Rung{linux.RungTwo, linux.RungOne} {
		for _, order := range []struct {
			name    string
			classes []string
		}{
			{name: "read-then-write", classes: []string{"filesystem.tree.read.v1", "filesystem.tree.write.v1"}},
			{name: "write-then-read", classes: []string{"filesystem.tree.write.v1", "filesystem.tree.read.v1"}},
		} {
			t.Run("rung-"+strconv.Itoa(int(rung))+"/"+order.name, func(t *testing.T) {
				now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
				workspace := mustCanonicalGrantRoot(t, t.TempDir())
				target := filepath.Join(workspace, "target")
				inodeA := target + ".inode-a"
				inodeB := target + ".inode-b"
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(target, "identity"), []byte("A"), 0o600); err != nil {
					t.Fatal(err)
				}
				profile := mustProfile(t, ProfileConfig{
					WorkspaceRoot: workspace, WorkspaceRead: Gated, WorkspaceWrite: Gated,
					HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
					AdditionalRoots: []RootAccess{{Path: target, Read: Gated, Write: Gated}},
				})
				backend := &trackingGrantPathBackend{Rung: rung}
				executor, err := newTestExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
				if err != nil {
					t.Fatal(err)
				}
				readToken := issueTestGrant(t, executor, now, "same-target-mismatch", "true", workspace,
					"filesystem.read", "tree:"+target, "filesystem.tree.read.v1", target)
				if err := os.Rename(target, inodeA); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(target, "identity"), []byte("B"), 0o600); err != nil {
					t.Fatal(err)
				}
				writeToken := issueTestGrant(t, executor, now, "same-target-mismatch", "true", workspace,
					"filesystem.write", "tree:"+target, "filesystem.tree.write.v1", target)
				if err := os.Rename(target, inodeB); err != nil {
					t.Fatal(err)
				}

				tokens := map[string]string{
					"filesystem.tree.read.v1":  readToken,
					"filesystem.tree.write.v1": writeToken,
				}
				paths := map[string]string{
					"filesystem.tree.read.v1":  inodeA,
					"filesystem.tree.write.v1": inodeB,
				}
				var acquiredFDs []int
				acquire := func(binding *policy.PathBinding, canonicalTarget string, exact bool) (*policy.PathHandle, error) {
					if err := os.Rename(paths[order.classes[len(acquiredFDs)]], target); err != nil {
						return nil, err
					}
					handle, err := policy.AcquirePathHandle(binding, canonicalTarget, exact)
					if err != nil {
						return nil, err
					}
					acquiredFDs = append(acquiredFDs, int(handle.File().Fd()))
					if err := os.Rename(target, paths[order.classes[len(acquiredFDs)-1]]); err != nil {
						_ = handle.Close()
						return nil, err
					}
					return handle, nil
				}
				orderedTokens := []string{tokens[order.classes[0]], tokens[order.classes[1]]}
				_, _, err = executor.runCommandWithGrants(context.Background(), "same-target-mismatch", workspace, "true", orderedTokens, acquire)
				if !errors.Is(err, ErrGrantTargetChanged) {
					t.Fatalf("RunCommandWithGrants error = %v, want ErrGrantTargetChanged", err)
				}
				if backend.grantCompiles != 0 || backend.configures != 0 {
					t.Fatalf("backend reached before identity rejection: compiles=%d configures=%d", backend.grantCompiles, backend.configures)
				}
				if len(acquiredFDs) != 2 {
					t.Fatalf("acquired FDs = %v, want two handles", acquiredFDs)
				}
				for _, fd := range acquiredFDs {
					if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
						t.Fatalf("mismatched grant handle fd %d remains open: %v", fd, err)
					}
				}
			})
		}
	}
}

func TestLinuxSameTargetMatchingIdentityCoalescesMergedAxes(t *testing.T) {
	for _, rung := range []linux.Rung{linux.RungTwo, linux.RungOne} {
		for _, reverse := range []bool{false, true} {
			name := "read-then-write"
			if reverse {
				name = "write-then-read"
			}
			t.Run("rung-"+strconv.Itoa(int(rung))+"/"+name, func(t *testing.T) {
				now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
				workspace := mustCanonicalGrantRoot(t, t.TempDir())
				target := filepath.Join(workspace, "target")
				if err := os.Mkdir(target, 0o700); err != nil {
					t.Fatal(err)
				}
				profile := mustProfile(t, ProfileConfig{
					WorkspaceRoot: workspace, WorkspaceRead: Gated, WorkspaceWrite: Gated,
					HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
					AdditionalRoots: []RootAccess{{Path: target, Read: Gated, Write: Gated}},
				})
				backend := &trackingGrantPathBackend{Rung: rung}
				executor, err := newTestExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
				if err != nil {
					t.Fatal(err)
				}
				readToken := issueTestGrant(t, executor, now, "same-target-match", "true", workspace,
					"filesystem.read", "tree:"+target, "filesystem.tree.read.v1", target)
				writeToken := issueTestGrant(t, executor, now, "same-target-match", "true", workspace,
					"filesystem.write", "tree:"+target, "filesystem.tree.write.v1", target)
				tokens := []string{readToken, writeToken}
				if reverse {
					tokens[0], tokens[1] = tokens[1], tokens[0]
				}
				var acquiredFDs []int
				acquire := func(binding *policy.PathBinding, canonicalTarget string, exact bool) (*policy.PathHandle, error) {
					handle, err := policy.AcquirePathHandle(binding, canonicalTarget, exact)
					if handle != nil {
						acquiredFDs = append(acquiredFDs, int(handle.File().Fd()))
					}
					return handle, err
				}
				if _, _, err := executor.runCommandWithGrants(context.Background(), "same-target-match", workspace, "true", tokens, acquire); err != nil {
					t.Fatalf("RunCommandWithGrants: %v", err)
				}
				if backend.grantCompiles != 1 || backend.configures != 1 {
					t.Fatalf("backend calls = compiles %d configures %d, want 1/1", backend.grantCompiles, backend.configures)
				}
				if len(backend.handles) != 1 {
					t.Fatalf("compiled handles = %d, want one coalesced target", len(backend.handles))
				}
				if backend.handles[0].Target() != target || backend.handles[0].Access() != policy.AllAccess {
					t.Fatalf("coalesced handle = target %q access %#x, want %q all axes", backend.handles[0].Target(), backend.handles[0].Access(), target)
				}
				if len(backend.spec.GrantFDs) == 0 || backend.spec.GrantFDs[0] != policy.FirstPathHandleChildFD {
					t.Fatalf("GrantFDs = %v, want coalesced grant handle first at fd %d", backend.spec.GrantFDs, policy.FirstPathHandleChildFD)
				}
				for index, fd := range backend.spec.GrantFDs {
					if want := policy.FirstPathHandleChildFD + index; fd != want {
						t.Fatalf("GrantFDs = %v, want unique contiguous transport; index %d fd=%d want=%d", backend.spec.GrantFDs, index, fd, want)
					}
				}
				for _, rule := range backend.spec.FSRules {
					if rule.Target == target && (rule.ParentFD == 0 || rule.ParentFD != policy.FirstPathHandleChildFD) {
						t.Fatalf("same-target rule used zero sentinel or collided: %+v", rule)
					}
				}
				if len(acquiredFDs) != 2 {
					t.Fatalf("acquired FDs = %v, want two handles before coalescing", acquiredFDs)
				}
				for _, fd := range acquiredFDs {
					if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
						t.Fatalf("successful grant handle fd %d remains open: %v", fd, err)
					}
				}
			})
		}
	}
}

func TestLinuxGrantHandleSetSortsCanonicalTargetsAndPreservesLongestAncestor(t *testing.T) {
	root := t.TempDir()
	targets := []string{
		filepath.Join(root, "a-distinct"),
		filepath.Join(root, "m-outer"),
		filepath.Join(root, "m-outer", "inner"),
		filepath.Join(root, "z-distinct"),
	}
	for _, target := range targets {
		if err := os.MkdirAll(target, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	var set policy.PathHandleSet
	var acquiredFDs []int
	for i := len(targets) - 1; i >= 0; i-- {
		binding, err := policy.CapturePathBinding(targets[i])
		if err != nil {
			t.Fatal(err)
		}
		handle, err := policy.AcquirePathHandle(&binding, targets[i], false)
		if err != nil {
			t.Fatal(err)
		}
		acquiredFDs = append(acquiredFDs, int(handle.File().Fd()))
		if err := set.Add(handle); err != nil {
			t.Fatal(err)
		}
	}
	handles := set.Sorted()
	if len(handles) != len(targets) {
		t.Fatalf("distinct handles = %d, want %d", len(handles), len(targets))
	}
	for i, target := range targets {
		if handles[i].Target() != target {
			t.Fatalf("canonical handle order = %q at %d, want %q", handles[i].Target(), i, target)
		}
	}
	descendant := filepath.Join(targets[2], "leaf")
	if got := policy.MatchingPathHandleIdentityAncestor(handles, descendant); got != 2 {
		t.Fatalf("longest Ancestor index = %d, want inner target at canonical index 2", got)
	}
	set.Close()
	for _, fd := range acquiredFDs {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("ordered distinct handle fd %d remains open: %v", fd, err)
		}
	}
}

func TestLinuxPinnedTreeEnumerationUsesRelativeChildHandles(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	approved := target + ".approved"
	outside := filepath.Join(root, "outside")
	for _, dir := range []string{target, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	allowed := filepath.Join(target, "allowed")
	denied := filepath.Join(target, "denied")
	if err := os.WriteFile(allowed, []byte("approved-inode"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(denied, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "escape"), filepath.Join(target, "link")); err != nil {
		t.Fatal(err)
	}
	binding, err := policy.CapturePathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := policy.AcquirePathHandle(&binding, target, false)
	if err != nil {
		t.Fatal(err)
	}
	handle.SetAccess(policy.AllAccess)
	defer handle.Close()

	if err := os.Rename(target, approved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}

	compiled := policy.CompileFSWithPathHandles([]policy.FSEntry{
		{Path: target, Access: policy.AllAccess, Canonical: true},
		{Path: filepath.Join(target, "denied"), Denied: policy.ReadAccess},
		{Path: filepath.Join(target, "missing"), Denied: policy.ReadAccess},
	}, []*policy.PathHandle{handle})
	rules, children, err := policy.EnumerateFSRulesWithPathHandles(compiled, []*policy.PathHandle{handle})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(children)

	const rootChildFD = policy.FirstPathHandleChildFD
	var allowedRead *policy.FSRule
	var rootExec, rootWrite bool
	for i := range rules {
		rule := &rules[i]
		if rule.ParentFD != 0 && rule.Path != "" {
			t.Fatalf("FD-bound rule re-resolved pathname: %+v", *rule)
		}
		if rule.Target == allowed && rule.Access&policy.ReadAccess != 0 {
			allowedRead = rule
		}
		if rule.Target == target && rule.ParentFD == rootChildFD {
			rootExec = rootExec || rule.Access&policy.ExecAccess != 0
			rootWrite = rootWrite || rule.Access&policy.WriteAccess != 0
			if rule.Access&policy.ReadAccess != 0 {
				t.Fatalf("read axis widened back to pinned root despite nested excludes: %+v", *rule)
			}
		}
		if rule.Target == denied && rule.Access&policy.ReadAccess != 0 {
			t.Fatalf("denied child received read rule: %+v", *rule)
		}
		if rule.Target == filepath.Join(target, "link") {
			t.Fatalf("symlink child received pinned rule: %+v", *rule)
		}
	}
	if allowedRead == nil || allowedRead.ParentFD <= rootChildFD {
		t.Fatalf("rules = %+v, want allowed read via direct child FD after the root grant FD", rules)
	}
	if !rootExec || rootWrite {
		t.Fatalf("rules = %+v, want exec but no topology write on the pinned root FD", rules)
	}
	if allowedRead.Access&policy.WriteAccess == 0 {
		t.Fatalf("rules = %+v, want unaffected pinned child to retain enumerated write", rules)
	}
	childIndex := allowedRead.ParentFD - policy.FirstPathHandleChildFD - 1
	if childIndex < 0 || childIndex >= len(children) {
		t.Fatalf("allowed child fd %d has no parent file in %d children", allowedRead.ParentFD, len(children))
	}
	contents, err := os.ReadFile("/proc/self/fd/" + strconv.Itoa(int(children[childIndex].Fd())))
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != "approved-inode" {
		t.Fatalf("allowed child handle resolved %q, want original approved inode", contents)
	}

	if err := os.WriteFile(filepath.Join(approved, "new-sibling"), []byte("late"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, rule := range rules {
		if rule.Access&policy.ReadAccess != 0 && rule.Target == filepath.Join(target, "new-sibling") {
			t.Fatalf("post-enumeration sibling unexpectedly received authority: %+v", rule)
		}
	}

	fds := make([]int, 0, len(children))
	for _, child := range children {
		fds = append(fds, int(child.Fd()))
	}
	closeFiles(children)
	for _, fd := range fds {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("relative child fd %d remains open: %v", fd, err)
		}
	}
}

func TestLinuxExactGrantNonexistentErrorTyping(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "future")
	binding, err := policy.CapturePathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := policy.AcquirePathHandle(&binding, target, true); !errors.Is(err, ErrGrantUnsupported) {
		t.Fatalf("unchanged nonexistent exact target error = %v, want ErrGrantUnsupported", err)
	}
	if err := os.WriteFile(target, []byte("appeared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.AcquirePathHandle(&binding, target, true); !errors.Is(err, ErrGrantTargetChanged) {
		t.Fatalf("newly appeared exact target error = %v, want ErrGrantTargetChanged", err)
	}
}

func TestLinuxPinnedTreeEnumerationFeedsBothRungs(t *testing.T) {
	for _, rung := range []linux.Rung{linux.RungTwo, linux.RungOne} {
		t.Run("rung-"+strconv.Itoa(int(rung)), func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			allowed := filepath.Join(target, "allowed")
			denied := filepath.Join(target, "denied")
			for _, path := range []string{allowed, denied} {
				if err := os.WriteFile(path, []byte(path), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			binding, err := policy.CapturePathBinding(target)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := policy.AcquirePathHandle(&binding, target, false)
			if err != nil {
				t.Fatal(err)
			}
			handle.SetAccess(policy.AllAccess)
			defer handle.Close()
			if err := os.Rename(target, target+".approved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(root, target); err != nil {
				t.Fatal(err)
			}

			pol := policy.Effective{FS: []policy.FSEntry{
				{Path: target, Access: policy.AllAccess, Canonical: true},
				{Path: denied, Denied: policy.ReadAccess},
			}}
			backend := &linux.Backend{Rung: rung}
			spawn, _, _, _, err := backend.CompileWithPathHandles(pol, []*policy.PathHandle{handle})
			if err != nil {
				t.Fatal(err)
			}
			_, configure, cleanup := spawn.Wrap(root, []string{"/bin/true"})
			cmd := exec.Command("/proc/self/exe")
			cmd.Env = []string{}
			if err := configure(cmd); err != nil {
				t.Fatal(err)
			}
			if len(cmd.ExtraFiles) < 3 {
				t.Fatalf("ExtraFiles = %d, want spec + root grant + relative child", len(cmd.ExtraFiles))
			}
			spec, err := linux.DecodeStage2Spec(cmd.ExtraFiles[0])
			if err != nil {
				t.Fatal(err)
			}
			var allowedRead policy.FSRule
			for _, rule := range spec.FSRules {
				if rule.Target == allowed && rule.Access&policy.ReadAccess != 0 {
					allowedRead = rule
				}
				if rule.Target == denied && rule.Access&policy.ReadAccess != 0 {
					t.Fatalf("denied read rule reached linux.Rung %d spec: %+v", rung, rule)
				}
			}
			if allowedRead.ParentFD <= policy.FirstPathHandleChildFD || allowedRead.Path != "" {
				t.Fatalf("rung %d allowed read rule = %+v, want direct relative child FD", rung, allowedRead)
			}
			if rung == linux.RungOne {
				wantSource := "/proc/self/fd/" + strconv.Itoa(allowedRead.ParentFD)
				var found bool
				for _, bind := range spec.MountView.Binds {
					if bind.Target == allowed && bind.Source == wantSource {
						found = true
					}
				}
				if !found {
					t.Fatalf("linux.Rung-1 binds = %+v, want allowed child sourced only from %q", spec.MountView.Binds, wantSource)
				}
			}

			childFDs := make([]int, 0, len(cmd.ExtraFiles)-2)
			for _, file := range cmd.ExtraFiles[2:] {
				childFDs = append(childFDs, int(file.Fd()))
			}
			cleanup()
			for _, fd := range childFDs {
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
					t.Fatalf("linux.Rung %d relative child fd %d remains open after cleanup: %v", rung, fd, err)
				}
			}
		})
	}
}

func TestLinuxPinnedDescendantRestorationFeedsBothRungs(t *testing.T) {
	for _, rung := range []linux.Rung{linux.RungTwo, linux.RungOne} {
		t.Run("rung-"+strconv.Itoa(int(rung)), func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			denied := filepath.Join(target, "denied")
			restored := filepath.Join(denied, "restored")
			safe := filepath.Join(target, "safe")
			if err := os.MkdirAll(restored, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(safe, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(restored, "identity"), []byte("approved"), 0o600); err != nil {
				t.Fatal(err)
			}
			binding, err := policy.CapturePathBinding(target)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := policy.AcquirePathHandle(&binding, target, false)
			if err != nil {
				t.Fatal(err)
			}
			handle.SetAccess(policy.AllAccess)
			defer handle.Close()

			approved := target + ".approved"
			if err := os.Rename(target, approved); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(restored, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(restored, "identity"), []byte("replacement"), 0o600); err != nil {
				t.Fatal(err)
			}

			pol := policy.Effective{FS: []policy.FSEntry{
				{Path: target, Access: policy.AllAccess, Canonical: true},
				{Path: denied, Denied: policy.ReadAccess},
				{Path: restored, Access: policy.ReadAccess},
			}}
			spec, cmd, cleanup := compilePinnedGrantSpec(t, rung, root, pol, []*policy.PathHandle{handle})
			assertPinnedDescendantRule(t, spec, cmd, restored, policy.ReadAccess, "approved", rung)
			var rootAxes policy.FSAccess
			for _, rule := range spec.FSRules {
				if rule.Target == target && rule.ParentFD == policy.FirstPathHandleChildFD {
					rootAxes |= rule.Access
				}
			}
			if rootAxes != policy.ExecAccess {
				t.Fatalf("root unaffected axes = %#x, want exec only", rootAxes)
			}
			var safeWrite bool
			for _, rule := range spec.FSRules {
				if rule.Target == safe && rule.Access&policy.WriteAccess != 0 {
					safeWrite = true
				}
			}
			if !safeWrite {
				t.Fatalf("rules = %+v, want unaffected pinned child %q to retain enumerated write", spec.FSRules, safe)
			}
			cleanup()
		})
	}
}

func TestLinuxPinnedNestedAdditionalRootFeedsBothRungs(t *testing.T) {
	for _, rung := range []linux.Rung{linux.RungTwo, linux.RungOne} {
		t.Run("rung-"+strconv.Itoa(int(rung)), func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			additional := filepath.Join(target, "additional")
			if err := os.MkdirAll(additional, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(additional, "identity"), []byte("approved"), 0o600); err != nil {
				t.Fatal(err)
			}
			binding, err := policy.CapturePathBinding(target)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := policy.AcquirePathHandle(&binding, target, false)
			if err != nil {
				t.Fatal(err)
			}
			handle.SetAccess(policy.WriteAccess)
			defer handle.Close()

			if err := os.Rename(target, target+".approved"); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(additional, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(additional, "identity"), []byte("replacement"), 0o600); err != nil {
				t.Fatal(err)
			}

			pol := policy.Effective{FS: []policy.FSEntry{
				{Path: target, Access: policy.WriteAccess, Canonical: true},
				{Path: additional, Access: policy.ReadAccess | policy.ExecAccess},
			}}
			spec, cmd, cleanup := compilePinnedGrantSpec(t, rung, root, pol, []*policy.PathHandle{handle})
			assertPinnedDescendantRule(t, spec, cmd, additional, policy.ReadAccess|policy.ExecAccess, "approved", rung)
			cleanup()
		})
	}
}

func TestLinuxPinnedDescendantLongestAncestorFeedsBothRungs(t *testing.T) {
	for _, rung := range []linux.Rung{linux.RungTwo, linux.RungOne} {
		t.Run("rung-"+strconv.Itoa(int(rung)), func(t *testing.T) {
			root := t.TempDir()
			outer := filepath.Join(root, "outer")
			inner := filepath.Join(outer, "inner")
			leaf := filepath.Join(inner, "leaf")
			if err := os.MkdirAll(leaf, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(leaf, "identity"), []byte("longest"), 0o600); err != nil {
				t.Fatal(err)
			}
			outerBinding, err := policy.CapturePathBinding(outer)
			if err != nil {
				t.Fatal(err)
			}
			outerHandle, err := policy.AcquirePathHandle(&outerBinding, outer, false)
			if err != nil {
				t.Fatal(err)
			}
			outerHandle.SetAccess(policy.WriteAccess)
			defer outerHandle.Close()
			innerBinding, err := policy.CapturePathBinding(inner)
			if err != nil {
				t.Fatal(err)
			}
			innerHandle, err := policy.AcquirePathHandle(&innerBinding, inner, false)
			if err != nil {
				t.Fatal(err)
			}
			innerHandle.SetAccess(policy.WriteAccess)
			defer innerHandle.Close()

			if err := os.Rename(inner, inner+".approved"); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(leaf, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(leaf, "identity"), []byte("shortest"), 0o600); err != nil {
				t.Fatal(err)
			}

			pol := policy.Effective{FS: []policy.FSEntry{
				{Path: outer, Access: policy.WriteAccess, Canonical: true},
				{Path: inner, Access: policy.WriteAccess, Canonical: true},
				{Path: leaf, Access: policy.ReadAccess},
			}}
			spec, cmd, cleanup := compilePinnedGrantSpec(t, rung, root, pol, []*policy.PathHandle{outerHandle, innerHandle})
			assertPinnedDescendantRule(t, spec, cmd, leaf, policy.ReadAccess, "longest", rung)
			cleanup()
		})
	}
}

func TestLinuxPinnedCarveEnumerationReselectsLongestAncestorBothRungs(t *testing.T) {
	for _, rung := range []linux.Rung{linux.RungTwo, linux.RungOne} {
		t.Run("rung-"+strconv.Itoa(int(rung)), func(t *testing.T) {
			root := t.TempDir()
			outer := filepath.Join(root, "outer")
			inner := filepath.Join(outer, "inner")
			allowed := filepath.Join(inner, "allowed")
			denied := filepath.Join(inner, "denied")
			if err := os.MkdirAll(allowed, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(denied, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(allowed, "identity"), []byte("longest"), 0o600); err != nil {
				t.Fatal(err)
			}
			outerBinding, err := policy.CapturePathBinding(outer)
			if err != nil {
				t.Fatal(err)
			}
			outerHandle, err := policy.AcquirePathHandle(&outerBinding, outer, false)
			if err != nil {
				t.Fatal(err)
			}
			outerHandle.SetAccess(policy.ReadAccess)
			defer outerHandle.Close()
			innerBinding, err := policy.CapturePathBinding(inner)
			if err != nil {
				t.Fatal(err)
			}
			innerHandle, err := policy.AcquirePathHandle(&innerBinding, inner, false)
			if err != nil {
				t.Fatal(err)
			}
			innerHandle.SetAccess(policy.ReadAccess)
			defer innerHandle.Close()

			if err := os.Rename(inner, inner+".approved"); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{allowed, denied} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(allowed, "identity"), []byte("shortest"), 0o600); err != nil {
				t.Fatal(err)
			}

			pol := policy.Effective{FS: []policy.FSEntry{
				{Path: outer, Access: policy.ReadAccess, Canonical: true},
				{Path: inner, Access: policy.ReadAccess, Canonical: true},
				{Path: denied, Denied: policy.ReadAccess},
			}}
			spec, cmd, cleanup := compilePinnedGrantSpec(t, rung, root, pol, []*policy.PathHandle{outerHandle, innerHandle})
			defer cleanup()
			var found bool
			for _, rule := range spec.FSRules {
				if rule.Target != allowed || rule.Access&policy.ReadAccess == 0 {
					continue
				}
				found = true
				extraIndex := rule.ParentFD - linux.Stage2SpecFD
				if rule.Path != "" || extraIndex < 0 || extraIndex >= len(cmd.ExtraFiles) {
					t.Fatalf("carved rule did not carry direct child handle: %+v", rule)
				}
				contents, err := os.ReadFile("/proc/self/fd/" + strconv.Itoa(int(cmd.ExtraFiles[extraIndex].Fd())) + "/identity")
				if err != nil {
					t.Fatal(err)
				}
				if string(contents) != "longest" {
					t.Fatalf("carved rule resolved from shorter pinned Ancestor: rule=%+v identity=%q", rule, contents)
				}
			}
			if !found {
				t.Fatalf("FSRules = %+v, want carved allowed descendant", spec.FSRules)
			}
		})
	}
}

func TestLinuxPinnedDescendantSymlinkAndMissingFailClosedBothRungs(t *testing.T) {
	for _, rung := range []linux.Rung{linux.RungTwo, linux.RungOne} {
		t.Run("rung-"+strconv.Itoa(int(rung)), func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			outside := filepath.Join(root, "outside")
			if err := os.Mkdir(target, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(outside, 0o700); err != nil {
				t.Fatal(err)
			}
			symlink := filepath.Join(target, "symlink")
			missing := filepath.Join(target, "missing")
			if err := os.Symlink(outside, symlink); err != nil {
				t.Fatal(err)
			}
			binding, err := policy.CapturePathBinding(target)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := policy.AcquirePathHandle(&binding, target, false)
			if err != nil {
				t.Fatal(err)
			}
			handle.SetAccess(policy.WriteAccess)
			defer handle.Close()

			if err := os.Rename(target, target+".approved"); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{symlink, missing} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}

			pol := policy.Effective{FS: []policy.FSEntry{
				{Path: target, Access: policy.WriteAccess, Canonical: true},
				{Path: symlink, Access: policy.ReadAccess},
				{Path: missing, Access: policy.ReadAccess},
			}}

			// RungTwo (Landlock-only, no mount view): an unresolvable pinned
			// descendant simply gets no Landlock rule -- fail closed by
			// omission, and inherently safe, since Landlock enforces a
			// per-file allowlist rather than exposing raw filesystem access.
			// compilePinnedGrantSpec's own t.Fatal(err) enforces that this
			// path compiles cleanly.
			if rung == linux.RungTwo {
				spec, _, cleanup := compilePinnedGrantSpec(t, rung, root, pol, []*policy.PathHandle{handle})
				defer cleanup()
				for _, rule := range spec.FSRules {
					if rule.Target == symlink || rule.Target == missing || rule.Path == symlink || rule.Path == missing {
						t.Fatalf("unresolvable pinned descendant received rule: %+v", rule)
					}
				}
				return
			}

			// RungOne (mount view): an unresolvable pinned descendant cannot
			// materialize a read-only carveout bind, and the writable
			// ancestor bind (target) would otherwise silently expose it with
			// write access -- exactly the security concern
			// TestLinuxRung1PinnedWritableGrantRejectsAbsentCarveoutDespiteROAncestor
			// names. The mount view therefore fails closed with an explicit
			// compile error instead of RungTwo's silent omission; this is a
			// stricter, not weaker, guarantee than the old expectation this
			// test previously encoded (which predated that fail-closed
			// design and never actually inspected spec.MountView.Binds'
			// ReadOnly field, so it never observed this compile error was
			// possible).
			backend := &linux.Backend{Rung: rung}
			spawn, _, _, _, err := backend.CompileWithPathHandles(pol, []*policy.PathHandle{handle})
			if err != nil {
				t.Fatal(err)
			}
			_, configure, cleanup := spawn.Wrap(root, []string{"/bin/true"})
			defer cleanup()
			cmd := exec.Command("/proc/self/exe")
			cmd.Env = []string{}
			err = configure(cmd)
			if err == nil {
				t.Fatal("configure succeeded, want unresolvable pinned descendant beneath writable grant to fail closed")
			}
			if !strings.Contains(err.Error(), "protected path") {
				t.Fatalf("configure error = %q, want explicit protected-path rejection", err)
			}
		})
	}
}

func TestLinuxRung1PinnedWritableGrantRejectsAbsentCarveoutDespiteROAncestor(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	binding, err := policy.CapturePathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := policy.AcquirePathHandle(&binding, target, false)
	if err != nil {
		t.Fatal(err)
	}
	handle.SetAccess(policy.AllAccess)
	defer handle.Close()

	absent := filepath.Join(target, ".git")
	pol := policy.Effective{FS: []policy.FSEntry{
		{Path: "/", Access: policy.ReadAccess | policy.ExecAccess},
		{Path: target, Access: policy.AllAccess, Canonical: true},
		{Path: absent, Access: policy.ReadAccess},
	}}
	backend := &linux.Backend{Rung: linux.RungOne}
	spawn, _, _, _, err := backend.CompileWithPathHandles(pol, []*policy.PathHandle{handle})
	if err != nil {
		t.Fatal(err)
	}
	_, configure, cleanup := spawn.Wrap(root, []string{"/bin/true"})
	defer cleanup()
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = []string{}
	err = configure(cmd)
	if err == nil {
		t.Fatal("configure succeeded, want absent protected descendant beneath pinned rw grant to fail closed")
	}
	if !strings.Contains(err.Error(), "protected path") || !strings.Contains(err.Error(), absent) {
		t.Fatalf("configure error = %q, want explicit absent protected path %q", err, absent)
	}
}

func TestLinuxPinnedExactFileIsNeverAnAncestor(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "exact")
	if err := os.WriteFile(target, []byte("approved"), 0o600); err != nil {
		t.Fatal(err)
	}
	binding, err := policy.CapturePathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := policy.AcquirePathHandle(&binding, target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	descendant := filepath.Join(target, "child")
	if got := policy.MatchingPathHandleAncestor([]*policy.PathHandle{handle}, descendant, false); got != -1 {
		t.Fatalf("exact-file handle selected as typed Ancestor: %d", got)
	}
	if got := policy.MatchingPathHandleIdentityAncestor([]*policy.PathHandle{handle}, descendant); got != -1 {
		t.Fatalf("exact-file handle selected as identity Ancestor: %d", got)
	}
}

func TestLinuxPinnedDescendantFDTransportAndCleanup(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	descendant := filepath.Join(target, "descendant")
	if err := os.MkdirAll(descendant, 0o700); err != nil {
		t.Fatal(err)
	}
	binding, err := policy.CapturePathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := policy.AcquirePathHandle(&binding, target, false)
	if err != nil {
		t.Fatal(err)
	}
	handle.SetAccess(policy.WriteAccess)
	defer handle.Close()
	pol := policy.Effective{FS: []policy.FSEntry{
		{Path: target, Access: policy.WriteAccess, Canonical: true},
		{Path: descendant, Access: policy.ReadAccess},
	}}
	spec, cmd, cleanup := compilePinnedGrantSpec(t, linux.RungTwo, root, pol, []*policy.PathHandle{handle})
	if len(cmd.ExtraFiles) != 3 {
		t.Fatalf("ExtraFiles = %d, want sealed spec + root + descendant", len(cmd.ExtraFiles))
	}
	wantFDs := []int{policy.FirstPathHandleChildFD, policy.FirstPathHandleChildFD + 1}
	if len(spec.GrantFDs) != len(wantFDs) {
		t.Fatalf("GrantFDs = %v, want %v", spec.GrantFDs, wantFDs)
	}
	seen := make(map[int]bool)
	for i, fd := range spec.GrantFDs {
		if fd != wantFDs[i] || fd <= linux.Stage2SpecFD || seen[fd] {
			t.Fatalf("GrantFDs = %v, want collision-free %v with no zero sentinel", spec.GrantFDs, wantFDs)
		}
		seen[fd] = true
	}
	descendantParentFD := spec.GrantFDs[1]
	if descendantParentFD == 0 {
		t.Fatal("descendant ParentFD used zero pathname sentinel")
	}
	actualDescendantFD := int(cmd.ExtraFiles[descendantParentFD-linux.Stage2SpecFD].Fd())
	cleanup()
	if _, err := unix.FcntlInt(uintptr(actualDescendantFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("descendant transport fd %d remains open after cleanup: %v", actualDescendantFD, err)
	}
}

func TestLinuxDirectFileFDTransportSurvivesSwapAndCleansUp(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	moved := filepath.Join(root, "moved")
	if err := os.WriteFile(target, []byte("checked"), 0o600); err != nil {
		t.Fatal(err)
	}
	pol := policy.Effective{FS: []policy.FSEntry{{
		Path: target, Access: policy.ReadAccess, Exact: true, Canonical: true,
	}}}
	spec, cmd, cleanup := compilePinnedGrantSpec(t, linux.RungTwo, root, pol, nil)

	var direct *policy.FSRule
	for index := range spec.FSRules {
		rule := &spec.FSRules[index]
		if rule.Target == target {
			direct = rule
			break
		}
	}
	if direct == nil {
		cleanup()
		t.Fatalf("FSRules = %+v, want descriptor-backed direct file", spec.FSRules)
	}
	if direct.Path != "" || direct.ParentFD <= linux.Stage2SpecFD ||
		!slices.Contains(spec.GrantFDs, direct.ParentFD) {
		cleanup()
		t.Fatalf("direct rule = %+v GrantFDs=%v, want transported descriptor", *direct, spec.GrantFDs)
	}
	extraIndex := direct.ParentFD - linux.Stage2SpecFD
	if extraIndex < 0 || extraIndex >= len(cmd.ExtraFiles) {
		cleanup()
		t.Fatalf("direct fd %d has no ExtraFiles entry in %d files", direct.ParentFD, len(cmd.ExtraFiles))
	}
	actualFD := int(cmd.ExtraFiles[extraIndex].Fd())

	if err := os.Rename(target, moved); err != nil {
		cleanup()
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("replacement"), 0o600); err != nil {
		cleanup()
		t.Fatal(err)
	}
	contents, err := os.ReadFile("/proc/self/fd/" + strconv.Itoa(actualFD))
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	if string(contents) != "checked" {
		cleanup()
		t.Fatalf("transported descriptor contains %q, want checked inode", contents)
	}

	cleanup()
	if _, err := unix.FcntlInt(uintptr(actualFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("direct transport fd %d remains open after cleanup: %v", actualFD, err)
	}
}

func TestLinuxPinnedDenyMaskAndGlobScanUseOriginalTree(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	denied := filepath.Join(target, "denied")
	originalGlob := filepath.Join(target, "original.secret")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{denied, originalGlob} {
		if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	binding, err := policy.CapturePathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := policy.AcquirePathHandle(&binding, target, false)
	if err != nil {
		t.Fatal(err)
	}
	handle.SetAccess(policy.AllAccess)
	defer handle.Close()

	if err := os.Rename(target, target+".approved"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(denied, 0o700); err != nil {
		t.Fatal(err)
	}
	replacementGlob := filepath.Join(target, "replacement.secret")
	if err := os.WriteFile(replacementGlob, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}

	pol := policy.Effective{FS: []policy.FSEntry{
		{Path: target, Access: policy.AllAccess, Canonical: true},
		{Path: denied, Denied: policy.AllAccess},
		{Path: "**/*.secret", Denied: policy.AllAccess},
	}}
	spec, _, cleanup := compilePinnedGrantSpec(t, linux.RungOne, root, pol, []*policy.PathHandle{handle})
	defer cleanup()
	var foundDeny, foundOriginalGlob bool
	for _, mask := range spec.MountView.Masks {
		switch mask.Target {
		case denied:
			foundDeny = true
			if mask.IsDir {
				t.Fatalf("deny mask type followed replacement directory: %+v", mask)
			}
		case originalGlob:
			foundOriginalGlob = true
		case replacementGlob:
			t.Fatalf("glob scan followed swapped pathname: %+v", mask)
		}
	}
	if !foundDeny || !foundOriginalGlob {
		t.Fatalf("Masks = %+v, want original deny and glob targets", spec.MountView.Masks)
	}
}

func compilePinnedGrantSpec(t *testing.T, rung linux.Rung, dir string, pol policy.Effective, handles []*policy.PathHandle) (linux.Stage2Spec, *exec.Cmd, func()) {
	t.Helper()
	backend := &linux.Backend{Rung: rung}
	spawn, _, _, _, err := backend.CompileWithPathHandles(pol, handles)
	if err != nil {
		t.Fatal(err)
	}
	_, configure, cleanup := spawn.Wrap(dir, []string{"/bin/true"})
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = []string{}
	if err := configure(cmd); err != nil {
		cleanup()
		t.Fatal(err)
	}
	spec, err := linux.DecodeStage2Spec(cmd.ExtraFiles[0])
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	return spec, cmd, cleanup
}

func assertPinnedDescendantRule(t *testing.T, spec linux.Stage2Spec, cmd *exec.Cmd, target string, access policy.FSAccess, wantIdentity string, rung linux.Rung) {
	t.Helper()
	var pinned *policy.FSRule
	for i := range spec.FSRules {
		rule := &spec.FSRules[i]
		if rule.Target == target && rule.Access&access != 0 {
			if rule.Path != "" || rule.ParentFD <= policy.FirstPathHandleChildFD {
				t.Fatalf("descendant rule = %+v, want direct child fd after root grant", *rule)
			}
			if rule.Access != access {
				t.Fatalf("descendant rule access = %#x, want independent axes %#x", rule.Access, access)
			}
			pinned = rule
		}
		if rule.Path == target {
			t.Fatalf("descendant rule reopened swapped pathname: %+v", *rule)
		}
	}
	if pinned == nil {
		t.Fatalf("FSRules = %+v, want pinned descendant %q access %#x", spec.FSRules, target, access)
	}
	extraIndex := pinned.ParentFD - linux.Stage2SpecFD
	if extraIndex < 0 || extraIndex >= len(cmd.ExtraFiles) {
		t.Fatalf("child fd %d has no ExtraFiles entry in %d files", pinned.ParentFD, len(cmd.ExtraFiles))
	}
	contents, err := os.ReadFile("/proc/self/fd/" + strconv.Itoa(int(cmd.ExtraFiles[extraIndex].Fd())) + "/identity")
	if err != nil {
		t.Fatal(err)
	}
	if string(contents) != wantIdentity {
		t.Fatalf("pinned descendant resolved %q, want %q", contents, wantIdentity)
	}
	if rung != linux.RungOne {
		return
	}
	wantSource := "/proc/self/fd/" + strconv.Itoa(pinned.ParentFD)
	for _, bind := range spec.MountView.Binds {
		if bind.Target == target {
			if bind.Source != wantSource {
				t.Fatalf("linux.Rung-1 descendant source = %q, want %q", bind.Source, wantSource)
			}
			return
		}
	}
	t.Fatalf("linux.Rung-1 binds = %+v, want descendant target %q", spec.MountView.Binds, target)
}

func closeFiles(files []*os.File) {
	for _, file := range files {
		_ = file.Close()
	}
}

func TestLinuxProcessGroupStateTreatsOnlyZombieAsInactive(t *testing.T) {
	for _, test := range []struct {
		name  string
		state string
		want  bool
	}{
		{name: "running", state: "R", want: true},
		{name: "sleeping", state: "S", want: true},
		{name: "uninterruptible", state: "D", want: true},
		{name: "stopped", state: "T", want: true},
		{name: "tracing-stop", state: "t", want: true},
		{name: "zombie", state: "Z", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			stat := []byte("123 (command with ) parens) " + test.state + " 1 77 77 0")
			got, err := activeProcessGroupStat(stat, 77)
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("activeProcessGroupStat(state=%q) = %v, want %v", test.state, got, test.want)
			}
		})
	}
	got, err := activeProcessGroupStat([]byte("124 (other) R 1 88 88 0"), 77)
	if err != nil || got {
		t.Fatalf("different group = (%v, %v), want (false, nil)", got, err)
	}
	if _, err := activeProcessGroupStat([]byte("malformed"), 77); err == nil {
		t.Fatal("malformed stat accepted")
	}
}
