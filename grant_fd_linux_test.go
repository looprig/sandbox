//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type failingGrantPathBackend struct {
	handles []*grantPathHandle
}

type trackingGrantPathBackend struct {
	rung          rung
	grantCompiles int
	configures    int
	handles       []*grantPathHandle
	spec          stage2Spec
}

func (backend *trackingGrantPathBackend) compile(policy effectivePolicy) (spawnSpec, CompileReport, uint8, uint64, error) {
	return (&linuxBackend{rung: backend.rung}).compile(policy)
}

func (backend *trackingGrantPathBackend) compileWithGrantPaths(policy effectivePolicy, handles []*grantPathHandle) (spawnSpec, CompileReport, uint8, uint64, error) {
	backend.grantCompiles++
	backend.handles = append([]*grantPathHandle(nil), handles...)
	spawn, report, level, bits, err := (&linuxBackend{rung: backend.rung}).compileWithGrantPaths(policy, handles)
	if err != nil {
		return spawnSpec{}, CompileReport{}, LevelNone, 0, err
	}
	_, configure, cleanup := spawn.wrap(policy.Workspace, []string{"/bin/true"})
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = []string{}
	if err := configure(cmd); err != nil {
		cleanup()
		return spawnSpec{}, CompileReport{}, LevelNone, 0, err
	}
	backend.configures++
	backend.spec, err = decodeStage2Spec(cmd.ExtraFiles[0])
	cleanup()
	if err != nil {
		return spawnSpec{}, CompileReport{}, LevelNone, 0, err
	}
	return spawnSpec{wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd) error, func()) {
		return argv, nil, nil
	}}, report, level, bits, nil
}

func (backend *failingGrantPathBackend) compile(effectivePolicy) (spawnSpec, CompileReport, uint8, uint64, error) {
	return spawnSpec{wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd) error, func()) {
		return argv, nil, nil
	}}, CompileReport{}, LevelNone, GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub, nil
}

func (backend *failingGrantPathBackend) compileWithGrantPaths(_ effectivePolicy, handles []*grantPathHandle) (spawnSpec, CompileReport, uint8, uint64, error) {
	backend.handles = append([]*grantPathHandle(nil), handles...)
	return spawnSpec{}, CompileReport{}, LevelNone, 0, errors.New("compile failed")
}

func TestLinuxGrantEnforcementCarriesPinnedFDPastPathSwap(t *testing.T) {
	for _, targetKind := range []struct {
		name  string
		exact bool
	}{
		{name: "exact-file", exact: true},
		{name: "tree-directory", exact: false},
	} {
		for _, rung := range []rung{rungTwo, rungOne} {
			t.Run(targetKind.name+"/rung-"+strconv.Itoa(int(rung)), func(t *testing.T) {
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
				binding, err := captureGrantPathBinding(target)
				if err != nil {
					t.Fatal(err)
				}
				handle, err := acquireGrantPathHandle(&binding, target, targetKind.exact)
				if err != nil {
					t.Fatal(err)
				}
				handle.access = writeFSAccess
				defer handle.Close()

				if err := os.Rename(target, target+".approved"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, target); err != nil {
					t.Fatal(err)
				}

				policy := effectivePolicy{FS: []fsEntry{
					{Path: target, Access: readFSAccess, Exact: targetKind.exact},
					{Path: target, Access: writeFSAccess, Exact: targetKind.exact, Canonical: true},
				}}
				backend := &linuxBackend{rung: rung}
				spawn, _, _, _, err := backend.compileWithGrantPaths(policy, []*grantPathHandle{handle})
				if err != nil {
					t.Fatal(err)
				}
				_, configure, cleanup := spawn.wrap(root, []string{"/bin/true"})
				defer cleanup()
				cmd := exec.Command("/proc/self/exe")
				cmd.Env = []string{}
				if err := configure(cmd); err != nil {
					t.Fatal(err)
				}
				if len(cmd.ExtraFiles) != 2 {
					t.Fatalf("ExtraFiles = %d, want sealed spec plus one pinned grant FD", len(cmd.ExtraFiles))
				}
				spec, err := decodeStage2Spec(cmd.ExtraFiles[0])
				if err != nil {
					t.Fatal(err)
				}
				const grantChildFD = stage2SpecFD + 1
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
				if rung == rungOne {
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
	executor, err := newExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
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
	fd := int(backend.handles[0].file.Fd())
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("grant handle fd %d remains open after compile failure: %v", fd, err)
	}
}

func TestLinuxSameTargetGrantIdentityMismatchFailsBeforeCompilation(t *testing.T) {
	for _, rung := range []rung{rungTwo, rungOne} {
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
				backend := &trackingGrantPathBackend{rung: rung}
				executor, err := newExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
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
				acquire := func(binding *grantPathBinding, canonicalTarget string, exact bool) (*grantPathHandle, error) {
					if err := os.Rename(paths[order.classes[len(acquiredFDs)]], target); err != nil {
						return nil, err
					}
					handle, err := acquireGrantPathHandle(binding, canonicalTarget, exact)
					if err != nil {
						return nil, err
					}
					acquiredFDs = append(acquiredFDs, int(handle.file.Fd()))
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
	for _, rung := range []rung{rungTwo, rungOne} {
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
				backend := &trackingGrantPathBackend{rung: rung}
				executor, err := newExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
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
				acquire := func(binding *grantPathBinding, canonicalTarget string, exact bool) (*grantPathHandle, error) {
					handle, err := acquireGrantPathHandle(binding, canonicalTarget, exact)
					if handle != nil {
						acquiredFDs = append(acquiredFDs, int(handle.file.Fd()))
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
				if backend.handles[0].target != target || backend.handles[0].access != allFSAccess {
					t.Fatalf("coalesced handle = target %q access %#x, want %q all axes", backend.handles[0].target, backend.handles[0].access, target)
				}
				if got, want := backend.spec.GrantFDs, []int{firstGrantPathChildFD}; !slices.Equal(got, want) {
					t.Fatalf("GrantFDs = %v, want canonical collision-free %v", got, want)
				}
				for _, rule := range backend.spec.FSRules {
					if rule.Target == target && (rule.ParentFD == 0 || rule.ParentFD != firstGrantPathChildFD) {
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
	var set grantPathHandleSet
	var acquiredFDs []int
	for i := len(targets) - 1; i >= 0; i-- {
		binding, err := captureGrantPathBinding(targets[i])
		if err != nil {
			t.Fatal(err)
		}
		handle, err := acquireGrantPathHandle(&binding, targets[i], false)
		if err != nil {
			t.Fatal(err)
		}
		acquiredFDs = append(acquiredFDs, int(handle.file.Fd()))
		if err := set.add(handle); err != nil {
			t.Fatal(err)
		}
	}
	handles := set.sorted()
	if len(handles) != len(targets) {
		t.Fatalf("distinct handles = %d, want %d", len(handles), len(targets))
	}
	for i, target := range targets {
		if handles[i].target != target {
			t.Fatalf("canonical handle order = %q at %d, want %q", handles[i].target, i, target)
		}
	}
	descendant := filepath.Join(targets[2], "leaf")
	if got := matchingGrantPathIdentityAncestor(handles, descendant); got != 2 {
		t.Fatalf("longest ancestor index = %d, want inner target at canonical index 2", got)
	}
	set.close()
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
	binding, err := captureGrantPathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := acquireGrantPathHandle(&binding, target, false)
	if err != nil {
		t.Fatal(err)
	}
	handle.access = allFSAccess
	defer handle.Close()

	if err := os.Rename(target, approved); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Fatal(err)
	}

	compiled := compileFSPolicyWithGrantPaths([]fsEntry{
		{Path: target, Access: allFSAccess, Canonical: true},
		{Path: filepath.Join(target, "denied"), Denied: readFSAccess},
		{Path: filepath.Join(target, "missing"), Denied: readFSAccess},
	}, []*grantPathHandle{handle})
	rules, children, err := enumerateFSRulesWithGrantPaths(compiled, []*grantPathHandle{handle})
	if err != nil {
		t.Fatal(err)
	}
	defer closeFiles(children)

	const rootChildFD = firstGrantPathChildFD
	var allowedRead *fsRule
	var rootExec, rootWrite bool
	for i := range rules {
		rule := &rules[i]
		if rule.ParentFD != 0 && rule.Path != "" {
			t.Fatalf("FD-bound rule re-resolved pathname: %+v", *rule)
		}
		if rule.Target == allowed && rule.Access&readFSAccess != 0 {
			allowedRead = rule
		}
		if rule.Target == target && rule.ParentFD == rootChildFD {
			rootExec = rootExec || rule.Access&execFSAccess != 0
			rootWrite = rootWrite || rule.Access&writeFSAccess != 0
			if rule.Access&readFSAccess != 0 {
				t.Fatalf("read axis widened back to pinned root despite nested excludes: %+v", *rule)
			}
		}
		if rule.Target == denied && rule.Access&readFSAccess != 0 {
			t.Fatalf("denied child received read rule: %+v", *rule)
		}
		if rule.Target == filepath.Join(target, "link") {
			t.Fatalf("symlink child received pinned rule: %+v", *rule)
		}
	}
	if allowedRead == nil || allowedRead.ParentFD <= rootChildFD {
		t.Fatalf("rules = %+v, want allowed read via direct child FD after the root grant FD", rules)
	}
	if !rootExec || !rootWrite {
		t.Fatalf("rules = %+v, want independent exec and write axes to retain the pinned root FD", rules)
	}
	childIndex := allowedRead.ParentFD - firstGrantPathChildFD - 1
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
		if rule.Access&readFSAccess != 0 && rule.Target == filepath.Join(target, "new-sibling") {
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
	binding, err := captureGrantPathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := acquireGrantPathHandle(&binding, target, true); !errors.Is(err, ErrGrantUnsupported) {
		t.Fatalf("unchanged nonexistent exact target error = %v, want ErrGrantUnsupported", err)
	}
	if err := os.WriteFile(target, []byte("appeared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := acquireGrantPathHandle(&binding, target, true); !errors.Is(err, ErrGrantTargetChanged) {
		t.Fatalf("newly appeared exact target error = %v, want ErrGrantTargetChanged", err)
	}
}

func TestLinuxPinnedTreeEnumerationFeedsBothRungs(t *testing.T) {
	for _, rung := range []rung{rungTwo, rungOne} {
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
			binding, err := captureGrantPathBinding(target)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := acquireGrantPathHandle(&binding, target, false)
			if err != nil {
				t.Fatal(err)
			}
			handle.access = allFSAccess
			defer handle.Close()
			if err := os.Rename(target, target+".approved"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(root, target); err != nil {
				t.Fatal(err)
			}

			policy := effectivePolicy{FS: []fsEntry{
				{Path: target, Access: allFSAccess, Canonical: true},
				{Path: denied, Denied: readFSAccess},
			}}
			backend := &linuxBackend{rung: rung}
			spawn, _, _, _, err := backend.compileWithGrantPaths(policy, []*grantPathHandle{handle})
			if err != nil {
				t.Fatal(err)
			}
			_, configure, cleanup := spawn.wrap(root, []string{"/bin/true"})
			cmd := exec.Command("/proc/self/exe")
			cmd.Env = []string{}
			if err := configure(cmd); err != nil {
				t.Fatal(err)
			}
			if len(cmd.ExtraFiles) < 3 {
				t.Fatalf("ExtraFiles = %d, want spec + root grant + relative child", len(cmd.ExtraFiles))
			}
			spec, err := decodeStage2Spec(cmd.ExtraFiles[0])
			if err != nil {
				t.Fatal(err)
			}
			var allowedRead fsRule
			for _, rule := range spec.FSRules {
				if rule.Target == allowed && rule.Access&readFSAccess != 0 {
					allowedRead = rule
				}
				if rule.Target == denied && rule.Access&readFSAccess != 0 {
					t.Fatalf("denied read rule reached rung %d spec: %+v", rung, rule)
				}
			}
			if allowedRead.ParentFD <= firstGrantPathChildFD || allowedRead.Path != "" {
				t.Fatalf("rung %d allowed read rule = %+v, want direct relative child FD", rung, allowedRead)
			}
			if rung == rungOne {
				wantSource := "/proc/self/fd/" + strconv.Itoa(allowedRead.ParentFD)
				var found bool
				for _, bind := range spec.MountView.Binds {
					if bind.Target == allowed && bind.Source == wantSource {
						found = true
					}
				}
				if !found {
					t.Fatalf("rung-1 binds = %+v, want allowed child sourced only from %q", spec.MountView.Binds, wantSource)
				}
			}

			childFDs := make([]int, 0, len(cmd.ExtraFiles)-2)
			for _, file := range cmd.ExtraFiles[2:] {
				childFDs = append(childFDs, int(file.Fd()))
			}
			cleanup()
			for _, fd := range childFDs {
				if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
					t.Fatalf("rung %d relative child fd %d remains open after cleanup: %v", rung, fd, err)
				}
			}
		})
	}
}

func TestLinuxPinnedDescendantRestorationFeedsBothRungs(t *testing.T) {
	for _, rung := range []rung{rungTwo, rungOne} {
		t.Run("rung-"+strconv.Itoa(int(rung)), func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "target")
			denied := filepath.Join(target, "denied")
			restored := filepath.Join(denied, "restored")
			if err := os.MkdirAll(restored, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(restored, "identity"), []byte("approved"), 0o600); err != nil {
				t.Fatal(err)
			}
			binding, err := captureGrantPathBinding(target)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := acquireGrantPathHandle(&binding, target, false)
			if err != nil {
				t.Fatal(err)
			}
			handle.access = allFSAccess
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

			policy := effectivePolicy{FS: []fsEntry{
				{Path: target, Access: allFSAccess, Canonical: true},
				{Path: denied, Denied: readFSAccess},
				{Path: restored, Access: readFSAccess},
			}}
			spec, cmd, cleanup := compilePinnedGrantSpec(t, rung, root, policy, []*grantPathHandle{handle})
			assertPinnedDescendantRule(t, spec, cmd, restored, readFSAccess, "approved", rung)
			var rootAxes fsAccess
			for _, rule := range spec.FSRules {
				if rule.Target == target && rule.ParentFD == firstGrantPathChildFD {
					rootAxes |= rule.Access
				}
			}
			if rootAxes != execFSAccess|writeFSAccess {
				t.Fatalf("root unaffected axes = %#x, want exec|write", rootAxes)
			}
			cleanup()
		})
	}
}

func TestLinuxPinnedNestedAdditionalRootFeedsBothRungs(t *testing.T) {
	for _, rung := range []rung{rungTwo, rungOne} {
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
			binding, err := captureGrantPathBinding(target)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := acquireGrantPathHandle(&binding, target, false)
			if err != nil {
				t.Fatal(err)
			}
			handle.access = writeFSAccess
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

			policy := effectivePolicy{FS: []fsEntry{
				{Path: target, Access: writeFSAccess, Canonical: true},
				{Path: additional, Access: readFSAccess | execFSAccess},
			}}
			spec, cmd, cleanup := compilePinnedGrantSpec(t, rung, root, policy, []*grantPathHandle{handle})
			assertPinnedDescendantRule(t, spec, cmd, additional, readFSAccess|execFSAccess, "approved", rung)
			cleanup()
		})
	}
}

func TestLinuxPinnedDescendantLongestAncestorFeedsBothRungs(t *testing.T) {
	for _, rung := range []rung{rungTwo, rungOne} {
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
			outerBinding, err := captureGrantPathBinding(outer)
			if err != nil {
				t.Fatal(err)
			}
			outerHandle, err := acquireGrantPathHandle(&outerBinding, outer, false)
			if err != nil {
				t.Fatal(err)
			}
			outerHandle.access = writeFSAccess
			defer outerHandle.Close()
			innerBinding, err := captureGrantPathBinding(inner)
			if err != nil {
				t.Fatal(err)
			}
			innerHandle, err := acquireGrantPathHandle(&innerBinding, inner, false)
			if err != nil {
				t.Fatal(err)
			}
			innerHandle.access = writeFSAccess
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

			policy := effectivePolicy{FS: []fsEntry{
				{Path: outer, Access: writeFSAccess, Canonical: true},
				{Path: inner, Access: writeFSAccess, Canonical: true},
				{Path: leaf, Access: readFSAccess},
			}}
			spec, cmd, cleanup := compilePinnedGrantSpec(t, rung, root, policy, []*grantPathHandle{outerHandle, innerHandle})
			assertPinnedDescendantRule(t, spec, cmd, leaf, readFSAccess, "longest", rung)
			cleanup()
		})
	}
}

func TestLinuxPinnedCarveEnumerationReselectsLongestAncestorBothRungs(t *testing.T) {
	for _, rung := range []rung{rungTwo, rungOne} {
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
			outerBinding, err := captureGrantPathBinding(outer)
			if err != nil {
				t.Fatal(err)
			}
			outerHandle, err := acquireGrantPathHandle(&outerBinding, outer, false)
			if err != nil {
				t.Fatal(err)
			}
			outerHandle.access = readFSAccess
			defer outerHandle.Close()
			innerBinding, err := captureGrantPathBinding(inner)
			if err != nil {
				t.Fatal(err)
			}
			innerHandle, err := acquireGrantPathHandle(&innerBinding, inner, false)
			if err != nil {
				t.Fatal(err)
			}
			innerHandle.access = readFSAccess
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

			policy := effectivePolicy{FS: []fsEntry{
				{Path: outer, Access: readFSAccess, Canonical: true},
				{Path: inner, Access: readFSAccess, Canonical: true},
				{Path: denied, Denied: readFSAccess},
			}}
			spec, cmd, cleanup := compilePinnedGrantSpec(t, rung, root, policy, []*grantPathHandle{outerHandle, innerHandle})
			defer cleanup()
			var found bool
			for _, rule := range spec.FSRules {
				if rule.Target != allowed || rule.Access&readFSAccess == 0 {
					continue
				}
				found = true
				extraIndex := rule.ParentFD - stage2SpecFD
				if rule.Path != "" || extraIndex < 0 || extraIndex >= len(cmd.ExtraFiles) {
					t.Fatalf("carved rule did not carry direct child handle: %+v", rule)
				}
				contents, err := os.ReadFile("/proc/self/fd/" + strconv.Itoa(int(cmd.ExtraFiles[extraIndex].Fd())) + "/identity")
				if err != nil {
					t.Fatal(err)
				}
				if string(contents) != "longest" {
					t.Fatalf("carved rule resolved from shorter pinned ancestor: rule=%+v identity=%q", rule, contents)
				}
			}
			if !found {
				t.Fatalf("FSRules = %+v, want carved allowed descendant", spec.FSRules)
			}
		})
	}
}

func TestLinuxPinnedDescendantSymlinkAndMissingFailClosedBothRungs(t *testing.T) {
	for _, rung := range []rung{rungTwo, rungOne} {
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
			binding, err := captureGrantPathBinding(target)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := acquireGrantPathHandle(&binding, target, false)
			if err != nil {
				t.Fatal(err)
			}
			handle.access = writeFSAccess
			defer handle.Close()

			if err := os.Rename(target, target+".approved"); err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{symlink, missing} {
				if err := os.MkdirAll(path, 0o700); err != nil {
					t.Fatal(err)
				}
			}

			policy := effectivePolicy{FS: []fsEntry{
				{Path: target, Access: writeFSAccess, Canonical: true},
				{Path: symlink, Access: readFSAccess},
				{Path: missing, Access: readFSAccess},
			}}
			spec, _, cleanup := compilePinnedGrantSpec(t, rung, root, policy, []*grantPathHandle{handle})
			defer cleanup()
			for _, rule := range spec.FSRules {
				if rule.Target == symlink || rule.Target == missing || rule.Path == symlink || rule.Path == missing {
					t.Fatalf("unresolvable pinned descendant received rule: %+v", rule)
				}
			}
			for _, bind := range spec.MountView.Binds {
				if bind.Target == symlink || bind.Target == missing {
					t.Fatalf("unresolvable pinned descendant received bind: %+v", bind)
				}
			}
		})
	}
}

func TestLinuxPinnedExactFileIsNeverAnAncestor(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "exact")
	if err := os.WriteFile(target, []byte("approved"), 0o600); err != nil {
		t.Fatal(err)
	}
	binding, err := captureGrantPathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := acquireGrantPathHandle(&binding, target, true)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	descendant := filepath.Join(target, "child")
	if got := matchingGrantPathAncestor([]*grantPathHandle{handle}, descendant, false); got != -1 {
		t.Fatalf("exact-file handle selected as typed ancestor: %d", got)
	}
	if got := matchingGrantPathIdentityAncestor([]*grantPathHandle{handle}, descendant); got != -1 {
		t.Fatalf("exact-file handle selected as identity ancestor: %d", got)
	}
}

func TestLinuxPinnedDescendantFDTransportAndCleanup(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	descendant := filepath.Join(target, "descendant")
	if err := os.MkdirAll(descendant, 0o700); err != nil {
		t.Fatal(err)
	}
	binding, err := captureGrantPathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := acquireGrantPathHandle(&binding, target, false)
	if err != nil {
		t.Fatal(err)
	}
	handle.access = writeFSAccess
	defer handle.Close()
	policy := effectivePolicy{FS: []fsEntry{
		{Path: target, Access: writeFSAccess, Canonical: true},
		{Path: descendant, Access: readFSAccess},
	}}
	spec, cmd, cleanup := compilePinnedGrantSpec(t, rungTwo, root, policy, []*grantPathHandle{handle})
	if len(cmd.ExtraFiles) != 3 {
		t.Fatalf("ExtraFiles = %d, want sealed spec + root + descendant", len(cmd.ExtraFiles))
	}
	wantFDs := []int{firstGrantPathChildFD, firstGrantPathChildFD + 1}
	if len(spec.GrantFDs) != len(wantFDs) {
		t.Fatalf("GrantFDs = %v, want %v", spec.GrantFDs, wantFDs)
	}
	seen := make(map[int]bool)
	for i, fd := range spec.GrantFDs {
		if fd != wantFDs[i] || fd <= stage2SpecFD || seen[fd] {
			t.Fatalf("GrantFDs = %v, want collision-free %v with no zero sentinel", spec.GrantFDs, wantFDs)
		}
		seen[fd] = true
	}
	descendantParentFD := spec.GrantFDs[1]
	if descendantParentFD == 0 {
		t.Fatal("descendant ParentFD used zero pathname sentinel")
	}
	actualDescendantFD := int(cmd.ExtraFiles[descendantParentFD-stage2SpecFD].Fd())
	cleanup()
	if _, err := unix.FcntlInt(uintptr(actualDescendantFD), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
		t.Fatalf("descendant transport fd %d remains open after cleanup: %v", actualDescendantFD, err)
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
	binding, err := captureGrantPathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := acquireGrantPathHandle(&binding, target, false)
	if err != nil {
		t.Fatal(err)
	}
	handle.access = allFSAccess
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

	policy := effectivePolicy{FS: []fsEntry{
		{Path: target, Access: allFSAccess, Canonical: true},
		{Path: denied, Denied: allFSAccess},
		{Path: "**/*.secret", Denied: allFSAccess},
	}}
	spec, _, cleanup := compilePinnedGrantSpec(t, rungOne, root, policy, []*grantPathHandle{handle})
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

func compilePinnedGrantSpec(t *testing.T, rung rung, dir string, policy effectivePolicy, handles []*grantPathHandle) (stage2Spec, *exec.Cmd, func()) {
	t.Helper()
	backend := &linuxBackend{rung: rung}
	spawn, _, _, _, err := backend.compileWithGrantPaths(policy, handles)
	if err != nil {
		t.Fatal(err)
	}
	_, configure, cleanup := spawn.wrap(dir, []string{"/bin/true"})
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = []string{}
	if err := configure(cmd); err != nil {
		cleanup()
		t.Fatal(err)
	}
	spec, err := decodeStage2Spec(cmd.ExtraFiles[0])
	if err != nil {
		cleanup()
		t.Fatal(err)
	}
	return spec, cmd, cleanup
}

func assertPinnedDescendantRule(t *testing.T, spec stage2Spec, cmd *exec.Cmd, target string, access fsAccess, wantIdentity string, rung rung) {
	t.Helper()
	var pinned *fsRule
	for i := range spec.FSRules {
		rule := &spec.FSRules[i]
		if rule.Target == target && rule.Access&access != 0 {
			if rule.Path != "" || rule.ParentFD <= firstGrantPathChildFD {
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
	extraIndex := pinned.ParentFD - stage2SpecFD
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
	if rung != rungOne {
		return
	}
	wantSource := "/proc/self/fd/" + strconv.Itoa(pinned.ParentFD)
	for _, bind := range spec.MountView.Binds {
		if bind.Target == target {
			if bind.Source != wantSource {
				t.Fatalf("rung-1 descendant source = %q, want %q", bind.Source, wantSource)
			}
			return
		}
	}
	t.Fatalf("rung-1 binds = %+v, want descendant target %q", spec.MountView.Binds, target)
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
