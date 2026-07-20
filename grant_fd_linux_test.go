//go:build linux

package sandbox

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type failingGrantPathBackend struct {
	handles []*grantPathHandle
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
