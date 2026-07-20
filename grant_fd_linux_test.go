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
	return spawnSpec{wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd), func()) {
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
				configure(cmd)
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
