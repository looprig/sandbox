//go:build linux

package linux

import (
	"errors"
	"github.com/looprig/sandbox/internal/policy"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestValidateRetainedLandlockFileFDRejectsLateHardlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	alias := filepath.Join(root, "alias")
	if err := os.WriteFile(target, []byte("checked"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(target, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)

	if err := validateRetainedLandlockFD(fd, false); err != nil {
		t.Fatalf("single-link retained file rejected: %v", err)
	}
	if err := os.Link(target, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	if err := validateRetainedLandlockFD(fd, false); err == nil {
		t.Fatal("retained file accepted after a hard link was added")
	}
}

func TestValidateRetainedLandlockFDRequiresDeclaredShape(t *testing.T) {
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := validateRetainedLandlockFD(fd, false); err == nil {
		t.Fatal("retained directory accepted as a direct file rule")
	}
	if err := validateRetainedLandlockFD(fd, true); err != nil {
		t.Fatalf("retained directory rejected as a directory rule: %v", err)
	}

	file, err := os.Create(filepath.Join(t.TempDir(), "file"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if err := validateRetainedLandlockFD(int(file.Fd()), true); err == nil {
		t.Fatal("retained regular file accepted as a directory rule")
	}
}

func TestOpenLandlockDirectoryRuleRequiresDirectoryWithoutFollowingLeafSymlink(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, "directory")
	regular := filepath.Join(root, "regular")
	link := filepath.Join(root, "link")
	ancestorLink := filepath.Join(root, "ancestor-link")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(regular, []byte("regular"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(directory, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	if err := os.Symlink(root, ancestorLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	fd, err := openLandlockRulePath(directory, true)
	if err != nil {
		t.Fatalf("open directory rule: %v", err)
	}
	if err := unix.Close(fd); err != nil {
		t.Fatal(err)
	}
	if fd, err := openLandlockRulePath(regular, true); err == nil {
		_ = unix.Close(fd)
		t.Fatal("regular file accepted as a path-backed directory rule")
	}
	if fd, err := openLandlockRulePath(link, true); err == nil {
		_ = unix.Close(fd)
		t.Fatal("leaf symlink accepted as a path-backed directory rule")
	}
	if fd, err := openLandlockRulePath(filepath.Join(ancestorLink, "directory"), true); err == nil {
		_ = unix.Close(fd)
		t.Fatal("ancestor symlink accepted as a path-backed directory rule")
	}
}

func TestValidateStage2GrantFDsRequiresContiguousTransportAndRuleMembership(t *testing.T) {
	valid := Stage2Spec{
		GrantFDs: []int{Stage2SpecFD + 1, Stage2SpecFD + 2},
		FSRules: []policy.FSRule{
			{Path: "/path-backed", IsDir: true},
			{Target: "/fd-backed", ParentFD: Stage2SpecFD + 2},
		},
	}
	if err := validateStage2GrantFDs(valid); err != nil {
		t.Fatalf("valid transport rejected: %v", err)
	}

	tests := []struct {
		name string
		spec Stage2Spec
		err  error
	}{
		{
			name: "gap",
			spec: Stage2Spec{GrantFDs: []int{Stage2SpecFD + 1, Stage2SpecFD + 3}},
			err:  unix.EBADF,
		},
		{
			name: "duplicate",
			spec: Stage2Spec{GrantFDs: []int{Stage2SpecFD + 1, Stage2SpecFD + 1}},
			err:  unix.EBADF,
		},
		{
			name: "untransported rule fd",
			spec: Stage2Spec{
				GrantFDs: []int{Stage2SpecFD + 1},
				FSRules:  []policy.FSRule{{Target: "/target", ParentFD: Stage2SpecFD + 2}},
			},
			err: unix.EBADF,
		},
		{
			name: "mixed path and fd metadata",
			spec: Stage2Spec{
				GrantFDs: []int{Stage2SpecFD + 1},
				FSRules: []policy.FSRule{{
					Path: "/path", Target: "/target", ParentFD: Stage2SpecFD + 1,
				}},
			},
			err: unix.EINVAL,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := validateStage2GrantFDs(test.spec); !errors.Is(err, test.err) {
				t.Fatalf("error = %v, want %v", err, test.err)
			}
		})
	}
}
