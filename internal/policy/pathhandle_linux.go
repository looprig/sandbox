//go:build linux

package policy

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func AcquirePathHandle(binding *PathBinding, target string, exact bool) (*PathHandle, error) {
	if binding == nil || binding.CanonicalPath != target {
		return nil, ErrTargetChanged
	}
	if binding.ExistingPath != target {
		// Revalidation distinguishes an unchanged missing suffix from one that
		// appeared or changed since approval. Landlock cannot represent an exact
		// nonexistent object, so unchanged absence is unsupported; any suffix drift
		// remains a target-change error.
		if err := RevalidatePathBinding(binding, target); err != nil {
			return nil, err
		}
		return nil, ErrUnsupportedClass
	}
	how := &unix.OpenHow{
		Flags: uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: uint64(unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS),
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, target, how)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTargetChanged, err)
	}
	file := os.NewFile(uintptr(fd), "sandbox-grant-path")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrTargetChanged
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %v", ErrTargetChanged, err)
	}
	identity, err := fileInfoIdentity(info)
	if err != nil || identity != binding.Identity {
		_ = file.Close()
		return nil, ErrTargetChanged
	}
	if exact {
		if !info.Mode().IsRegular() {
			_ = file.Close()
			return nil, ErrUnsupportedClass
		}
		if !directRegularFileRuleSafe(info) {
			_ = file.Close()
			return nil, ErrUnsupportedClass
		}
	} else if !info.IsDir() {
		_ = file.Close()
		return nil, ErrUnsupportedClass
	}
	return &PathHandle{
		file: file, target: target, exact: exact, isDir: info.IsDir(), identity: identity,
	}, nil
}

func samePathHandleTarget(left, right string) bool { return left == right }
