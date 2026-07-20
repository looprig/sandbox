//go:build linux

package sandbox

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

func acquireGrantPathHandle(binding *grantPathBinding, target string, exact bool) (*grantPathHandle, error) {
	if binding == nil || binding.CanonicalPath != target || binding.ExistingPath != target {
		return nil, ErrGrantTargetChanged
	}
	how := &unix.OpenHow{
		Flags: uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: uint64(unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS),
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, target, how)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrGrantTargetChanged, err)
	}
	file := os.NewFile(uintptr(fd), "sandbox-grant-path")
	if file == nil {
		_ = unix.Close(fd)
		return nil, ErrGrantTargetChanged
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, fmt.Errorf("%w: %v", ErrGrantTargetChanged, err)
	}
	identity, err := fileInfoIdentity(info)
	if err != nil || identity != binding.Identity {
		_ = file.Close()
		return nil, ErrGrantTargetChanged
	}
	if exact {
		if !info.Mode().IsRegular() {
			_ = file.Close()
			return nil, ErrGrantUnsupported
		}
	} else if !info.IsDir() {
		_ = file.Close()
		return nil, ErrGrantUnsupported
	}
	return &grantPathHandle{file: file, target: target, exact: exact, isDir: info.IsDir()}, nil
}
