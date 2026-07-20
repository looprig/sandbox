//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"golang.org/x/sys/unix"
)

func enumerateGrantPathHandle(handle *grantPathHandle, target string, access fsAccess, excludes []string, firstFD int) ([]fsRule, []*os.File, error) {
	if handle == nil || handle.file == nil || !handle.isDir || handle.target != target || firstFD <= stage2SpecFD {
		return nil, nil, ErrGrantUnsupported
	}
	var rules []fsRule
	var files []*os.File
	var walk func(int, string, []string) error
	walk = func(dirFD int, dirTarget string, nestedExcludes []string) error {
		readFD, err := unix.Openat2(dirFD, ".", &unix.OpenHow{
			Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
			Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS |
				unix.RESOLVE_NO_MAGICLINKS),
		})
		if err != nil {
			return fmt.Errorf("%w: enumerate pinned tree %q: %v", ErrGrantUnsupported, dirTarget, err)
		}
		readDir := os.NewFile(uintptr(readFD), "sandbox-grant-enumerate")
		if readDir == nil {
			_ = unix.Close(readFD)
			return ErrGrantUnsupported
		}
		entries, err := readDir.ReadDir(-1)
		_ = readDir.Close()
		if err != nil {
			return fmt.Errorf("%w: enumerate pinned tree %q: %v", ErrGrantUnsupported, dirTarget, err)
		}
		for _, entry := range entries {
			childTarget := filepath.Join(dirTarget, entry.Name())
			if slices.Contains(nestedExcludes, childTarget) {
				continue
			}
			childFD, err := unix.Openat2(dirFD, entry.Name(), &unix.OpenHow{
				Flags: uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC),
				Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS |
					unix.RESOLVE_NO_MAGICLINKS),
			})
			if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) {
				continue
			}
			if err != nil {
				return fmt.Errorf("%w: open pinned child %q: %v", ErrGrantUnsupported, childTarget, err)
			}
			child := os.NewFile(uintptr(childFD), "sandbox-grant-child")
			if child == nil {
				_ = unix.Close(childFD)
				return ErrGrantUnsupported
			}
			info, err := child.Stat()
			if err != nil {
				_ = child.Close()
				return fmt.Errorf("%w: stat pinned child %q: %v", ErrGrantUnsupported, childTarget, err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				_ = child.Close()
				continue
			}
			deeper := excludesUnder(nestedExcludes, childTarget)
			if len(deeper) == 0 {
				rules = append(rules, fsRule{
					Target: childTarget, ParentFD: firstFD + len(files),
					Access: access, IsDir: info.IsDir(),
				})
				files = append(files, child)
				continue
			}
			if info.IsDir() {
				err = walk(int(child.Fd()), childTarget, deeper)
			}
			_ = child.Close()
			if err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(int(handle.file.Fd()), target, excludes); err != nil {
		closeGrantRuleFiles(files)
		return nil, nil, err
	}
	return rules, files, nil
}
