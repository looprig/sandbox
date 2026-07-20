//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

type pinnedPathResolution struct {
	file    *os.File
	childFD int
	isDir   bool
}

type pinnedPathResolver struct {
	handles []*grantPathHandle
	firstFD int
	files   []*os.File
	paths   map[string]pinnedPathResolution
}

func newPinnedPathResolver(handles []*grantPathHandle, firstFD int) *pinnedPathResolver {
	return &pinnedPathResolver{
		handles: handles,
		firstFD: firstFD,
		paths:   make(map[string]pinnedPathResolution),
	}
}

func (resolver *pinnedPathResolver) resolve(target string, exact bool) (pinnedPathResolution, bool, error) {
	return resolver.resolveTyped(target, exact, true)
}

func (resolver *pinnedPathResolver) resolveAny(target string) (pinnedPathResolution, bool, error) {
	return resolver.resolveTyped(target, false, false)
}

func (resolver *pinnedPathResolver) resolveTyped(target string, exact, checkType bool) (pinnedPathResolution, bool, error) {
	target = filepath.Clean(target)
	if cached, ok := resolver.paths[target]; ok {
		if checkType {
			if err := validatePinnedPathType(cached.isDir, exact, target); err != nil {
				return pinnedPathResolution{}, false, err
			}
		}
		return cached, true, nil
	}
	index := matchingGrantPathIdentityAncestor(resolver.handles, target)
	if checkType {
		index = matchingGrantPathAncestor(resolver.handles, target, exact)
	}
	if index < 0 {
		return pinnedPathResolution{}, false, nil
	}
	handle := resolver.handles[index]
	if handle.target == target {
		resolved := pinnedPathResolution{
			file: handle.file, childFD: firstGrantPathChildFD + index,
			isDir: handle.isDir,
		}
		if checkType {
			if err := validatePinnedPathType(resolved.isDir, exact, target); err != nil {
				return pinnedPathResolution{}, false, err
			}
		}
		resolver.paths[target] = resolved
		return resolved, true, nil
	}
	relative, err := filepath.Rel(handle.target, target)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return pinnedPathResolution{}, false, ErrGrantUnsupported
	}
	fd, err := unix.Openat2(int(handle.file.Fd()), relative, &unix.OpenHow{
		Flags: uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS),
	})
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return pinnedPathResolution{}, false, nil
	}
	if err != nil {
		return pinnedPathResolution{}, false, fmt.Errorf("%w: open pinned descendant %q: %v", ErrGrantUnsupported, target, err)
	}
	file := os.NewFile(uintptr(fd), "sandbox-grant-descendant")
	if file == nil {
		_ = unix.Close(fd)
		return pinnedPathResolution{}, false, ErrGrantUnsupported
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return pinnedPathResolution{}, false, fmt.Errorf("%w: stat pinned descendant %q: %v", ErrGrantUnsupported, target, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		_ = file.Close()
		return pinnedPathResolution{}, false, nil
	}
	if checkType {
		if err := validatePinnedPathType(info.IsDir(), exact, target); err != nil {
			_ = file.Close()
			return pinnedPathResolution{}, false, err
		}
	}
	resolved := pinnedPathResolution{
		file: file, childFD: resolver.firstFD + len(resolver.files),
		isDir: info.IsDir(),
	}
	resolver.files = append(resolver.files, file)
	resolver.paths[target] = resolved
	return resolved, true, nil
}

func validatePinnedPathType(isDir, exact bool, target string) error {
	if exact && isDir {
		return fmt.Errorf("%w: pinned exact path %q is a directory", ErrGrantUnsupported, target)
	}
	if !exact && !isDir {
		return fmt.Errorf("%w: pinned tree path %q is not a directory", ErrGrantUnsupported, target)
	}
	return nil
}

func (resolver *pinnedPathResolver) addFile(file *os.File) int {
	childFD := resolver.firstFD + len(resolver.files)
	resolver.files = append(resolver.files, file)
	return childFD
}

func enumerateGrantPathHandle(handle *grantPathHandle, target string, access fsAccess, excludes []string, firstFD int) ([]fsRule, []*os.File, error) {
	if handle == nil || handle.file == nil || !handle.isDir || handle.target != target || firstFD <= stage2SpecFD {
		return nil, nil, ErrGrantUnsupported
	}
	var files []*os.File
	rules, err := enumeratePinnedTree(handle.file, target, access, excludes, func(file *os.File) int {
		childFD := firstFD + len(files)
		files = append(files, file)
		return childFD
	}, nil)
	if err != nil {
		closeGrantRuleFiles(files)
		return nil, nil, err
	}
	return rules, files, nil
}

func enumeratePinnedTree(root *os.File, target string, access fsAccess, excludes []string, addFile func(*os.File) int, resolver *pinnedPathResolver) ([]fsRule, error) {
	var rules []fsRule
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
			var child *os.File
			var ruleFD int
			owned := false
			if resolver != nil {
				resolved, ok, err := resolver.resolveAny(childTarget)
				if err != nil {
					return err
				}
				if !ok {
					continue
				}
				child = resolved.file
				ruleFD = resolved.childFD
			} else {
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
				child = os.NewFile(uintptr(childFD), "sandbox-grant-child")
				if child == nil {
					_ = unix.Close(childFD)
					return ErrGrantUnsupported
				}
				owned = true
			}
			info, err := child.Stat()
			if err != nil {
				if owned {
					_ = child.Close()
				}
				return fmt.Errorf("%w: stat pinned child %q: %v", ErrGrantUnsupported, childTarget, err)
			}
			if info.Mode()&os.ModeSymlink != 0 {
				if owned {
					_ = child.Close()
				}
				continue
			}
			deeper := excludesUnder(nestedExcludes, childTarget)
			if len(deeper) == 0 {
				if owned {
					ruleFD = addFile(child)
					owned = false
				}
				rules = append(rules, fsRule{
					Target: childTarget, ParentFD: ruleFD,
					Access: access, IsDir: info.IsDir(),
				})
				continue
			}
			if info.IsDir() {
				err = walk(int(child.Fd()), childTarget, deeper)
			}
			if owned {
				_ = child.Close()
			}
			if err != nil {
				return err
			}
		}
		return nil
	}
	if err := walk(int(root.Fd()), target, excludes); err != nil {
		return nil, err
	}
	return rules, nil
}
