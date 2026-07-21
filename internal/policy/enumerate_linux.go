//go:build linux

package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// PinnedPathResolution is one path resolved through an identity-pinned handle:
// the open descriptor, the number it will carry in the child, and whether it is
// a directory.
type PinnedPathResolution struct {
	File    *os.File
	ChildFD int
	IsDir   bool
}

type PinnedPathResolver struct {
	handles []*PathHandle
	firstFD int
	files   []*os.File
	paths   map[string]PinnedPathResolution
}

func NewPinnedPathResolver(handles []*PathHandle, firstFD int) *PinnedPathResolver {
	return &PinnedPathResolver{
		handles: handles,
		firstFD: firstFD,
		paths:   make(map[string]PinnedPathResolution),
	}
}

func (resolver *PinnedPathResolver) resolve(target string, exact bool) (PinnedPathResolution, bool, error) {
	return resolver.resolveTyped(target, exact, true)
}

// ResolveAny resolves target against any pinned handle, exact or tree.
func (resolver *PinnedPathResolver) ResolveAny(target string) (PinnedPathResolution, bool, error) {
	return resolver.resolveTyped(target, false, false)
}

func (resolver *PinnedPathResolver) resolveTyped(target string, exact, checkType bool) (PinnedPathResolution, bool, error) {
	target = filepath.Clean(target)
	if cached, ok := resolver.paths[target]; ok {
		if checkType {
			if err := validatePinnedPathType(cached.IsDir, exact, target); err != nil {
				return PinnedPathResolution{}, false, err
			}
		}
		return cached, true, nil
	}
	index := MatchingPathHandleIdentityAncestor(resolver.handles, target)
	if checkType {
		index = MatchingPathHandleAncestor(resolver.handles, target, exact)
	}
	if index < 0 {
		return PinnedPathResolution{}, false, nil
	}
	handle := resolver.handles[index]
	if handle.target == target {
		resolved := PinnedPathResolution{
			File: handle.file, ChildFD: FirstPathHandleChildFD + index,
			IsDir: handle.isDir,
		}
		if checkType {
			if err := validatePinnedPathType(resolved.IsDir, exact, target); err != nil {
				return PinnedPathResolution{}, false, err
			}
		}
		resolver.paths[target] = resolved
		return resolved, true, nil
	}
	relative, err := filepath.Rel(handle.target, target)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return PinnedPathResolution{}, false, ErrUnsupportedClass
	}
	fd, err := unix.Openat2(int(handle.file.Fd()), relative, &unix.OpenHow{
		Flags: uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS |
			unix.RESOLVE_NO_MAGICLINKS),
	})
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
		return PinnedPathResolution{}, false, nil
	}
	if err != nil {
		return PinnedPathResolution{}, false, fmt.Errorf("%w: open pinned descendant %q: %v", ErrUnsupportedClass, target, err)
	}
	file := os.NewFile(uintptr(fd), "sandbox-grant-descendant")
	if file == nil {
		_ = unix.Close(fd)
		return PinnedPathResolution{}, false, ErrUnsupportedClass
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return PinnedPathResolution{}, false, fmt.Errorf("%w: stat pinned descendant %q: %v", ErrUnsupportedClass, target, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		_ = file.Close()
		return PinnedPathResolution{}, false, nil
	}
	if checkType {
		if err := validatePinnedPathType(info.IsDir(), exact, target); err != nil {
			_ = file.Close()
			return PinnedPathResolution{}, false, err
		}
	}
	resolved := PinnedPathResolution{
		File: file, ChildFD: resolver.firstFD + len(resolver.files),
		IsDir: info.IsDir(),
	}
	resolver.files = append(resolver.files, file)
	resolver.paths[target] = resolved
	return resolved, true, nil
}

func validatePinnedPathType(isDir, exact bool, target string) error {
	if exact && isDir {
		return fmt.Errorf("%w: pinned exact path %q is a directory", ErrUnsupportedClass, target)
	}
	if !exact && !isDir {
		return fmt.Errorf("%w: pinned tree path %q is not a directory", ErrUnsupportedClass, target)
	}
	return nil
}

func (resolver *PinnedPathResolver) addFile(file *os.File) int {
	childFD := resolver.firstFD + len(resolver.files)
	resolver.files = append(resolver.files, file)
	return childFD
}

func enumerateGrantPathHandle(handle *PathHandle, target string, access FSAccess, excludes []string, firstFD int) ([]FSRule, []*os.File, error) {
	if handle == nil || handle.file == nil || !handle.isDir || handle.target != target || firstFD <= ReservedSpecFD {
		return nil, nil, ErrUnsupportedClass
	}
	var files []*os.File
	rules, err := enumeratePinnedTree(handle.file, target, access, excludes, func(file *os.File) int {
		childFD := firstFD + len(files)
		files = append(files, file)
		return childFD
	}, nil)
	if err != nil {
		CloseRuleFiles(files)
		return nil, nil, err
	}
	return rules, files, nil
}

func enumeratePinnedTree(root *os.File, target string, access FSAccess, excludes []string, addFile func(*os.File) int, resolver *PinnedPathResolver) ([]FSRule, error) {
	var rules []FSRule
	var walk func(int, string, []string) error
	walk = func(dirFD int, dirTarget string, nestedExcludes []string) error {
		readFD, err := unix.Openat2(dirFD, ".", &unix.OpenHow{
			Flags: uint64(unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC),
			Resolve: uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS |
				unix.RESOLVE_NO_MAGICLINKS),
		})
		if err != nil {
			return fmt.Errorf("%w: enumerate pinned tree %q: %v", ErrUnsupportedClass, dirTarget, err)
		}
		readDir := os.NewFile(uintptr(readFD), "sandbox-grant-enumerate")
		if readDir == nil {
			_ = unix.Close(readFD)
			return ErrUnsupportedClass
		}
		entries, err := readDir.ReadDir(-1)
		_ = readDir.Close()
		if err != nil {
			return fmt.Errorf("%w: enumerate pinned tree %q: %v", ErrUnsupportedClass, dirTarget, err)
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
				resolved, ok, err := resolver.ResolveAny(childTarget)
				if err != nil {
					return err
				}
				if !ok {
					continue
				}
				child = resolved.File
				ruleFD = resolved.ChildFD
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
					return fmt.Errorf("%w: open pinned child %q: %v", ErrUnsupportedClass, childTarget, err)
				}
				child = os.NewFile(uintptr(childFD), "sandbox-grant-child")
				if child == nil {
					_ = unix.Close(childFD)
					return ErrUnsupportedClass
				}
				owned = true
			}
			info, err := child.Stat()
			if err != nil {
				if owned {
					_ = child.Close()
				}
				return fmt.Errorf("%w: stat pinned child %q: %v", ErrUnsupportedClass, childTarget, err)
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
				rules = append(rules, FSRule{
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

// Files returns the descriptors the resolver opened while enumerating rules.
// The caller takes responsibility for closing them via CloseRuleFiles.
func (resolver *PinnedPathResolver) Files() []*os.File {
	if resolver == nil {
		return nil
	}
	return resolver.files
}
