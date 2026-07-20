package sandbox

import (
	"os"
	"slices"
	"strings"
)

// grantPathHandle owns the identity-bound descriptor for one exact-file or
// tree-directory grant between authentication and child confinement setup.
type grantPathHandle struct {
	file   *os.File
	target string
	exact  bool
	isDir  bool
	access fsAccess
	// identity is the device/inode/object-type tuple captured from the opened
	// descriptor. It is compared when multiple tokens name one canonical target.
	identity string
}

func (handle *grantPathHandle) Close() error {
	if handle == nil || handle.file == nil {
		return nil
	}
	return handle.file.Close()
}

func closeGrantPathHandles(handles []*grantPathHandle) {
	for _, handle := range handles {
		_ = handle.Close()
	}
}

// grantPathHandleSet is the sole owner of every non-nil handle added to it.
// Equal canonical targets are safe to coalesce only when their opened object
// identities match. A mismatch closes the incoming handle and every handle the
// set already owns before returning ErrGrantTargetChanged.
type grantPathHandleSet struct {
	handles []*grantPathHandle
}

func (set *grantPathHandleSet) add(handle *grantPathHandle) error {
	if handle == nil {
		return nil
	}
	if handle.file == nil || handle.target == "" || handle.identity == "" {
		_ = handle.Close()
		set.close()
		return ErrGrantTargetChanged
	}
	for _, existing := range set.handles {
		if existing.target != handle.target {
			continue
		}
		if existing.identity != handle.identity {
			_ = handle.Close()
			set.close()
			return ErrGrantTargetChanged
		}
		existing.access |= handle.access
		_ = handle.Close()
		return nil
	}
	set.handles = append(set.handles, handle)
	return nil
}

// sorted returns a borrowed canonical-target-ordered view. The set retains sole
// ownership and closes the handles when its caller's operation finishes.
func (set *grantPathHandleSet) sorted() []*grantPathHandle {
	slices.SortFunc(set.handles, func(left, right *grantPathHandle) int {
		return strings.Compare(left.target, right.target)
	})
	return set.handles
}

func (set *grantPathHandleSet) close() {
	closeGrantPathHandles(set.handles)
	set.handles = nil
}
