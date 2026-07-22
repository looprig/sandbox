package policy

import (
	"os"
	"slices"
	"strings"
)

// PathHandle owns the identity-bound descriptor for one exact-file or
// tree-directory grant between authentication and child confinement setup.
type PathHandle struct {
	file   *os.File
	close  func() error
	target string
	exact  bool
	isDir  bool
	access FSAccess
	// identity is the device/inode/object-type tuple captured from the opened
	// descriptor. It is compared when multiple tokens name one canonical target.
	identity string
}

func (handle *PathHandle) Close() error {
	if handle == nil {
		return nil
	}
	if handle.close != nil {
		close := handle.close
		handle.close = nil
		return close()
	}
	if handle.file == nil {
		return nil
	}
	return handle.file.Close()
}

func closeGrantPathHandles(handles []*PathHandle) {
	for _, handle := range handles {
		_ = handle.Close()
	}
}

// PathHandleSet is the sole owner of every non-nil handle added to it.
// Equal canonical targets are safe to coalesce only when their opened object
// identities match. A mismatch closes the incoming handle and every handle the
// set already owns before returning ErrTargetChanged.
type PathHandleSet struct {
	handles []*PathHandle
}

// Add records a handle, merging access when two grants pin the same target and
// refusing the whole set when their identities disagree.
func (set *PathHandleSet) Add(handle *PathHandle) error {
	if handle == nil {
		return nil
	}
	if (handle.file == nil && handle.close == nil) || handle.target == "" || handle.identity == "" {
		_ = handle.Close()
		set.Close()
		return ErrTargetChanged
	}
	for _, existing := range set.handles {
		if !samePathHandleTarget(existing.target, handle.target) {
			continue
		}
		if existing.identity != handle.identity {
			_ = handle.Close()
			set.Close()
			return ErrTargetChanged
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
// Sorted returns the handles in a deterministic target order.
func (set *PathHandleSet) Sorted() []*PathHandle {
	slices.SortFunc(set.handles, func(left, right *PathHandle) int {
		return strings.Compare(left.target, right.target)
	})
	return set.handles
}

// Close releases every handle the set holds.
func (set *PathHandleSet) Close() {
	closeGrantPathHandles(set.handles)
	set.handles = nil
}

// Access reports the filesystem access the grant that pinned this handle asked
// for. It is read by the executor when it folds a verified grant into the
// compiled policy.
func (handle *PathHandle) Access() FSAccess {
	if handle == nil {
		return DenyAccess
	}
	return handle.access
}

// SetAccess records the filesystem access a verified grant asked for on this
// handle. The executor calls it once, immediately after acquiring the handle
// and before the handle joins a PathHandleSet.
func (handle *PathHandle) SetAccess(access FSAccess) {
	if handle == nil {
		return
	}
	handle.access = access
}

// File returns the pinned directory or file descriptor this handle holds open.
// The handle retains ownership; callers must not close the returned file.
func (handle *PathHandle) File() *os.File {
	if handle == nil {
		return nil
	}
	return handle.file
}

// IsDir reports whether the pinned target is a directory.
func (handle *PathHandle) IsDir() bool { return handle != nil && handle.isDir }

// Target reports the canonical path this handle is pinned to.
func (handle *PathHandle) Target() string {
	if handle == nil {
		return ""
	}
	return handle.target
}

// Exact reports whether the handle pins one file rather than a whole tree.
func (handle *PathHandle) Exact() bool { return handle != nil && handle.exact }

// SamePathHandleIdentity reports whether two independently opened handles pin
// the same canonical target and complete platform identity.
func SamePathHandleIdentity(left, right *PathHandle) bool {
	return left != nil && right != nil && samePathHandleTarget(left.target, right.target) &&
		left.identity == right.identity && left.exact == right.exact && left.isDir == right.isDir
}
