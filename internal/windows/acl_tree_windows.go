//go:build windows

package windows

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unsafe"

	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/internal/winpath"
	win "golang.org/x/sys/windows"
)

const fileIDBothDirectoryInfoHeaderSize = 104

type aclDirectoryEntry struct {
	name      string
	directory bool
	reparse   bool
}

// ACLTreeEntry is one deterministic, no-follow enumeration result. Reparse
// entries are represented for planning and audit, but never retained or
// traversed. RelativePath is descriptive only and is never used for mutation.
type ACLTreeEntry struct {
	Object       ACLObjectIdentity
	RelativePath string
}

// RetainedACLTree owns one ACL-capable handle for the root and each distinct
// ordinary descendant identity. Multiple names for one hard-linked file are
// represented by one entry and one retained handle.
type RetainedACLTree struct {
	root    ACLObjectIdentity
	entries []ACLTreeEntry
	objects map[aclIdentityKey]aclProjectionObject
}

// EnumerateRetainedACLTree walks an already pinned directory without following
// reparses. Directory listing and child opens are relative to retained handles;
// a journal path is never used to reacquire a live mutation target.
func EnumerateRetainedACLTree(root *policy.PathHandle) (*RetainedACLTree, error) {
	if root == nil || root.NativeHandle() == 0 || root.Exact() || !root.IsDir() {
		return nil, errors.New("sandbox: retained ACL tree requires an open directory handle")
	}
	rootObject, err := openBoundWin32ACLObject(win.Handle(root.NativeHandle()), root.Target(), true, true)
	if err != nil {
		return nil, err
	}
	rootSnapshot, err := rootObject.snapshot()
	if err != nil || rootSnapshot.identity.Kind != ACLObjectDirectory {
		_ = rootObject.close()
		return nil, errors.Join(fmt.Errorf("%w: invalid retained ACL tree root", policy.ErrTargetChanged), err)
	}
	tree := &RetainedACLTree{
		root: rootSnapshot.identity,
		objects: map[aclIdentityKey]aclProjectionObject{
			identityKey(rootSnapshot.identity): rootObject,
		},
	}
	if err := tree.walkDirectory(rootObject, ""); err != nil {
		_ = tree.Close()
		return nil, err
	}
	finalRoot, err := rootObject.snapshot()
	if err != nil || finalRoot.identity != tree.root {
		_ = tree.Close()
		return nil, errors.Join(fmt.Errorf("%w: ACL tree root changed during enumeration", policy.ErrTargetChanged), err)
	}
	slices.SortFunc(tree.entries, func(left, right ACLTreeEntry) int {
		return winpath.Compare(left.RelativePath, right.RelativePath)
	})
	return tree, nil
}

// Root returns the identity captured from the retained root handle.
func (tree *RetainedACLTree) Root() ACLObjectIdentity {
	if tree == nil {
		return ACLObjectIdentity{}
	}
	return tree.root
}

// Entries returns a defensive copy in ordinal case-insensitive path order.
func (tree *RetainedACLTree) Entries() []ACLTreeEntry {
	if tree == nil {
		return nil
	}
	return append([]ACLTreeEntry(nil), tree.entries...)
}

// Close releases every retained object unless ownership was transferred to an
// ACLProjection. It is safe to call repeatedly.
func (tree *RetainedACLTree) Close() error {
	if tree == nil {
		return nil
	}
	var result error
	for key, object := range tree.objects {
		result = errors.Join(result, object.close())
		delete(tree.objects, key)
	}
	return result
}

// NewACLTreeProjection consumes tree on success. The resulting projection owns
// every retained ordinary-object handle until Close.
func NewACLTreeProjection(plan ACLPlan, tree *RetainedACLTree, recorder ACLMutationRecorder) (*ACLProjection, error) {
	if tree == nil || len(tree.objects) == 0 || plan.RootIdentity() != tree.root {
		return nil, errors.New("sandbox: ACL plan does not match retained tree root")
	}
	projection, err := newACLProjection(plan, tree.objects, recorder)
	if err != nil {
		return nil, err
	}
	projection.relaxTreeSharing = true
	tree.objects = nil
	return projection, nil
}

// NewRestrictedACLTreeProjection consumes tree on success and attaches the
// cleanup-only write-ahead journal to every retained-handle mutation.
func NewRestrictedACLTreeProjection(plan ACLPlan, tree *RetainedACLTree, journal *RestrictedJournal) (*ACLProjection, error) {
	if journal == nil {
		return nil, errors.New("sandbox: restricted ACL projection requires a journal")
	}
	recorder := &restrictedACLRecorder{
		journal: journal,
		paths:   make(map[aclIdentityKey]string),
		keys:    make(map[string][]string),
	}
	projection, err := NewACLTreeProjection(plan, tree, recorder)
	if err != nil {
		return nil, err
	}
	for key, object := range projection.objects {
		win32Object, ok := object.(*win32ACLObject)
		if !ok {
			_ = projection.Close()
			return nil, errors.New("sandbox: restricted ACL tree requires Windows retained handles")
		}
		recorder.paths[key] = win32Object.target
	}
	return projection, nil
}

func (tree *RetainedACLTree) walkDirectory(directory *win32ACLObject, relative string) error {
	before, err := directory.snapshot()
	if err != nil || before.identity.Kind != ACLObjectDirectory {
		return errors.Join(fmt.Errorf("%w: enumerated directory changed", policy.ErrTargetChanged), err)
	}
	entries, err := directoryEntries(directory.handle)
	if err != nil {
		return fmt.Errorf("enumerate retained directory handle: %w", err)
	}
	for _, entry := range entries {
		child, identity, err := openRelativeACLChild(directory.handle, entry)
		if err != nil {
			return err
		}
		childRelative := entry.name
		if relative != "" {
			childRelative = relative + `\` + entry.name
		}
		entry := ACLTreeEntry{Object: identity, RelativePath: childRelative}
		if identity.Kind == ACLObjectReparsePoint {
			tree.entries = append(tree.entries, entry)
			_ = child.close()
			continue
		}
		key := identityKey(identity)
		if existing, duplicate := tree.objects[key]; duplicate {
			existingSnapshot, inspectErr := existing.snapshot()
			if inspectErr != nil || existingSnapshot.identity != identity || identity.Kind != ACLObjectFile || identity.LinkCount < 2 {
				_ = child.close()
				return errors.Join(fmt.Errorf("%w: duplicate ACL identity is not a stable hard link", policy.ErrTargetChanged), inspectErr)
			}
			_ = child.close()
			continue
		}
		tree.entries = append(tree.entries, entry)
		tree.objects[key] = child
		if identity.Kind == ACLObjectDirectory {
			if err := tree.walkDirectory(child, childRelative); err != nil {
				return err
			}
		}
	}
	after, err := directory.snapshot()
	if err != nil || after.identity != before.identity {
		return errors.Join(fmt.Errorf("%w: directory changed during retained enumeration", policy.ErrTargetChanged), err)
	}
	return nil
}

func directoryEntries(handle win.Handle) ([]aclDirectoryEntry, error) {
	buffer := make([]byte, 64*1024)
	class := uint32(win.FileIdBothDirectoryRestartInfo)
	var entries []aclDirectoryEntry
	for {
		err := win.GetFileInformationByHandleEx(handle, class, &buffer[0], uint32(len(buffer)))
		class = win.FileIdBothDirectoryInfo
		if errors.Is(err, win.ERROR_NO_MORE_FILES) {
			break
		}
		if err != nil {
			granted, inspectErr := handleGrantedAccess(handle)
			return nil, errors.Join(fmt.Errorf("directory query failed with granted access %#x: %w", granted, err), inspectErr)
		}
		batch, err := parseFileIDBothDirectoryInfo(buffer)
		if err != nil {
			return nil, err
		}
		entries = append(entries, batch...)
	}
	slices.SortFunc(entries, func(left, right aclDirectoryEntry) int { return winpath.Compare(left.name, right.name) })
	for index := 1; index < len(entries); index++ {
		if winpath.EqualPath(entries[index-1].name, entries[index].name) {
			return nil, errors.New("sandbox: duplicate directory entry name")
		}
	}
	return entries, nil
}

func parseFileIDBothDirectoryInfo(buffer []byte) ([]aclDirectoryEntry, error) {
	var entries []aclDirectoryEntry
	for offset := 0; ; {
		if offset < 0 || len(buffer)-offset < fileIDBothDirectoryInfoHeaderSize {
			return nil, errors.New("sandbox: malformed directory enumeration record")
		}
		record := buffer[offset:]
		next := int(binary.LittleEndian.Uint32(record[0:4]))
		recordSize := len(record)
		if next != 0 {
			if next < fileIDBothDirectoryInfoHeaderSize || next > len(record) || next&7 != 0 {
				return nil, errors.New("sandbox: malformed directory enumeration offset")
			}
			recordSize = next
		}
		nameBytes := int(binary.LittleEndian.Uint32(record[60:64]))
		fileAttributes := binary.LittleEndian.Uint32(record[56:60])
		if nameBytes == 0 || nameBytes&1 != 0 || nameBytes > recordSize-fileIDBothDirectoryInfoHeaderSize {
			return nil, errors.New("sandbox: malformed directory entry name")
		}
		units := unsafe.Slice((*uint16)(unsafe.Pointer(&record[fileIDBothDirectoryInfoHeaderSize])), nameBytes/2)
		name := win.UTF16ToString(units)
		if name != "." && name != ".." {
			if name == "" || strings.ContainsAny(name, `\/`) || strings.IndexByte(name, 0) >= 0 {
				return nil, errors.New("sandbox: unsafe directory entry name")
			}
			entries = append(entries, aclDirectoryEntry{
				name: name, directory: fileAttributes&win.FILE_ATTRIBUTE_DIRECTORY != 0,
				reparse: fileAttributes&win.FILE_ATTRIBUTE_REPARSE_POINT != 0,
			})
		}
		if next == 0 {
			return entries, nil
		}
		offset += next
	}
}

func openRelativeACLChild(parent win.Handle, entry aclDirectoryEntry) (*win32ACLObject, ACLObjectIdentity, error) {
	objectName, err := win.NewNTUnicodeString(entry.name)
	if err != nil {
		return nil, ACLObjectIdentity{}, err
	}
	attributes := win.OBJECT_ATTRIBUTES{
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    win.OBJ_CASE_INSENSITIVE | win.OBJ_DONT_REPARSE,
	}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	var candidate win.Handle
	var status win.IO_STATUS_BLOCK
	desired := uint32(win.READ_CONTROL | win.WRITE_DAC | win.FILE_READ_ATTRIBUTES)
	options := uint32(win.FILE_OPEN_REPARSE_POINT)
	if entry.directory && !entry.reparse {
		desired |= win.FILE_LIST_DIRECTORY
		options |= win.FILE_DIRECTORY_FILE
	}
	err = win.NtCreateFile(&candidate, desired, &attributes, &status, nil, 0,
		win.FILE_SHARE_READ, win.FILE_OPEN, options, 0, 0)
	if err != nil {
		return nil, ACLObjectIdentity{}, fmt.Errorf("open retained relative ACL child %q: %w", entry.name, err)
	}
	target, err := finalPathFromHandle(candidate)
	if err != nil {
		_ = win.CloseHandle(candidate)
		return nil, ACLObjectIdentity{}, err
	}
	identity, err := identityFromHandle(candidate, target)
	if err != nil {
		_ = win.CloseHandle(candidate)
		return nil, ACLObjectIdentity{}, err
	}
	if identity.Kind == ACLObjectDirectory != (entry.directory && !entry.reparse) ||
		(identity.Kind == ACLObjectReparsePoint) != entry.reparse {
		_ = win.CloseHandle(candidate)
		return nil, ACLObjectIdentity{}, fmt.Errorf("%w: relative ACL child %q changed type", policy.ErrTargetChanged, target)
	}
	object := &win32ACLObject{handle: candidate, target: target}
	retained, err := object.snapshot()
	if err != nil || retained.identity != identity {
		_ = object.close()
		return nil, ACLObjectIdentity{}, errors.Join(fmt.Errorf("%w: relative ACL child %q changed while retaining", policy.ErrTargetChanged, target), err)
	}
	return object, identity, nil
}
