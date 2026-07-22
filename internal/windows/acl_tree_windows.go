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
	rootObject, err := reopenDirectoryACLObject(win.Handle(root.NativeHandle()), root.Target())
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

func reopenDirectoryACLObject(handle win.Handle, target string) (*win32ACLObject, error) {
	desired := uintptr(win.READ_CONTROL | win.WRITE_DAC | win.FILE_READ_ATTRIBUTES | win.FILE_LIST_DIRECTORY)
	reopened, _, callErr := procReOpenFile.Call(uintptr(handle), desired,
		win.FILE_SHARE_READ, win.FILE_FLAG_BACKUP_SEMANTICS|win.FILE_FLAG_OPEN_REPARSE_POINT)
	if reopened == uintptr(win.InvalidHandle) {
		return nil, fmt.Errorf("retain ACL directory handle: %w", callErr)
	}
	return &win32ACLObject{handle: win.Handle(reopened), target: target}, nil
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
	names, err := directoryNames(directory.handle)
	if err != nil {
		return fmt.Errorf("enumerate retained directory handle: %w", err)
	}
	for _, name := range names {
		child, identity, err := openRelativeACLChild(directory.handle, name)
		if err != nil {
			return err
		}
		childRelative := name
		if relative != "" {
			childRelative = relative + `\` + name
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

func directoryNames(handle win.Handle) ([]string, error) {
	buffer := make([]byte, 64*1024)
	class := uint32(win.FileIdBothDirectoryRestartInfo)
	var names []string
	for {
		err := win.GetFileInformationByHandleEx(handle, class, &buffer[0], uint32(len(buffer)))
		class = win.FileIdBothDirectoryInfo
		if errors.Is(err, win.ERROR_NO_MORE_FILES) {
			break
		}
		if err != nil {
			return nil, err
		}
		batch, err := parseFileIDBothDirectoryInfo(buffer)
		if err != nil {
			return nil, err
		}
		names = append(names, batch...)
	}
	slices.SortFunc(names, winpath.Compare)
	for index := 1; index < len(names); index++ {
		if winpath.EqualPath(names[index-1], names[index]) {
			return nil, errors.New("sandbox: duplicate directory entry name")
		}
	}
	return names, nil
}

func parseFileIDBothDirectoryInfo(buffer []byte) ([]string, error) {
	var names []string
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
		if nameBytes == 0 || nameBytes&1 != 0 || nameBytes > recordSize-fileIDBothDirectoryInfoHeaderSize {
			return nil, errors.New("sandbox: malformed directory entry name")
		}
		units := unsafe.Slice((*uint16)(unsafe.Pointer(&record[fileIDBothDirectoryInfoHeaderSize])), nameBytes/2)
		name := win.UTF16ToString(units)
		if name != "." && name != ".." {
			if name == "" || strings.ContainsAny(name, `\/`) || strings.IndexByte(name, 0) >= 0 {
				return nil, errors.New("sandbox: unsafe directory entry name")
			}
			names = append(names, name)
		}
		if next == 0 {
			return names, nil
		}
		offset += next
	}
}

func openRelativeACLChild(parent win.Handle, name string) (*win32ACLObject, ACLObjectIdentity, error) {
	objectName, err := win.NewNTUnicodeString(name)
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
	err = win.NtCreateFile(&candidate, win.FILE_READ_ATTRIBUTES, &attributes, &status, nil, 0,
		win.FILE_SHARE_READ, win.FILE_OPEN, win.FILE_OPEN_REPARSE_POINT, 0, 0)
	if err != nil {
		return nil, ACLObjectIdentity{}, fmt.Errorf("open retained relative ACL child: %w", err)
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
	if identity.Kind == ACLObjectReparsePoint {
		return &win32ACLObject{handle: candidate, target: target}, identity, nil
	}
	desired := uint32(win.READ_CONTROL | win.WRITE_DAC | win.FILE_READ_ATTRIBUTES)
	if identity.Kind == ACLObjectDirectory {
		desired |= win.FILE_LIST_DIRECTORY
	}
	reopened, _, callErr := procReOpenFile.Call(uintptr(candidate), uintptr(desired),
		win.FILE_SHARE_READ, win.FILE_FLAG_BACKUP_SEMANTICS|win.FILE_FLAG_OPEN_REPARSE_POINT)
	_ = win.CloseHandle(candidate)
	if reopened == uintptr(win.InvalidHandle) {
		return nil, ACLObjectIdentity{}, fmt.Errorf("retain relative ACL child: %w", callErr)
	}
	object := &win32ACLObject{handle: win.Handle(reopened), target: target}
	retained, err := object.snapshot()
	if err != nil || retained.identity != identity {
		_ = object.close()
		return nil, ACLObjectIdentity{}, errors.Join(fmt.Errorf("%w: relative ACL child changed while retaining", policy.ErrTargetChanged), err)
	}
	return object, identity, nil
}
