//go:build windows

package windows

import (
	"errors"
	"fmt"
	"unsafe"

	"github.com/looprig/sandbox/internal/policy"
	win "golang.org/x/sys/windows"
)

// errACLObjectGone reports that a journaled object no longer exists anywhere
// on its volume: its file ID resolves to nothing. An ACE lives in its
// object's security descriptor, so a deleted object took the lease's ACE
// with it and the mutation is already rolled back.
var errACLObjectGone = errors.New("sandbox: ACL object no longer exists")

// aclByIDAccess is what reopening an object for a DACL edit needs: the DACL
// and owner read (READ_CONTROL), the DACL write (WRITE_DAC) and the identity
// read (FILE_READ_ATTRIBUTES). None of these is subject to share-mode checks,
// and the open itself grants every sharing mode, so a by-ID open never blocks
// (or is blocked by) another process reading, writing, renaming or deleting
// the file.
const aclByIDAccess = win.READ_CONTROL | win.WRITE_DAC | win.FILE_READ_ATTRIBUTES

// openFileByIDWithAccess is OpenFileById with every sharing mode granted,
// backup semantics (directories open too) and no reparse traversal.
func openFileByIDWithAccess(volume win.Handle, id [16]byte, access uint32) (win.Handle, error) {
	descriptor := fileIDDescriptor{Size: uint32(unsafe.Sizeof(fileIDDescriptor{})), Type: extendedFileIDType, ID: id}
	handle, _, callErr := procOpenFileByID.Call(uintptr(volume), uintptr(unsafe.Pointer(&descriptor)),
		uintptr(access), win.FILE_SHARE_READ|win.FILE_SHARE_WRITE|win.FILE_SHARE_DELETE, 0,
		win.FILE_FLAG_BACKUP_SEMANTICS|win.FILE_FLAG_OPEN_REPARSE_POINT)
	if win.Handle(handle) == win.InvalidHandle {
		return win.InvalidHandle, syscallErr(callErr)
	}
	return win.Handle(handle), nil
}

// openVolumeRootForSerial opens the root of path's drive and proves it is the
// journaled volume: the serial must match, and opening the root by its own
// file ID must succeed, so a malformed descriptor or a filesystem without
// stable file IDs can never be mistaken for "object deleted".
func openVolumeRootForSerial(path string, serial uint64) (win.Handle, error) {
	if len(path) < 3 || path[1] != ':' || path[2] != '\\' {
		return win.InvalidHandle, errors.New("windows sandbox: ACL object path has no drive root")
	}
	rootPath, err := win.UTF16PtrFromString(path[:3])
	if err != nil {
		return win.InvalidHandle, err
	}
	root, err := win.CreateFile(rootPath, win.FILE_READ_ATTRIBUTES,
		win.FILE_SHARE_READ|win.FILE_SHARE_WRITE|win.FILE_SHARE_DELETE, nil, win.OPEN_EXISTING,
		win.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return win.InvalidHandle, fmt.Errorf("open volume root: %w", err)
	}
	var rootID fileIDInfo
	if err := win.GetFileInformationByHandleEx(root, win.FileIdInfo, (*byte)(unsafe.Pointer(&rootID)), uint32(unsafe.Sizeof(rootID))); err != nil {
		_ = win.CloseHandle(root)
		return win.InvalidHandle, fmt.Errorf("identify volume root: %w", err)
	}
	if rootID.VolumeSerialNumber != serial {
		_ = win.CloseHandle(root)
		return win.InvalidHandle, errors.New("windows sandbox: the object's volume is no longer mounted at its drive letter")
	}
	control, err := openFileByIDWithAccess(root, rootID.FileID, win.FILE_READ_ATTRIBUTES)
	if err != nil {
		_ = win.CloseHandle(root)
		return win.InvalidHandle, fmt.Errorf("open volume root by file ID: %w", err)
	}
	_ = win.CloseHandle(control)
	return root, nil
}

// fileIDAbsent recognizes OpenFileById's answer for a file reference no
// object uses any more: NTFS reports ERROR_INVALID_PARAMETER, ReFS may report
// ERROR_FILE_NOT_FOUND. It is only meaningful after openVolumeRootForSerial's
// control open succeeded.
func fileIDAbsent(err error) bool {
	return errors.Is(err, win.ERROR_INVALID_PARAMETER) || errors.Is(err, win.ERROR_FILE_NOT_FOUND)
}

// openSharedWin32ACLObject opens the exact object a policy handle names for a
// DACL edit, by file ID and with every sharing mode granted (review M16). It
// replaces the path re-open (OpenForACL, which never grants delete sharing)
// for allow-only exact projections: the restricted tier closes this handle as
// soon as the lease's ACE is applied and read back, so neither the user nor
// the sandbox is blocked from renaming or deleting the file while the lease
// lives. The policy handle is only the volume hint; the identity, final path
// included, must match it exactly before the handle is used.
func openSharedWin32ACLObject(handle *policy.PathHandle) (*win32ACLObject, error) {
	if handle == nil || handle.NativeHandle() == 0 {
		return nil, errors.New("sandbox: ACL projection requires an open retained handle")
	}
	source := win.Handle(handle.NativeHandle())
	expected, err := identityFromHandle(source, handle.Target())
	if err != nil {
		return nil, fmt.Errorf("inspect ACL source %q: %w", handle.Target(), err)
	}
	opened, err := openFileByIDWithAccess(source, expected.FileID, aclByIDAccess)
	if err != nil {
		return nil, fmt.Errorf("open ACL target %q by file ID: %w", handle.Target(), err)
	}
	object := &win32ACLObject{handle: opened, target: handle.Target()}
	actual, err := object.snapshot()
	if err != nil || actual.identity != expected {
		_ = object.close()
		return nil, errors.Join(fmt.Errorf("%w: ACL target %q changed while acquiring authority", policy.ErrTargetChanged, handle.Target()), err)
	}
	return object, nil
}

// reopenableACLObject is an applied exact-projection object whose handle has
// been closed (review M16). It holds no handle between operations: every
// snapshot and DACL write reopens the object by volume serial + file ID, so
// rollback finds the object wherever it now lives, and the lease's ACE is
// removed even from a file that was renamed or moved within its volume.
//
// What it cannot reach is a copy: a file moved to another volume is a new
// object, and the copy may carry the lease's allow ACE. That ACE names the
// lease's one-shot SID, which is retired when generated and never reissued,
// so no future token can match it; it is inert, never re-activated.
type reopenableACLObject struct {
	identity ACLObjectIdentity
	target   string
}

func (object *reopenableACLObject) open() (*win32ACLObject, error) {
	root, err := openVolumeRootForSerial(object.target, object.identity.VolumeSerial)
	if err != nil {
		return nil, err
	}
	defer win.CloseHandle(root)
	handle, err := openFileByIDWithAccess(root, object.identity.FileID, aclByIDAccess)
	if err != nil {
		if fileIDAbsent(err) {
			return nil, errACLObjectGone
		}
		return nil, fmt.Errorf("reopen ACL object %q by file ID: %w", object.target, err)
	}
	current, err := finalPathFromHandle(handle)
	if err != nil {
		_ = win.CloseHandle(handle)
		return nil, err
	}
	return &win32ACLObject{handle: handle, target: current}, nil
}

func (object *reopenableACLObject) snapshot() (aclObjectSnapshot, error) {
	opened, err := object.open()
	if err != nil {
		return aclObjectSnapshot{}, err
	}
	defer opened.close()
	return opened.snapshot()
}

func (object *reopenableACLObject) setDACL(aces [][]byte) error {
	opened, err := object.open()
	if err != nil {
		return err
	}
	defer opened.close()
	current, err := opened.snapshot()
	if err != nil {
		return err
	}
	if identityKey(current.identity) != identityKey(object.identity) {
		return fmt.Errorf("%w: reopened ACL object is not the journaled one", policy.ErrTargetChanged)
	}
	return opened.setDACL(aces)
}

func (*reopenableACLObject) close() error { return nil }

// rollbackIdentityMatches is Rollback's identity gate. A retained handle must
// still name exactly the identity recorded at apply (path, link count and
// all). A reopenable object was found by file ID, so it may have been renamed,
// moved or hard-linked since, and only its volume, file ID and kind must
// match: removing the lease's own allow ACE from that same object is correct
// wherever it now lives.
func rollbackIdentityMatches(object aclProjectionObject, current, recorded ACLObjectIdentity) bool {
	if _, relocatable := object.(*reopenableACLObject); relocatable {
		return identityKey(current) == identityKey(recorded)
	}
	return current == recorded
}
