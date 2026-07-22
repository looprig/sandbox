//go:build windows

// Package winpath provides fail-closed, handle-derived Windows path identity.
package winpath

import (
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var ErrUnsupportedPath = errors.New("sandbox: unsupported Windows path")

type Kind uint8

const (
	KindUnknown Kind = iota
	KindFile
	KindDirectory
	KindReparsePoint
)

// Object owns a no-follow Windows handle and the identity obtained from it.
type Object struct {
	Handle       windows.Handle
	DOSPath      string
	PathKey      string
	VolumeSerial uint64
	FileID       [16]byte
	Kind         Kind
	ReparseTag   uint32
	LinkCount    uint32

	closeOnce sync.Once
	closeErr  error
	ancestors []windows.Handle
}

type fileIDInfo struct {
	VolumeSerialNumber uint64
	FileID             [16]byte
}

type fileAttributeTagInfo struct {
	FileAttributes uint32
	ReparseTag     uint32
}

type fileStandardInfo struct {
	AllocationSize int64
	EndOfFile      int64
	NumberOfLinks  uint32
	DeletePending  byte
	Directory      byte
	_              [2]byte
}

var compareStringOrdinal = windows.NewLazySystemDLL("kernel32.dll").NewProc("CompareStringOrdinal")

// Normalize validates a path spelling without widening it and returns an
// absolute DOS-drive spelling suitable for CreateFileW.
func Normalize(path string) (string, error) {
	if path == "" || strings.IndexByte(path, 0) >= 0 {
		return "", ErrUnsupportedPath
	}
	path = strings.ReplaceAll(path, "/", `\`)
	if hasFoldPrefix(path, `\\?\`) {
		path = path[4:]
	}
	if len(path) < 3 || path[1] != ':' || path[2] != '\\' || !asciiLetter(path[0]) {
		return "", ErrUnsupportedPath
	}
	if strings.IndexByte(path[2:], ':') >= 0 {
		return "", ErrUnsupportedPath
	}
	for _, component := range strings.Split(path[3:], `\`) {
		if component == "" {
			continue
		}
		if component == "." || component == ".." || strings.HasSuffix(component, " ") ||
			strings.HasSuffix(component, ".") || reservedDOSName(component) {
			return "", ErrUnsupportedPath
		}
	}
	path = filepath.Clean(path)
	if len(path) < 3 || path[1:3] != `:\` {
		return "", ErrUnsupportedPath
	}
	return strings.ToUpper(path[:1]) + path[1:], nil
}

func asciiLetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func hasFoldPrefix(value, prefix string) bool {
	return len(value) >= len(prefix) && strings.EqualFold(value[:len(prefix)], prefix)
}

func reservedDOSName(component string) bool {
	name := strings.TrimRight(component, " .")
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	name = strings.ToUpper(name)
	if name == "CON" || name == "PRN" || name == "AUX" || name == "NUL" {
		return true
	}
	return len(name) == 4 && (strings.HasPrefix(name, "COM") || strings.HasPrefix(name, "LPT")) && name[3] >= '1' && name[3] <= '9'
}

// Compare orders path keys with CompareStringOrdinal's case-insensitive UTF-16
// semantics. It returns -1, 0, or 1.
func Compare(left, right string) int {
	left16, err := windows.UTF16FromString(left)
	if err != nil {
		return strings.Compare(left, right)
	}
	right16, err := windows.UTF16FromString(right)
	if err != nil {
		return strings.Compare(left, right)
	}
	result, _, _ := compareStringOrdinal.Call(
		uintptr(unsafe.Pointer(&left16[0])), uintptr(len(left16)-1),
		uintptr(unsafe.Pointer(&right16[0])), uintptr(len(right16)-1), 1,
	)
	switch result {
	case 1: // CSTR_LESS_THAN
		return -1
	case 2: // CSTR_EQUAL
		return 0
	case 3: // CSTR_GREATER_THAN
		return 1
	default:
		// CompareStringOrdinal is present on every supported Windows release.
		// Fail closed for equality if the syscall nevertheless fails.
		return strings.Compare(left, right)
	}
}

// EqualPath reports ordinal case-insensitive equality.
func EqualPath(left, right string) bool { return Compare(left, right) == 0 }

// HasPrefix reports whether value begins with prefix under ordinal
// case-insensitive UTF-16 comparison.
func HasPrefix(value, prefix string) bool {
	value16, err := windows.UTF16FromString(value)
	if err != nil {
		return false
	}
	prefix16, err := windows.UTF16FromString(prefix)
	if err != nil || len(value16) < len(prefix16) {
		return false
	}
	prefixUnits := len(prefix16) - 1
	if len(value16)-1 < prefixUnits {
		return false
	}
	result, _, _ := compareStringOrdinal.Call(
		uintptr(unsafe.Pointer(&value16[0])), uintptr(prefixUnits),
		uintptr(unsafe.Pointer(&prefix16[0])), uintptr(prefixUnits), 1,
	)
	return result == 2
}

type enumeratedVolume struct {
	identity string
	paths    []string
}

// VolumeRoots enumerates every supported fixed local NTFS/ReFS volume. A
// volume with no drive letter is represented by its ordinal-lowest DOS mount
// path; volume GUID paths never escape this package.
func VolumeRoots() ([]string, error) {
	volumes, err := enumerateVolumes()
	if err != nil {
		return nil, err
	}
	roots := selectVolumeMountRoots(volumes)
	if len(roots) == 0 {
		return nil, fmt.Errorf("%w: no supported local volumes", ErrUnsupportedPath)
	}
	return roots, nil
}

func enumerateVolumes() ([]enumeratedVolume, error) {
	buffer := make([]uint16, 1024)
	find, err := windows.FindFirstVolume(&buffer[0], uint32(len(buffer)))
	if err != nil {
		return nil, fmt.Errorf("enumerate volumes: %w", err)
	}
	defer windows.FindVolumeClose(find)

	var volumes []enumeratedVolume
	for {
		volumeName := windows.UTF16ToString(buffer)
		supported, inspectErr := supportedLocalVolume(volumeName)
		if inspectErr != nil {
			return nil, inspectErr
		}
		if supported {
			paths, pathErr := volumePathNames(volumeName)
			if pathErr != nil {
				return nil, pathErr
			}
			volumes = append(volumes, enumeratedVolume{identity: volumeName, paths: paths})
		}
		clear(buffer)
		if err := windows.FindNextVolume(find, &buffer[0], uint32(len(buffer))); err != nil {
			if errors.Is(err, windows.ERROR_NO_MORE_FILES) {
				break
			}
			return nil, fmt.Errorf("enumerate next volume: %w", err)
		}
	}
	return volumes, nil
}

func supportedLocalVolume(volumeName string) (bool, error) {
	name, err := windows.UTF16PtrFromString(volumeName)
	if err != nil {
		return false, fmt.Errorf("encode volume name: %w", err)
	}
	if windows.GetDriveType(name) != windows.DRIVE_FIXED {
		return false, nil
	}
	filesystem := make([]uint16, 32)
	if err := windows.GetVolumeInformation(name, nil, 0, nil, nil, nil, &filesystem[0], uint32(len(filesystem))); err != nil {
		return false, fmt.Errorf("inspect volume %q: %w", volumeName, err)
	}
	fs := windows.UTF16ToString(filesystem)
	return strings.EqualFold(fs, "NTFS") || strings.EqualFold(fs, "ReFS"), nil
}

func volumePathNames(volumeName string) ([]string, error) {
	name, err := windows.UTF16PtrFromString(volumeName)
	if err != nil {
		return nil, fmt.Errorf("encode volume name: %w", err)
	}
	buffer := make([]uint16, windows.MAX_PATH+1)
	for {
		var required uint32
		err = windows.GetVolumePathNamesForVolumeName(name, &buffer[0], uint32(len(buffer)), &required)
		if err == nil {
			return splitMultiSZ(buffer), nil
		}
		if !errors.Is(err, windows.ERROR_MORE_DATA) || required == 0 {
			return nil, fmt.Errorf("enumerate mount paths for %q: %w", volumeName, err)
		}
		buffer = make([]uint16, required)
	}
}

func splitMultiSZ(buffer []uint16) []string {
	var values []string
	for start := 0; start < len(buffer); {
		end := start
		for end < len(buffer) && buffer[end] != 0 {
			end++
		}
		if end == start {
			break
		}
		values = append(values, windows.UTF16ToString(buffer[start:end]))
		start = end + 1
	}
	return values
}

func selectVolumeMountRoots(volumes []enumeratedVolume) []string {
	type selectedVolume struct {
		identity string
		paths    []string
	}
	var selected []selectedVolume
	for _, volume := range volumes {
		index := slices.IndexFunc(selected, func(existing selectedVolume) bool {
			return strings.EqualFold(existing.identity, volume.identity)
		})
		if index < 0 {
			selected = append(selected, selectedVolume{identity: volume.identity})
			index = len(selected) - 1
		}
		for _, candidate := range volume.paths {
			path, err := Normalize(candidate)
			if err != nil {
				continue
			}
			if slices.ContainsFunc(selected[index].paths, func(existing string) bool { return EqualPath(existing, path) }) {
				continue
			}
			selected[index].paths = append(selected[index].paths, path)
		}
	}

	var roots []string
	for _, volume := range selected {
		if len(volume.paths) == 0 {
			continue
		}
		slices.SortFunc(volume.paths, func(left, right string) int {
			leftDrive := len(left) == 3 && left[1:] == `:\`
			rightDrive := len(right) == 3 && right[1:] == `:\`
			if leftDrive != rightDrive {
				if leftDrive {
					return -1
				}
				return 1
			}
			return Compare(left, right)
		})
		roots = append(roots, volume.paths[0])
	}
	slices.SortFunc(roots, Compare)
	return roots
}

// Open validates path, rejects reparse-point ancestors, and captures complete
// stable identity from an owned no-follow handle.
func Open(path string) (*Object, error) {
	return open(path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
}

// OpenPinned is Open with delete-sharing denied. This prevents ordinary Win32
// delete opens while the returned object is held, but it is only defense in
// depth: filesystems that support POSIX-style rename can still move a named
// object without honoring this sharing exclusion. Callers that rely on a path
// continuing to name this object must re-open and compare the complete identity
// before use. The retained handle itself continues to identify the original
// object even when its name moves.
func OpenPinned(path string) (*Object, error) {
	return open(path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
}

func open(path string, shareMode uint32) (*Object, error) {
	normalized, err := Normalize(path)
	if err != nil {
		return nil, err
	}
	handles, err := walkPathComponents(normalized, shareMode, openRawShared, openRelativeComponent, handleIsReparse, windows.CloseHandle)
	if err != nil {
		return nil, err
	}
	object := &Object{Handle: handles[len(handles)-1], ancestors: handles[:len(handles)-1]}
	if err := object.loadIdentity(); err != nil {
		_ = object.Close()
		return nil, err
	}
	return object, nil
}

func openRawShared(path string, shareMode uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(`\\?\` + path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.FILE_TRAVERSE, shareMode,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

type rootComponentOpener func(string, uint32) (windows.Handle, error)
type relativeComponentOpener func(windows.Handle, string, bool, uint32) (windows.Handle, error)
type reparseInspector func(windows.Handle) (bool, error)
type handleCloser func(windows.Handle) error

func walkPathComponents(path string, shareMode uint32, openRoot rootComponentOpener, openRelative relativeComponentOpener, isReparse reparseInspector, closeHandle handleCloser) ([]windows.Handle, error) {
	root := path[:3]
	rootHandle, err := openRoot(root, shareMode)
	if err != nil {
		return nil, fmt.Errorf("open volume root: %w", err)
	}
	handles := []windows.Handle{rootHandle}
	closeAll := func() {
		for i := len(handles) - 1; i >= 0; i-- {
			_ = closeHandle(handles[i])
		}
	}
	checkReparse := func(handle windows.Handle) error {
		reparse, inspectErr := isReparse(handle)
		if inspectErr != nil {
			return inspectErr
		}
		if reparse {
			return fmt.Errorf("%w: reparse-point component", ErrUnsupportedPath)
		}
		return nil
	}
	if err := checkReparse(rootHandle); err != nil {
		closeAll()
		return nil, err
	}
	components := strings.Split(strings.TrimPrefix(path[3:], `\`), `\`)
	for i, component := range components {
		if component == "" {
			continue
		}
		handle, openErr := openRelative(handles[len(handles)-1], component, i < len(components)-1, shareMode)
		if openErr != nil {
			closeAll()
			if errors.Is(openErr, windows.STATUS_REPARSE_POINT_ENCOUNTERED) || errors.Is(openErr, windows.STATUS_STOPPED_ON_SYMLINK) {
				return nil, fmt.Errorf("%w: relative component %q", ErrUnsupportedPath, component)
			}
			return nil, fmt.Errorf("open relative component %q: %w", component, openErr)
		}
		handles = append(handles, handle)
		if err := checkReparse(handle); err != nil {
			closeAll()
			return nil, err
		}
	}
	return handles, nil
}

func openRelativeComponent(parent windows.Handle, name string, directory bool, shareMode uint32) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	attributes.Length = uint32(unsafe.Sizeof(attributes))
	options := uint32(windows.FILE_OPEN_REPARSE_POINT)
	access := uint32(windows.FILE_READ_ATTRIBUTES)
	if directory {
		options |= windows.FILE_DIRECTORY_FILE
		access |= windows.FILE_TRAVERSE
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&handle, access, &attributes, &status, nil, 0, shareMode,
		windows.FILE_OPEN, options, 0, 0)
	return handle, err
}

func handleIsReparse(handle windows.Handle) (bool, error) {
	var tag fileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return false, fmt.Errorf("inspect path component: %w", err)
	}
	return tag.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0, nil
}

func (object *Object) loadIdentity() error {
	fileType, err := windows.GetFileType(object.Handle)
	if err != nil || fileType != windows.FILE_TYPE_DISK {
		return fmt.Errorf("%w: object is not a disk file", ErrUnsupportedPath)
	}

	var id fileIDInfo
	if err := windows.GetFileInformationByHandleEx(object.Handle, windows.FileIdInfo, (*byte)(unsafe.Pointer(&id)), uint32(unsafe.Sizeof(id))); err != nil {
		return fmt.Errorf("read file ID: %w", err)
	}
	var tag fileAttributeTagInfo
	if err := windows.GetFileInformationByHandleEx(object.Handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag))); err != nil {
		return fmt.Errorf("read reparse tag: %w", err)
	}
	var standard fileStandardInfo
	if err := windows.GetFileInformationByHandleEx(object.Handle, windows.FileStandardInfo, (*byte)(unsafe.Pointer(&standard)), uint32(unsafe.Sizeof(standard))); err != nil {
		return fmt.Errorf("read standard info: %w", err)
	}

	dosPath, err := finalDOSPath(object.Handle)
	if err != nil {
		return err
	}
	dosPath, err = Normalize(dosPath)
	if err != nil {
		return fmt.Errorf("%w: final path namespace", ErrUnsupportedPath)
	}
	if err := validateLocalVolume(object.Handle, dosPath); err != nil {
		return err
	}

	object.DOSPath = dosPath
	object.PathKey = dosPath
	object.VolumeSerial = id.VolumeSerialNumber
	object.FileID = id.FileID
	object.ReparseTag = tag.ReparseTag
	object.LinkCount = standard.NumberOfLinks
	switch {
	case tag.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		object.Kind = KindReparsePoint
	case standard.Directory != 0:
		object.Kind = KindDirectory
	default:
		object.Kind = KindFile
	}
	if object.VolumeSerial == 0 || object.FileID == ([16]byte{}) || object.LinkCount == 0 {
		return fmt.Errorf("%w: incomplete persistent identity", ErrUnsupportedPath)
	}
	return nil
}

func finalDOSPath(handle windows.Handle) (string, error) {
	size, err := windows.GetFinalPathNameByHandle(handle, nil, 0, 0)
	if err != nil && size == 0 {
		return "", fmt.Errorf("query final DOS path: %w", err)
	}
	buffer := make([]uint16, size+1)
	n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
	if err != nil {
		return "", fmt.Errorf("read final DOS path: %w", err)
	}
	if n >= uint32(len(buffer)) {
		return "", errors.New("final DOS path changed while reading")
	}
	return windows.UTF16ToString(buffer[:n]), nil
}

func validateLocalVolume(handle windows.Handle, path string) error {
	root, err := windows.UTF16PtrFromString(path[:3])
	if err != nil || windows.GetDriveType(root) != windows.DRIVE_FIXED {
		return fmt.Errorf("%w: volume is not fixed local storage", ErrUnsupportedPath)
	}
	filesystem := make([]uint16, 32)
	if err := windows.GetVolumeInformationByHandle(handle, nil, 0, nil, nil, nil, &filesystem[0], uint32(len(filesystem))); err != nil {
		return fmt.Errorf("read filesystem type: %w", err)
	}
	name := windows.UTF16ToString(filesystem)
	if !strings.EqualFold(name, "NTFS") && !strings.EqualFold(name, "ReFS") {
		return fmt.Errorf("%w: filesystem %q", ErrUnsupportedPath, name)
	}
	return nil
}

// SameIdentity compares every security-relevant identity field.
func (object *Object) SameIdentity(other *Object) bool {
	return object != nil && other != nil && EqualPath(object.PathKey, other.PathKey) &&
		object.VolumeSerial == other.VolumeSerial && object.FileID == other.FileID &&
		object.Kind == other.Kind && object.ReparseTag == other.ReparseTag && object.LinkCount == other.LinkCount
}

// Close releases the owned handle. It is safe to call repeatedly.
func (object *Object) Close() error {
	if object == nil {
		return nil
	}
	object.closeOnce.Do(func() {
		if object.Handle != 0 && object.Handle != windows.InvalidHandle {
			object.closeErr = windows.CloseHandle(object.Handle)
			object.Handle = windows.InvalidHandle
		}
		for i := len(object.ancestors) - 1; i >= 0; i-- {
			object.closeErr = errors.Join(object.closeErr, windows.CloseHandle(object.ancestors[i]))
		}
		object.ancestors = nil
	})
	return object.closeErr
}
