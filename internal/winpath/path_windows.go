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

// VolumeRoots enumerates every supported fixed local NTFS/ReFS drive root.
func VolumeRoots() ([]string, error) {
	candidates, err := logicalDriveRoots()
	if err != nil {
		return nil, err
	}
	var inspectErr error
	roots := filterVolumeRoots(candidates, func(root string) bool {
		object, err := Open(root)
		if err != nil {
			if errors.Is(err, ErrUnsupportedPath) {
				return false
			}
			inspectErr = err
			return false
		}
		defer object.Close()
		return object.Kind == KindDirectory && object.ReparseTag == 0
	})
	if inspectErr != nil {
		return nil, inspectErr
	}
	if len(roots) == 0 {
		return nil, fmt.Errorf("%w: no supported local volumes", ErrUnsupportedPath)
	}
	return roots, nil
}

func logicalDriveRoots() ([]string, error) {
	size, err := windows.GetLogicalDriveStrings(0, nil)
	if err != nil || size == 0 {
		return nil, fmt.Errorf("enumerate logical drives: %w", err)
	}
	buffer := make([]uint16, size+1)
	n, err := windows.GetLogicalDriveStrings(uint32(len(buffer)), &buffer[0])
	if err != nil {
		return nil, fmt.Errorf("read logical drives: %w", err)
	}
	var roots []string
	start := 0
	for i := 0; i < int(n); i++ {
		if buffer[i] != 0 {
			continue
		}
		if i > start {
			roots = append(roots, windows.UTF16ToString(buffer[start:i]))
		}
		start = i + 1
	}
	return roots, nil
}

func filterVolumeRoots(candidates []string, supported func(string) bool) []string {
	var roots []string
	for _, candidate := range candidates {
		root, err := Normalize(candidate)
		if err != nil || len(root) != 3 || root[1:] != `:\` || !supported(root) {
			continue
		}
		duplicate := false
		for _, existing := range roots {
			if EqualPath(existing, root) {
				duplicate = true
				break
			}
		}
		if !duplicate {
			roots = append(roots, root)
		}
	}
	slices.SortFunc(roots, Compare)
	return roots
}

// Open validates path, rejects reparse-point ancestors, and captures complete
// stable identity from an owned no-follow handle.
func Open(path string) (*Object, error) {
	return open(path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
}

// OpenPinned is Open with delete-sharing denied. Holding the returned object
// prevents replacement of the named leaf until Close.
func OpenPinned(path string) (*Object, error) {
	return open(path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE)
}

func open(path string, shareMode uint32) (*Object, error) {
	normalized, err := Normalize(path)
	if err != nil {
		return nil, err
	}
	if err := rejectReparseAncestors(normalized); err != nil {
		return nil, err
	}
	handle, err := openRawShared(normalized, shareMode)
	if err != nil {
		return nil, fmt.Errorf("open Windows path: %w", err)
	}
	object := &Object{Handle: handle}
	if err := object.loadIdentity(); err != nil {
		_ = object.Close()
		return nil, err
	}
	return object, nil
}

func openRaw(path string) (windows.Handle, error) {
	return openRawShared(path, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE)
}

func openRawShared(path string, shareMode uint32) (windows.Handle, error) {
	name, err := windows.UTF16PtrFromString(`\\?\` + path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, shareMode,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
}

func rejectReparseAncestors(path string) error {
	components := strings.Split(strings.TrimPrefix(path[3:], `\`), `\`)
	current := path[:3]
	for i := 0; i < len(components)-1; i++ {
		if components[i] == "" {
			continue
		}
		current = filepath.Join(current, components[i])
		handle, err := openRaw(current)
		if err != nil {
			return fmt.Errorf("open ancestor: %w", err)
		}
		var tag fileAttributeTagInfo
		err = windows.GetFileInformationByHandleEx(handle, windows.FileAttributeTagInfo, (*byte)(unsafe.Pointer(&tag)), uint32(unsafe.Sizeof(tag)))
		_ = windows.CloseHandle(handle)
		if err != nil {
			return fmt.Errorf("inspect ancestor: %w", err)
		}
		if tag.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("%w: reparse-point ancestor", ErrUnsupportedPath)
		}
	}
	return nil
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
	})
	return object.closeErr
}
