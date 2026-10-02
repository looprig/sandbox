//go:build darwin

package diskname

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Respell returns the on-disk spelling of path, which must be absolute,
// clean, symlink-free and name an existing object.
//
// A directory is re-spelled with F_GETPATH on a descriptor for it: that is the
// kernel's own vnode path, the one Seatbelt evaluates, so it folds case,
// Unicode normalization and firmlinks (/System/Volumes/Data/Users is /Users)
// exactly as enforcement does. A non-directory, or a directory that cannot be
// opened, is re-spelled as its re-spelled parent joined with the entry name
// found in that parent. Non-directories never use F_GETPATH because a hard
// link would let it answer with a different directory entry. Failing to
// determine the stored spelling is an error, never a fallback to the caller's
// bytes, because the caller's bytes are exactly what can miss a Deny root.
func Respell(path string) (string, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("respell %q: path is not absolute and clean", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		if stored, err := vnodePath(path); err == nil {
			return stored, nil
		}
	}
	parent := filepath.Dir(path)
	if parent == path {
		return path, nil
	}
	storedParent, err := Respell(parent)
	if err != nil {
		return "", err
	}
	name, err := entryName(storedParent, filepath.Base(path), info)
	if err != nil {
		return "", err
	}
	return filepath.Join(storedParent, name), nil
}

// vnodePath opens path without following a final symlink and without blocking
// on a FIFO, and returns the kernel's path for the opened vnode.
func vnodePath(path string) (string, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer unix.Close(fd)
	buf := make([]byte, unix.PathMax)
	// FcntlInt is the libSystem wrapper (direct SYS_FCNTL is deprecated on
	// darwin); F_GETPATH takes a buffer pointer in the int argument, so the
	// buffer is pinned for the call rather than relying on it merely being
	// referenced afterwards.
	var pinner runtime.Pinner
	pinner.Pin(&buf[0])
	defer pinner.Unpin()
	// #nosec G103 -- F_GETPATH takes the output buffer through fcntl's int
	// argument; the buffer is pinned above for the duration of the call and the
	// pointer is never converted back, so no Go object can move or be collected
	// underneath the kernel write.
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETPATH, int(uintptr(unsafe.Pointer(&buf[0])))); err != nil {
		return "", err
	}
	end := bytes.IndexByte(buf, 0)
	if end <= 0 {
		return "", errors.New("F_GETPATH returned an empty path")
	}
	stored := string(buf[:end])
	if !filepath.IsAbs(stored) || filepath.Clean(stored) != stored {
		return "", fmt.Errorf("F_GETPATH returned a non-canonical path %q", stored)
	}
	return stored, nil
}

// entryName finds the stored name, in dir, of the object name resolves to.
// An exact byte match is the stored name. Otherwise the candidates are the
// entries naming the same file, preferring case-insensitive spellings of name
// (normalization variants only match by identity); more than one is ambiguous.
func entryName(dir, name string, target os.FileInfo) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("respell %q: %w", filepath.Join(dir, name), err)
	}
	same := func(entry string) bool {
		info, err := os.Lstat(filepath.Join(dir, entry))
		return err == nil && os.SameFile(info, target)
	}
	var folded, identical []string
	for _, entry := range entries {
		switch {
		case entry.Name() == name:
			if same(name) {
				return name, nil
			}
		case strings.EqualFold(entry.Name(), name):
			if same(entry.Name()) {
				folded = append(folded, entry.Name())
			}
		}
	}
	if len(folded) == 1 {
		return folded[0], nil
	}
	if len(folded) == 0 {
		for _, entry := range entries {
			if entry.Name() != name && same(entry.Name()) {
				identical = append(identical, entry.Name())
			}
		}
		if len(identical) == 1 {
			return identical[0], nil
		}
	}
	return "", fmt.Errorf("respell %q: no unique stored entry in %q", name, dir)
}
