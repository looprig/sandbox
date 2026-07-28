//go:build windows

package policy

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/looprig/sandbox/internal/winpath"
	"golang.org/x/sys/windows"
)

func CanonicalPath(path string) (string, error) {
	clean, err := winpath.Normalize(path)
	if err != nil {
		return "", err
	}
	ancestor := clean
	var suffix []string
	for {
		object, openErr := winpath.Open(ancestor)
		if openErr == nil {
			defer object.Close()
			if object.Kind == winpath.KindReparsePoint {
				return "", ErrUnsupportedClass
			}
			resolved := object.DOSPath
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return winpath.Normalize(resolved)
		}
		if errors.Is(openErr, winpath.ErrReparsePoint) {
			return "", ErrUnsupportedClass
		}
		if !isWindowsPathNotFound(openErr) {
			return "", openErr
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", openErr
		}
		suffix = append(suffix, filepath.Base(ancestor))
		ancestor = parent
	}
}

func CapturePathBinding(path string) (PathBinding, error) {
	canonical, err := CanonicalPath(path)
	if err != nil {
		return PathBinding{}, err
	}
	object, err := winpath.Open(canonical)
	if err != nil {
		if isWindowsPathNotFound(err) {
			return PathBinding{}, ErrUnsupportedClass
		}
		return PathBinding{}, err
	}
	defer object.Close()
	if object.Kind == winpath.KindReparsePoint {
		return PathBinding{}, ErrUnsupportedClass
	}
	return PathBinding{
		CanonicalPath: object.DOSPath,
		ExistingPath:  object.DOSPath,
		Identity:      windowsObjectIdentity(object),
	}, nil
}

func isWindowsPathNotFound(err error) bool {
	return errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_PATH_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_OBJECT_NAME_NOT_FOUND) ||
		errors.Is(err, windows.STATUS_OBJECT_PATH_NOT_FOUND)
}

func RevalidatePathBinding(binding *PathBinding, target string) error {
	if binding == nil || binding.Identity == "" || binding.ExistingPath == "" ||
		!winpath.EqualPath(binding.CanonicalPath, target) ||
		!winpath.EqualPath(binding.CanonicalPath, binding.ExistingPath) {
		return ErrMalformed
	}
	object, err := winpath.Open(binding.ExistingPath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrTargetChanged, err)
	}
	defer object.Close()
	if object.Kind == winpath.KindReparsePoint || windowsObjectIdentity(object) != binding.Identity {
		return ErrTargetChanged
	}
	return nil
}
