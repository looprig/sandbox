//go:build windows

package policy

import (
	"fmt"

	"github.com/looprig/sandbox/internal/winpath"
)

func AcquirePathHandle(binding *PathBinding, target string, exact bool) (*PathHandle, error) {
	if binding == nil || !winpath.EqualPath(binding.CanonicalPath, target) ||
		!winpath.EqualPath(binding.ExistingPath, target) {
		return nil, ErrTargetChanged
	}
	object, err := winpath.Open(target)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTargetChanged, err)
	}
	identity := windowsObjectIdentity(object)
	if identity != binding.Identity || object.Kind == winpath.KindReparsePoint {
		_ = object.Close()
		return nil, ErrTargetChanged
	}
	if exact {
		if object.Kind != winpath.KindFile || object.LinkCount != 1 {
			_ = object.Close()
			return nil, ErrUnsupportedClass
		}
	} else if object.Kind != winpath.KindDirectory {
		_ = object.Close()
		return nil, ErrUnsupportedClass
	}
	return &PathHandle{
		target: object.DOSPath, exact: exact, isDir: object.Kind == winpath.KindDirectory,
		identity: identity, close: object.Close,
	}, nil
}

func samePathHandleTarget(left, right string) bool { return winpath.EqualPath(left, right) }
