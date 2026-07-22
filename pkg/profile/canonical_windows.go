//go:build windows

package profile

import (
	"errors"
	"strings"

	"github.com/looprig/sandbox/internal/winpath"
)

// CanonicalRoot derives an existing local directory's DOS path from an owned
// no-follow handle. Reparse-point roots and unsupported volumes fail closed.
func CanonicalRoot(path string) (string, error) {
	object, err := winpath.Open(path)
	if err != nil {
		return "", err
	}
	defer object.Close()
	if object.Kind != winpath.KindDirectory || object.ReparseTag != 0 {
		return "", errors.New("path is not an ordinary directory")
	}
	return object.DOSPath, nil
}

func canonicalPathEqual(left, right string) bool { return winpath.EqualPath(left, right) }
func canonicalPathLess(left, right string) bool {
	return strings.ToUpper(left) < strings.ToUpper(right)
}
func canonicalPathWithin(path, root string) bool {
	if winpath.EqualPath(path, root) {
		return true
	}
	prefix := strings.TrimSuffix(root, `\`) + `\`
	return len(path) > len(prefix) && winpath.EqualPath(path[:len(prefix)], prefix)
}
