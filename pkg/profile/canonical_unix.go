//go:build !windows

package profile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/looprig/sandbox/internal/diskname"
)

// CanonicalRoot resolves path to an absolute, symlink-free, existing
// directory. It is the canonicalization every configured root is held to. On
// macOS the result also carries the on-disk spelling of every component, the
// same spelling policy.CanonicalPath gives a grant target, so a case or
// normalization variant cannot step around a configured root.
func CanonicalRoot(path string) (string, error) {
	if path == "" {
		return "", errors.New("path is empty")
	}
	if !filepath.IsAbs(path) {
		return "", errors.New("path is not absolute")
	}
	resolved, err := filepath.EvalSymlinks(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fmt.Errorf("stat: %w", err)
	}
	if !info.IsDir() {
		return "", errors.New("path is not a directory")
	}
	stored, err := diskname.Respell(filepath.Clean(resolved))
	if err != nil {
		return "", fmt.Errorf("resolve stored spelling: %w", err)
	}
	return stored, nil
}

func canonicalPathEqual(left, right string) bool { return left == right }
func canonicalPathLess(left, right string) bool  { return left < right }
func canonicalPathWithin(path, root string) bool {
	if root == string(filepath.Separator) {
		return true
	}
	return path == root || strings.HasPrefix(path, root+string(filepath.Separator))
}
