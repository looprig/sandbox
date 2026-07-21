package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PathBinding pins a grant to a filesystem target by identity rather than by
// name. It records the canonical target, the deepest ancestor that existed when
// the grant was issued, and that ancestor's device/inode identity, so a symlink
// swap or a replaced directory between issue and spawn is detected and refused.

type PathBinding struct {
	CanonicalPath string
	ExistingPath  string
	Identity      string
}

func CanonicalPath(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", errors.New("path is not absolute")
	}
	clean := filepath.Clean(path)
	ancestor := clean
	var suffix []string
	for {
		resolved, err := filepath.EvalSymlinks(ancestor)
		if err == nil {
			for i := len(suffix) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, suffix[i])
			}
			return filepath.Clean(resolved), nil
		}
		parent := filepath.Dir(ancestor)
		if parent == ancestor {
			return "", err
		}
		suffix = append(suffix, filepath.Base(ancestor))
		ancestor = parent
	}
}

func CapturePathBinding(path string) (PathBinding, error) {
	canonical := filepath.Clean(path)
	existing := canonical
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		} else if !errors.Is(err, os.ErrNotExist) {
			return PathBinding{}, err
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			return PathBinding{}, os.ErrNotExist
		}
		existing = parent
	}
	if err := validateCanonicalPathNoFollow(existing); err != nil {
		return PathBinding{}, err
	}
	identity, err := FileIdentity(existing)
	if err != nil {
		return PathBinding{}, err
	}
	return PathBinding{CanonicalPath: canonical, ExistingPath: existing, Identity: identity}, nil
}

func RevalidatePathBinding(binding *PathBinding, target string) error {
	if binding == nil || binding.CanonicalPath != target || !filepath.IsAbs(binding.ExistingPath) {
		return ErrMalformed
	}
	if err := validateCanonicalPathNoFollow(binding.ExistingPath); err != nil {
		return fmt.Errorf("%w: %v", ErrTargetChanged, err)
	}
	identity, err := FileIdentity(binding.ExistingPath)
	if err != nil || identity != binding.Identity {
		return ErrTargetChanged
	}
	if binding.ExistingPath != binding.CanonicalPath {
		remainder, err := filepath.Rel(binding.ExistingPath, binding.CanonicalPath)
		if err != nil || remainder == "." || strings.HasPrefix(remainder, ".."+string(filepath.Separator)) {
			return ErrMalformed
		}
		candidate := binding.ExistingPath
		for _, component := range strings.Split(remainder, string(filepath.Separator)) {
			candidate = filepath.Join(candidate, component)
			if _, err := os.Lstat(candidate); err == nil || !errors.Is(err, os.ErrNotExist) {
				return ErrTargetChanged
			}
		}
	}
	return nil
}

func validateCanonicalPathNoFollow(path string) error {
	clean := filepath.Clean(path)
	current := string(filepath.Separator)
	for _, component := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if component == "" {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symlink component %q", current)
		}
	}
	return nil
}
