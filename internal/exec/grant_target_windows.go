//go:build windows

package exec

import (
	"errors"
	"os"
	"path/filepath"
)

// validateGrantTargetAvailability closes the Windows exact-object semantic gap
// before canonicalization. Exact ACL grants require an existing object whose
// identity can be retained; tree grants and non-Windows exact grants have
// different creation semantics and are handled by their normal binders.
func validateGrantTargetAvailability(scope, class, target string) error {
	if class != GrantClassFilesystemPathRead && class != GrantClassFilesystemPathWrite {
		return nil
	}
	// Preserve malformed-input precedence for relative, unclean, or mismatched
	// scope/target requests; validateGrantClass diagnoses those below.
	if !filepath.IsAbs(target) || filepath.Clean(target) != target || scope != target {
		return nil
	}
	if _, err := os.Lstat(target); errors.Is(err, os.ErrNotExist) {
		return ErrGrantUnsupported
	}
	return nil
}
