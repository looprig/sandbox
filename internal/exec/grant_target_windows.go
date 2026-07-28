//go:build windows

package exec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// prepareGrantRequestForAuthorization performs only lexical Windows path
// normalization. In particular, it must not open the target or walk any of its
// ancestors: the caller has not authorized that resource access yet.
func prepareGrantRequestForAuthorization(scope, class, target string) (string, string, error) {
	if !strings.HasPrefix(class, "filesystem.") || strings.Contains(class, ".host.") {
		return scope, target, nil
	}
	cleanTarget := filepath.Clean(target)
	if strings.Contains(class, ".tree.") {
		if !strings.HasPrefix(scope, "tree:") {
			return scope, cleanTarget, nil
		}
		return "tree:" + filepath.Clean(strings.TrimPrefix(scope, "tree:")), cleanTarget, nil
	}
	return filepath.Clean(scope), cleanTarget, nil
}

// validateGrantTargetAvailability closes the Windows exact-object semantic gap
// after request validation and profile authorization. Exact ACL grants require
// an existing object whose identity can be retained; tree grants and
// non-Windows exact grants have different creation semantics and are handled by
// their normal binders.
func validateGrantTargetAvailability(delta grantDelta) error {
	if delta.entry == nil || !delta.entry.Exact {
		return nil
	}
	if _, err := os.Lstat(delta.entry.Path); errors.Is(err, os.ErrNotExist) {
		return ErrGrantUnsupported
	}
	return nil
}
