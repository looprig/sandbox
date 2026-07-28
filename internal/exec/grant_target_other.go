//go:build !windows

package exec

// Non-Windows grant canonicalization retains its established pre-validation
// behavior. The target-availability restriction addressed by this seam is
// specific to Windows exact-object ACL grants.
func prepareGrantRequestForAuthorization(scope, class, target string) (string, string, error) {
	return normalizeGrantScopeTarget(scope, class, target)
}

func validateGrantTargetAvailability(grantDelta) error { return nil }
