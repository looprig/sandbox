//go:build integration && darwin

package exec

import "testing"

// escapeGrandchildAlive on darwin trusts the recorded pid: Seatbelt runs the
// target in the host's own pid space, so `echo $!` names the grandchild.
func escapeGrandchildAlive(t *testing.T, pidPath, _ string) bool {
	t.Helper()
	return pidFileAlive(pidPath)
}
