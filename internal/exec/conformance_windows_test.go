//go:build windows

package exec

import (
	"os"
	"testing"

	"github.com/looprig/sandbox/pkg/sandboxtest"
)

// Windows restricted execution mutates ACLs while the lease is live, so the
// platform conformance target uses the same explicit disposable-worker gate as
// the rest of the production restricted acceptance suite. The shared helper
// also rejects elevated and already-restricted source tokens.
func requireLiveConformanceBackend(t *testing.T) {
	t.Helper()
	if !windowsDisposableACLTestEnabled() {
		t.Skip(windowsDisposableACLTest + "=1 is required; live Windows ACL conformance remains unrun")
	}
	requireWindowsDisposableStandardSourceToken(t)
}

func windowsDisposableACLTestEnabled() bool {
	return os.Getenv(windowsDisposableACLTest) == "1"
}

func newLiveConformanceExecutor(t *testing.T, workspace string) sandboxtest.SUT {
	return newWindowsRestrictedAcceptanceExecutor(t, workspace)
}
