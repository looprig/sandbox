//go:build windows

package sandboxtest_test

import (
	"os"
	"testing"

	sandboxwindows "github.com/looprig/sandbox/internal/windows"
	win "golang.org/x/sys/windows"
)

// requireLivePlatformBackend keeps the external-consumer smoke test under the
// same disposable-worker contract as the production restricted acceptance. It
// does not turn an invalid source context into a pass: without the opt-in the
// test is reported as explicitly unrun, and with it an elevated or restricted
// source token is a hard failure.
func requireLivePlatformBackend(t *testing.T) {
	t.Helper()
	const gate = "SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST"
	if os.Getenv(gate) != "1" {
		t.Skip(gate + "=1 is required; external live Windows ACL suite remains unrun")
	}
	var token win.Token
	if err := win.OpenProcessToken(win.CurrentProcess(), win.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("inspect external live-suite source token: %v", err)
	}
	defer token.Close()
	if err := sandboxwindows.ValidateDisposableStandardUserToken(token); err != nil {
		t.Fatalf("external live Windows ACL suite source token: %v", err)
	}
}
