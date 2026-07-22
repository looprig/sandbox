//go:build windows

package sandboxtest_test

import (
	"os"
	"testing"

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
	restricted, err := token.IsRestricted()
	if err != nil {
		t.Fatalf("inspect external live-suite restriction state: %v", err)
	}
	if restricted {
		t.Fatal("external live Windows ACL suite requires a non-restricted source token")
	}
	if token.IsElevated() {
		t.Fatal("external live Windows ACL suite requires a standard-user, non-elevated source token")
	}
}
