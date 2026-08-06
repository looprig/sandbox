//go:build !windows

package exec

import (
	"errors"
	"fmt"
	"testing"
)

// This file is Task 22B's compile-only, non-Windows-build-tag proof that its
// facade/typed-error surface — ErrConPTYUnavailable (process_errors.go, no
// build tag) and the platform-neutral ConPTYLaunchPlan vocabulary
// (conpty_launch_plan.go, Task 22A, already covered on its own by
// conpty_launch_plan_test.go) — is real, ordinary, always-visible package
// surface: usable and checkable from any platform's code, never gated
// behind a windows build tag itself, exactly mirroring how
// terminal_other_test.go's TestPrepareProcessRejectsTTY proves
// ErrProcessTTYUnsupported is an ordinary, always-visible sentinel rather
// than something only reachable on the platform that actually returns it.
//
// Unlike terminal_windows.go's own probeConPTYAvailable/conPTYProbe (the
// REAL runtime capability check, which only exists under //go:build
// windows and is exercised for real by process_conpty_windows_test.go on a
// live Windows worker), this file never touches any Windows API and never
// spawns anything: it proves the ERROR VALUE itself — the thing a
// cross-platform caller actually branches on via errors.Is — compiles,
// wraps, and unwraps correctly from ordinary, non-Windows code. This file's
// own build tag excludes windows specifically so it never duplicates
// process_conpty_windows_test.go's real coverage; it runs for real (not
// merely compiles) on darwin and linux, and would compile identically on
// any other non-Windows platform.

// TestErrConPTYUnavailableIsAnOrdinarySentinel proves ErrConPTYUnavailable
// is a normal, comparable, wrappable error value: constructible, wrappable
// via fmt.Errorf's %w (exactly how terminal_windows.go's own
// probeConPTYAvailable wraps it with the underlying LazyProc.Find error),
// and recoverable via errors.Is/errors.Unwrap — the exact surface a
// cross-platform caller needs, reachable from this non-Windows file with no
// import of anything Windows-specific at all.
func TestErrConPTYUnavailableIsAnOrdinarySentinel(t *testing.T) {
	if ErrConPTYUnavailable == nil {
		t.Fatal("ErrConPTYUnavailable is nil")
	}
	if ErrConPTYUnavailable.Error() == "" {
		t.Fatal("ErrConPTYUnavailable has an empty message")
	}

	wrapped := fmt.Errorf("probe CreatePseudoConsole: %w: some underlying detail", ErrConPTYUnavailable)
	if !errors.Is(wrapped, ErrConPTYUnavailable) {
		t.Fatalf("errors.Is(wrapped, ErrConPTYUnavailable) = false for %v", wrapped)
	}
	if errors.Unwrap(wrapped) != ErrConPTYUnavailable {
		t.Fatalf("errors.Unwrap(wrapped) = %v, want ErrConPTYUnavailable", errors.Unwrap(wrapped))
	}

	// Distinct from the compile-time, platform-generic sentinel: a caller
	// must be able to tell "this platform never supports a TTY at all"
	// (ErrProcessTTYUnsupported) apart from "this platform generically
	// supports ConPTY, but this specific host does not"
	// (ErrConPTYUnavailable) — see both sentinels' own doc comments
	// (process_errors.go).
	if errors.Is(ErrConPTYUnavailable, ErrProcessTTYUnsupported) {
		t.Fatal("ErrConPTYUnavailable must not satisfy errors.Is against ErrProcessTTYUnsupported — they are distinct, independently checkable failure modes")
	}
}
