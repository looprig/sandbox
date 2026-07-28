package sandbox_test

import (
	"os"
	"testing"

	"github.com/looprig/sandbox"
)

// TestMain honors the public Linux initialization contract before any facade
// test constructs a live executor. In a re-exec child, Init dispatches the
// stage-2 helper before the test suite can run; on the normal path (and on
// non-Linux platforms) it returns before m.Run.
func TestMain(m *testing.M) {
	sandbox.Init()
	os.Exit(m.Run())
}
