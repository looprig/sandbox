package sandbox

import (
	"os"
	"testing"
)

// TestMain dispatches any re-exec'd child (the namespace-capability probe or the
// stage-2 helper) before the test suite runs. When THIS test binary is re-exec'd
// as /proc/self/exe with a recognized sentinel set, Init() catches it and
// exits/execve's before m.Run() — so the child never runs the test suite. In a
// normal test process no sentinel is set, Init() is a no-op, and the suite runs.
//
// It has NO build tag so it applies on both linux (where Init dispatches) and
// darwin (where Init is a no-op) — the package has exactly one TestMain.
func TestMain(m *testing.M) {
	Init()
	os.Exit(m.Run())
}
