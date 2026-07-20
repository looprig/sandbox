package sandboxtest_test

// This is the consumer-perspective proof that the conformance suite works: an
// EXTERNAL test package (like a downstream consumer would write) constructs
// executors through the sandbox package's public API and runs the suite against
// them. On this host the live backend is the rung-2 Landlock/seccomp ladder
// (LevelDegraded); on a weaker kernel it degrades and the guarantee-gated suite
// still passes at whatever level is achieved. The null-backend (LevelNone) target is driven from
// the sandbox package itself (conformance_test.go), because forcing the null
// backend needs an unexported seam an external consumer cannot reach.

import (
	"os"
	"testing"

	"github.com/looprig/sandbox"
	"github.com/looprig/sandbox/sandboxtest"
)

// TestMain dispatches any re-exec'd stage-2 child before running the suite: the
// live Linux backend re-execs this test binary as /proc/self/exe, and
// sandbox.Init() catches that child and execs the target instead of re-running
// the tests. In a normal process Init() is a no-op (and it is a no-op on darwin).
func TestMain(m *testing.M) {
	sandbox.Init()
	os.Exit(m.Run())
}

// TestSuiteAgainstLivePlatformBackend runs the conformance suite against the
// platform-selected backend (rung 2 here). This is the real, mechanism-backed
// proof: the write-boundary and env-scrub checks spawn through the live OS
// enforcement path.
func TestSuiteAgainstLivePlatformBackend(t *testing.T) {
	sandboxtest.RunSuite(t, "live-platform", func(t *testing.T, ws string) sandboxtest.SUT {
		profile, err := sandbox.NewProfile(sandbox.ProfileConfig{
			WorkspaceRoot: ws, WorkspaceRead: sandbox.Allow, WorkspaceWrite: sandbox.Allow,
			HostRead: sandbox.Allow, HostWrite: sandbox.Deny,
			Network: sandbox.Deny, Command: sandbox.Allow,
		})
		if err != nil {
			t.Fatalf("NewProfile: %v", err)
		}
		set, err := sandbox.NewExecutorSet(profile,
			sandbox.WithScratchRoot(t.TempDir()), sandbox.WithMaxExecutors(1))
		if err != nil {
			t.Fatalf("NewExecutorSet(live): %v", err)
		}
		t.Cleanup(func() { _ = set.Close() })
		e, err := set.For("conformance")
		if err != nil {
			t.Fatalf("ExecutorSet.For(live): %v", err)
		}
		return e
	})
}
