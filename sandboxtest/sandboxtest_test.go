package sandboxtest_test

// This is the consumer-perspective proof that the conformance suite works: an
// EXTERNAL test package (like a downstream consumer would write) constructs
// executors through the sandbox package's public API and runs the suite against
// them. On this host the live backend is the rung-2 Landlock/seccomp ladder
// (LevelDegraded); on a weaker kernel it degrades and the guarantee-gated suite
// still passes at whatever level is achieved. The external-boundary target
// exercises the LevelExternal path (mechanical write probe skipped, env scrub +
// self-consistency enforced). The null-backend (LevelNone) target is driven from
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
		e, err := sandbox.NewExecutor(sandbox.PolicyFor(sandbox.Write, ws))
		if err != nil {
			t.Fatalf("NewExecutor(live): %v", err)
		}
		return e
	})
}

// TestSuiteAgainstExternalBackend runs the suite against an external executor
// (LevelExternal): trust by explicit deployment declaration. The suite skips the
// mechanical write probe (the boundary is the surrounding container, not visible
// in-process) while still enforcing env scrub and posture self-consistency.
func TestSuiteAgainstExternalBackend(t *testing.T) {
	sandboxtest.RunSuite(t, "external", func(t *testing.T, ws string) sandboxtest.SUT {
		return sandbox.NewExternalExecutor(sandbox.ExternalDecl{
			Boundary: "docker",
			Env:      sandbox.EnvPolicy{}, // scrub still applies inside the boundary
		})
	})
}
