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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/looprig/sandbox"
	"github.com/looprig/sandbox/pkg/sandboxtest"
)

type conservativeSUT struct {
	workspace string
	bits      uint64
}

func (sut conservativeSUT) RunCommand(_ context.Context, _ string, command string) ([]byte, int, error) {
	if command == "env" || command == "set" {
		return []byte(strings.Join(os.Environ(), "\n")), 0, nil
	}
	if strings.HasPrefix(command, "type ") && !strings.HasPrefix(command, "type nul > ") {
		path := strings.Trim(strings.TrimPrefix(command, "type "), `"`)
		out, err := os.ReadFile(strings.ReplaceAll(path, "%%", "%"))
		if err != nil {
			return nil, 1, nil
		}
		return out, 0, nil
	}
	path := strings.TrimSuffix(strings.TrimPrefix(command, ": > '"), "'")
	if strings.HasPrefix(command, "type nul > ") {
		path = strings.Trim(strings.TrimPrefix(command, "type nul > "), `"`)
		path = strings.ReplaceAll(path, "%%", "%")
	}
	rel, err := filepath.Rel(sut.workspace, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return nil, 1, nil
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		return nil, 1, nil
	}
	return nil, 0, nil
}

func (sut conservativeSUT) RunArgv(_ context.Context, _ string, argv []string) ([]byte, int, error) {
	if len(argv) == 1 && argv[0] == "env" {
		return []byte(strings.Join(os.Environ(), "\n")), 0, nil
	}
	if len(argv) == 2 && argv[0] == "cat" {
		out, err := os.ReadFile(argv[1])
		if err != nil {
			return nil, 1, nil
		}
		return out, 0, nil
	}
	return nil, 127, nil
}

func (conservativeSUT) Level() uint8              { return sandboxtest.LevelNone }
func (sut conservativeSUT) GuaranteeBits() uint64 { return sut.bits }

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

func TestSuiteAcceptsUnclaimedWriteDenial(t *testing.T) {
	sandboxtest.RunSuite(t, "unclaimed-write-denial", func(_ *testing.T, workspace string) sandboxtest.SUT {
		return conservativeSUT{workspace: workspace}
	})
}

func TestClaimedImplicationChecksAreStrictlyBitGated(t *testing.T) {
	const claimed = sandboxtest.GuaranteeReadBoundary |
		sandboxtest.GuaranteeProcessBoundary |
		sandboxtest.GuaranteeNetworkBoundary |
		sandboxtest.GuaranteeResourceLimits
	sut := conservativeSUT{bits: claimed}
	calls := make(map[string]int)
	probe := func(name string) sandboxtest.ImplicationProbe {
		return func(context.Context, sandboxtest.SUT) (sandboxtest.ImplicationResult, error) {
			calls[name]++
			return sandboxtest.ImplicationResult{PositiveControl: true, GuaranteeHeld: true}, nil
		}
	}
	sandboxtest.CheckClaimedImplications(t, sut, sandboxtest.ImplicationProbes{
		Read: probe("read"), Process: probe("process"), Network: probe("network"), Resource: probe("resource"),
	})
	for _, name := range []string{"read", "process", "network", "resource"} {
		if calls[name] != 1 {
			t.Errorf("%s probe calls = %d; want 1", name, calls[name])
		}
	}

	called := false
	sandboxtest.CheckClaimedImplications(t, conservativeSUT{}, sandboxtest.ImplicationProbes{
		Read: func(context.Context, sandboxtest.SUT) (sandboxtest.ImplicationResult, error) {
			called = true
			return sandboxtest.ImplicationResult{}, nil
		},
	})
	if called {
		t.Error("unclaimed read implication probe was called")
	}
}
