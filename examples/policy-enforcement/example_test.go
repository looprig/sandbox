package policyenforcement_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/looprig/sandbox"
)

func TestMain(m *testing.M) {
	sandbox.Init()
	os.Exit(m.Run())
}

func TestExamplePolicyAndEnforcement(t *testing.T) {
	workspace := t.TempDir()
	scratch := t.TempDir()

	base := newProfile(t, sandbox.ProfileConfig{
		WorkspaceRoot:  workspace,
		WorkspaceRead:  sandbox.Allow,
		WorkspaceWrite: sandbox.Allow,
		HostRead:       sandbox.Allow,
		HostWrite:      sandbox.Allow,
		Network:        sandbox.Allow,
		Command:        sandbox.Allow,
		Home:           sandbox.RealHome,
		Isolation:      sandbox.Sandboxed,
	})
	ceiling := newProfile(t, sandbox.ProfileConfig{
		WorkspaceRoot:  workspace,
		WorkspaceRead:  sandbox.Allow,
		WorkspaceWrite: sandbox.Deny,
		HostRead:       sandbox.Allow,
		HostWrite:      sandbox.Deny,
		Network:        sandbox.Deny,
		Command:        sandbox.Gated,
		Home:           sandbox.IsolatedHome,
		Isolation:      sandbox.Sandboxed,
	})
	restricted, err := sandbox.Restrict(base, ceiling)
	if err != nil {
		t.Fatalf("Restrict: %v", err)
	}
	assertAccess(t, restricted, "filesystem.read", workspace, sandbox.Allow)
	assertAccess(t, restricted, "filesystem.write", workspace, sandbox.Deny)
	assertAccess(t, restricted, "network", "", sandbox.Deny)
	assertAccess(t, restricted, "command.execute", "", sandbox.Gated)

	// Gated is an application-policy decision. Without a command grant the
	// executor refuses before starting a process; this is separate from the OS
	// sandbox guarantees reported by Level, Guarantees, and Report below.
	gatedSet, err := sandbox.NewExecutorSet(restricted,
		sandbox.WithScratchRoot(scratch),
		sandbox.WithMaxExecutors(1),
		sandbox.WithGrantTTL(time.Minute),
	)
	if err != nil {
		t.Fatalf("NewExecutorSet (gated): %v", err)
	}
	gated, err := gatedSet.For("policy-gate")
	if err != nil {
		t.Fatalf("ExecutorSet.For (gated): %v", err)
	}
	if _, _, err := gated.RunArgv(context.Background(), workspace, []string{os.Args[0], "-test.run=^TestSandboxedCommandHelper$"}); !errors.Is(err, sandbox.ErrGrantRequired) {
		t.Fatalf("gated RunArgv error = %v, want ErrGrantRequired", err)
	}
	if err := gatedSet.Close(); err != nil {
		t.Fatalf("close gated executor set: %v", err)
	}

	// Command=Allow permits a spawn, while Sandboxed plus the deny fields asks
	// the selected OS backend to enforce write and network boundaries. Backend
	// capabilities differ by platform, so consumers inspect the achieved facts.
	enforced := newProfile(t, sandbox.ProfileConfig{
		WorkspaceRoot:  workspace,
		WorkspaceRead:  sandbox.Allow,
		WorkspaceWrite: sandbox.Deny,
		HostRead:       sandbox.Allow,
		HostWrite:      sandbox.Deny,
		Network:        sandbox.Deny,
		Command:        sandbox.Allow,
		Home:           sandbox.IsolatedHome,
		Isolation:      sandbox.Sandboxed,
	})
	set, err := sandbox.NewExecutorSet(enforced,
		sandbox.WithScratchRoot(scratch),
		sandbox.WithMaxExecutors(1),
	)
	if err != nil {
		t.Fatalf("NewExecutorSet (enforced): %v", err)
	}
	executor, err := set.For("worker")
	if err != nil {
		t.Fatalf("ExecutorSet.For: %v", err)
	}
	again, err := set.For("worker")
	if err != nil {
		t.Fatalf("ExecutorSet.For memoized: %v", err)
	}
	if again != executor {
		t.Fatal("ExecutorSet.For did not memoize by key")
	}
	if _, err := set.For("over-limit"); !errors.Is(err, sandbox.ErrExecutorLimit) {
		t.Fatalf("ExecutorSet.For over limit error = %v, want ErrExecutorLimit", err)
	}

	guarantees := executor.Guarantees()
	if executor.Level() == sandbox.LevelNone {
		t.Fatalf("platform reported LevelNone for a successfully compiled sandboxed profile: guarantees=%+v report=%+v", guarantees, executor.Report().Entries)
	}
	if !guarantees.WriteBoundary || !guarantees.EnvScrub || !guarantees.NetworkBoundary {
		t.Fatalf("platform omitted a required guarantee: level=%d guarantees=%+v report=%+v", executor.Level(), guarantees, executor.Report().Entries)
	}
	if guarantees.Bits() != executor.GuaranteeBits() {
		t.Fatalf("Guarantees.Bits = %#x, GuaranteeBits = %#x", guarantees.Bits(), executor.GuaranteeBits())
	}
	for index, entry := range executor.Report().Entries {
		if entry.Feature == "" || entry.Status == "" || entry.Detail == "" {
			t.Fatalf("CompileReport entry %d is incomplete: %+v", index, entry)
		}
	}
	t.Logf("platform capabilities: level=%d guarantees=%+v report=%+v", executor.Level(), guarantees, executor.Report().Entries)

	output, code, err := executor.RunArgv(context.Background(), workspace, []string{os.Args[0], "-test.run=^TestSandboxedCommandHelper$"})
	if err != nil {
		t.Fatalf("RunArgv: %v", err)
	}
	if code != 0 || !strings.Contains(string(output), "sandboxed command ran") {
		t.Fatalf("RunArgv = code %d output %q, want successful helper output", code, output)
	}

	if err := set.Close(); err != nil {
		t.Fatalf("ExecutorSet.Close: %v", err)
	}
	if err := set.Close(); err != nil {
		t.Fatalf("second ExecutorSet.Close: %v", err)
	}
	if _, err := set.For("after-close"); !errors.Is(err, sandbox.ErrExecutorSetClosed) {
		t.Fatalf("ExecutorSet.For after close error = %v, want ErrExecutorSetClosed", err)
	}
	if _, _, err := executor.RunArgv(context.Background(), workspace, []string{os.Args[0], "-test.run=^TestSandboxedCommandHelper$"}); !errors.Is(err, sandbox.ErrExecutorClosed) {
		t.Fatalf("Executor.RunArgv after close error = %v, want ErrExecutorClosed", err)
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatalf("read scratch root after close: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("scratch root retains %d set-owned entries after close", len(entries))
	}
}

func TestSandboxedCommandHelper(t *testing.T) {
	if !strings.Contains(filepath.Base(filepath.Dir(os.Getenv("HOME"))), "sandbox-executors-") {
		return
	}
	fmt.Println("sandboxed command ran")
}

func newProfile(t *testing.T, config sandbox.ProfileConfig) *sandbox.Profile {
	t.Helper()
	profile, err := sandbox.NewProfile(config)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	return profile
}

func assertAccess(t *testing.T, profile *sandbox.Profile, kind, scope string, want sandbox.Access) {
	t.Helper()
	got, err := profile.AccessFor(kind, scope)
	if err != nil {
		t.Fatalf("AccessFor(%q, %q): %v", kind, scope, err)
	}
	if got != uint8(want) {
		t.Fatalf("AccessFor(%q, %q) = %d, want %d", kind, scope, got, want)
	}
}
