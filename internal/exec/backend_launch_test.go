package exec

import (
	"context"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
)

// fixedExecution is a minimal enforce.Execution fake whose Wait returns
// immediately with a pre-decided (exitCode, err) pair, for tests that fake
// enforce.Spec.Launch directly and don't need any real asynchronous
// handshake — they already establish "authority" synchronously inside the
// fake Launch closure itself, exactly as before this field returned an
// Execution instead of a bare exit code.
type fixedExecution struct {
	code int
	err  error
}

func (execution fixedExecution) Wait(context.Context) (int, error) {
	return execution.code, execution.err
}

func TestBackendOwnedLaunchPreservesExecutorLifecycleAndOutputConvention(t *testing.T) {
	executor := &Executor{lifecycle: newExecutorLifecycle()}
	lease, err := executor.beginExecution(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var order []string
	originalEnv := []string{"A=B"}
	spec := enforce.Spec{Launch: func(request enforce.LaunchRequest) (enforce.Execution, error) {
		order = append(order, "launch")
		if request.Context != lease.ctx || request.Dir != "/work" ||
			!slices.Equal(request.Argv, []string{"/tool", "arg"}) ||
			!slices.Equal(request.Env, originalEnv) || request.Stdin == nil {
			t.Fatalf("launch request = %#v", request)
		}
		stdin, err := io.ReadAll(request.Stdin)
		if err != nil || len(stdin) != 0 {
			t.Fatalf("stdin = %q, %v; want empty input", stdin, err)
		}
		request.Argv[0] = "mutated"
		request.Env[0] = "mutated"
		_, _ = io.WriteString(request.Stdout, "out")
		_, _ = io.WriteString(request.Stderr, "err")
		return fixedExecution{code: 9}, nil
	}}
	out, code, err := executor.run(lease, "/work", []string{"/tool", "arg"},
		snapshot{spec: spec, env: originalEnv},
		func() { order = append(order, "observe") },
		func() error {
			order = append(order, "after-zero")
			return nil
		})
	if err != nil || code != 9 || string(out) != "outerr" {
		t.Fatalf("run = output %q code %d err %v", out, code, err)
	}
	if !slices.Equal(order, []string{"launch", "observe", "after-zero"}) {
		t.Fatalf("release order = %#v", order)
	}
	if originalEnv[0] != "A=B" {
		t.Fatalf("backend mutated executor environment: %#v", originalEnv)
	}
}

func TestBackendOwnedLaunchDoesNotStartAfterCancellation(t *testing.T) {
	executor := &Executor{lifecycle: newExecutorLifecycle()}
	ctx, cancel := context.WithCancel(context.Background())
	lease, err := executor.beginExecution(ctx)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	called := false
	_, code, err := executor.run(lease, "/work", []string{"/tool"},
		snapshot{spec: enforce.Spec{Launch: func(enforce.LaunchRequest) (enforce.Execution, error) {
			called = true
			return fixedExecution{}, nil
		}}},
		nil)
	if !errors.Is(err, context.Canceled) || code != -1 || called {
		t.Fatalf("cancelled run = called %t code %d err %v", called, code, err)
	}
}
