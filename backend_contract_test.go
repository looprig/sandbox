package sandbox

import (
	"errors"
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"testing"
)

func TestNullBackendRejectsSandboxedPolicy(t *testing.T) {
	_, _, _, _, err := enforce.NewNull().Compile(policy.Effective{Isolation: Sandboxed})
	if !errors.Is(err, enforce.ErrUnavailable) {
		t.Fatalf("sandboxed null compile error = %v, want enforce.ErrUnavailable", err)
	}
	spec, _, level, bits, err := enforce.NewNull().Compile(policy.Effective{Isolation: Unconfined, Env: policy.EnvPolicy{Inherit: true}})
	if err != nil || spec.Wrap == nil || level != LevelNone || bits != 0 {
		t.Fatalf("unconfined null compile = wrap %v level %d bits %d err %v", spec.Wrap != nil, level, bits, err)
	}
}
