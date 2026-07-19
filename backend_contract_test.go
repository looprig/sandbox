package sandbox

import (
	"errors"
	"testing"
)

func TestNullBackendRejectsSandboxedPolicy(t *testing.T) {
	_, _, _, _, err := newNullBackend().compile(effectivePolicy{Isolation: Sandboxed})
	if !errors.Is(err, ErrSandboxUnavailable) {
		t.Fatalf("sandboxed null compile error = %v, want ErrSandboxUnavailable", err)
	}
	spec, _, level, bits, err := newNullBackend().compile(effectivePolicy{Isolation: Unconfined, Env: effectiveEnvPolicy{Inherit: true}})
	if err != nil || spec.wrap == nil || level != LevelNone || bits != 0 {
		t.Fatalf("unconfined null compile = wrap %v level %d bits %d err %v", spec.wrap != nil, level, bits, err)
	}
}
