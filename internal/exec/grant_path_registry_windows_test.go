//go:build windows

package exec

import (
	"testing"

	"github.com/looprig/sandbox/internal/policy"
)

func TestWindowsRetainedGrantRegistryAcceptsInjectedHandleWithoutLiveObject(t *testing.T) {
	paths := make(retainedGrantPaths)
	handle := &fakeRetainedHandle{}
	binding := policy.PathBinding{CanonicalPath: `C:\target`, ExistingPath: `C:\target`, Identity: "volume:file-id:type:tag:links:path"}
	id := [32]byte{9}
	if err := paths.add(id, retainedGrantPath{binding: binding, target: binding.CanonicalPath, exact: true, expiryUnixMilli: 42, handle: handle}); err != nil {
		t.Fatal(err)
	}
	got, err := paths.borrow(id, &binding, binding.CanonicalPath, true, 42)
	if err != nil || got != handle {
		t.Fatalf("take injected Windows handle = (%T, %v)", got, err)
	}
}
