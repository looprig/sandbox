package exec

import (
	"errors"
	"testing"

	"github.com/looprig/sandbox/internal/policy"
)

type fakeRetainedHandle struct{ closes int }

func (handle *fakeRetainedHandle) Close() error {
	handle.closes++
	return nil
}

func TestRetainedGrantPathsPruneTakeAndCloseLifecycle(t *testing.T) {
	paths := make(retainedGrantPaths)
	binding := policy.PathBinding{CanonicalPath: "/target", ExistingPath: "/target", Identity: "identity"}
	firstID := [32]byte{1}
	first := &fakeRetainedHandle{}
	if err := paths.add(firstID, retainedGrantPath{binding: binding, target: "/target", exact: true, expiryUnixMilli: 10, handle: first}); err != nil {
		t.Fatal(err)
	}
	paths.prune(10)
	if first.closes != 0 {
		t.Fatal("entry was closed at its inclusive expiry")
	}
	paths.prune(11)
	if first.closes != 1 || len(paths) != 0 {
		t.Fatalf("expired entry lifecycle: closes=%d len=%d", first.closes, len(paths))
	}

	secondID := [32]byte{2}
	second := &fakeRetainedHandle{}
	if err := paths.add(secondID, retainedGrantPath{binding: binding, target: "/target", exact: true, expiryUnixMilli: 20, handle: second}); err != nil {
		t.Fatal(err)
	}
	got, err := paths.take(secondID, &binding, "/target", true, 20)
	if err != nil || got != second {
		t.Fatalf("take = (%T, %v), want retained handle", got, err)
	}
	if _, err := paths.take(secondID, &binding, "/target", true, 20); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("second take error = %v, want ErrGrantReplay", err)
	}
	if second.closes != 0 {
		t.Fatal("take closed transferred handle")
	}
	if err := second.Close(); err != nil || second.closes != 1 {
		t.Fatalf("transferred close = %v, closes=%d", err, second.closes)
	}

	third := &fakeRetainedHandle{}
	if err := paths.add([32]byte{3}, retainedGrantPath{binding: binding, target: "/target", expiryUnixMilli: 30, handle: third}); err != nil {
		t.Fatal(err)
	}
	paths.closeAll()
	if third.closes != 1 || len(paths) != 0 {
		t.Fatalf("closeAll lifecycle: closes=%d len=%d", third.closes, len(paths))
	}
}

func TestRetainedGrantPathsRejectAuthenticatedBindingMismatch(t *testing.T) {
	paths := make(retainedGrantPaths)
	id := [32]byte{4}
	handle := &fakeRetainedHandle{}
	binding := policy.PathBinding{CanonicalPath: "/target", ExistingPath: "/target", Identity: "identity"}
	if err := paths.add(id, retainedGrantPath{binding: binding, target: "/target", exact: true, expiryUnixMilli: 10, handle: handle}); err != nil {
		t.Fatal(err)
	}
	tampered := binding
	tampered.Identity = "other"
	if _, err := paths.take(id, &tampered, "/target", true, 10); !errors.Is(err, ErrGrantTargetChanged) {
		t.Fatalf("binding mismatch error = %v, want ErrGrantTargetChanged", err)
	}
	if handle.closes != 1 || len(paths) != 0 {
		t.Fatalf("mismatched entry was not revoked: closes=%d len=%d", handle.closes, len(paths))
	}
}
