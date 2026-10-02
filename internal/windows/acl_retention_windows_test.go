//go:build windows

package windows

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/looprig/sandbox/internal/policy"
	win "golang.org/x/sys/windows"
)

// inheritedAllowACE is the inherited copy of the root's allow that Windows
// propagates onto a child; fakes have no propagation, so tests seed it.
func inheritedAllowACE(sid SID, kind ACLObjectKind, access ACLAccess) []byte {
	ace := encodeACE(sid, kind, ACLACE{Type: ACEAllow, Access: access})
	ace[1] |= aceInheritedFlag
	return ace
}

type pinnedTreeFixture struct {
	sid                      SID
	plan                     ACLPlan
	root, carveout, ordinary ACLObjectIdentity
	objects                  map[ACLObjectIdentity]*fakeACLObject
	projection               *ACLProjection
}

func newPinnedTreeFixture(t *testing.T) *pinnedTreeFixture {
	t.Helper()
	fixture := &pinnedTreeFixture{
		sid:      deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "m16-pinned"),
		root:     testIdentity(70, ACLObjectDirectory, 1),
		carveout: testIdentity(71, ACLObjectDirectory, 1),
		ordinary: testIdentity(72, ACLObjectFile, 1),
	}
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: fixture.sid, Scope: ACLScopeTree, Access: ACLWrite, Root: fixture.root,
		Entries: []ACLPlanEntry{{Object: fixture.carveout, Deny: ACLWrite}, {Object: fixture.ordinary}},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.plan = plan
	fixture.objects = make(map[ACLObjectIdentity]*fakeACLObject)
	retained := make(map[aclIdentityKey]aclProjectionObject)
	for _, identity := range []ACLObjectIdentity{fixture.root, fixture.carveout, fixture.ordinary} {
		var aces [][]byte
		if identity != fixture.root {
			aces = [][]byte{inheritedAllowACE(fixture.sid, identity.Kind, ACLWrite)}
		}
		object := &fakeACLObject{snapshotValue: aclObjectSnapshot{identity: identity, owner: []byte("owner"), aces: aces},
			failSetAt: -1, failSnapshotAt: -1}
		fixture.objects[identity] = object
		retained[identityKey(identity)] = object
	}
	// Pre-create the pinned re-opens (fakeACLObject.prepareWriteShared
	// returns them) so the root's re-open can emulate Windows inheritance:
	// once the root no longer carries the lease's allow, the inherited copy
	// disappears from its children, which a real rollback relies on before
	// it may remove a carveout's deny.
	for _, identity := range []ACLObjectIdentity{fixture.root, fixture.carveout} {
		original := fixture.objects[identity]
		original.relaxed = &fakeACLObject{snapshotValue: aclObjectSnapshot{
			identity: identity, owner: []byte("owner"), aces: cloneACEs(original.snapshotValue.aces),
		}, failSetAt: -1, failSnapshotAt: -1}
	}
	fixture.objects[fixture.root].relaxed.afterSet = func(root *fakeACLObject) {
		if hasAllowForSID(root.snapshotValue.aces, fixture.sid) {
			return
		}
		for _, child := range []*fakeACLObject{fixture.objects[fixture.carveout].relaxed, fixture.objects[fixture.ordinary]} {
			kept := child.snapshotValue.aces[:0]
			for _, ace := range child.snapshotValue.aces {
				if ace[1]&aceInheritedFlag == 0 {
					kept = append(kept, ace)
				}
			}
			child.snapshotValue.aces = kept
		}
	}
	projection, err := newACLProjection(plan, retained, nil)
	if err != nil {
		t.Fatal(err)
	}
	projection.relaxTreeSharing = true
	projection.pinned = planPinnedACLTreeObjects(fixture.root, []ACLTreeEntry{
		{Object: fixture.carveout, RelativePath: "carveout"},
		{Object: fixture.ordinary, RelativePath: "ordinary.txt"},
	}, plan)
	fixture.projection = projection
	return fixture
}

// TestACLTreeProjectionPinsCarveoutsAndReleasesOrdinaryObjects pins M16 on
// the projection: the root and the carveout are re-opened (no delete
// sharing) before any mutation and own the rollback; the ordinary object's
// handle is released after its read-back and is no longer retained at all.
func TestACLTreeProjectionPinsCarveoutsAndReleasesOrdinaryObjects(t *testing.T) {
	fixture := newPinnedTreeFixture(t)
	root, carveout, ordinary := fixture.objects[fixture.root], fixture.objects[fixture.carveout], fixture.objects[fixture.ordinary]
	if err := fixture.projection.Apply(); err != nil {
		t.Fatal(err)
	}
	if !root.closed || !carveout.closed || root.relaxed.setCalls == 0 || carveout.relaxed.setCalls == 0 {
		t.Fatal("pinned objects were not re-opened and their enumeration handles closed")
	}
	if root.setCalls != 0 || carveout.setCalls != 0 {
		t.Fatal("a mutation went through an enumeration handle instead of the pinned one")
	}
	if !ordinary.closed || ordinary.relaxed != nil {
		t.Fatal("the ordinary object kept a handle or was pinned")
	}
	if _, retained := fixture.projection.objects[identityKey(fixture.ordinary)]; retained || len(fixture.projection.objects) != 2 {
		t.Fatalf("retained objects = %d, want only the root and the carveout", len(fixture.projection.objects))
	}
	for _, applied := range fixture.projection.applied {
		if applied.object != root.relaxed && applied.object != carveout.relaxed {
			t.Fatal("rollback ownership is on a handle that is not pinned")
		}
	}
	if err := fixture.projection.Rollback(); err != nil {
		t.Fatal(err)
	}
	for name, object := range map[string]*fakeACLObject{"root": root.relaxed, "carveout": carveout.relaxed} {
		for _, ace := range object.snapshotValue.aces {
			if ace[1]&aceInheritedFlag == 0 && bytes.Equal(ace[8:], fixture.sid.binary()) {
				t.Fatalf("%s kept a lease ACE after rollback: %x", name, ace)
			}
		}
	}
}

// TestACLTreeProjectionToleratesOnlyOrdinaryObjectsMovingDuringCompile: an
// ordinary object renamed while the compile ran is skipped by read-back;
// the same change to a pinned carveout fails closed before any write.
func TestACLTreeProjectionToleratesOnlyOrdinaryObjectsMovingDuringCompile(t *testing.T) {
	fixture := newPinnedTreeFixture(t)
	fixture.objects[fixture.ordinary].snapshotValue.identity.FileID[0]++
	if err := fixture.projection.Apply(); err != nil {
		t.Fatalf("an ordinary object moving during compile failed the projection: %v", err)
	}

	fixture = newPinnedTreeFixture(t)
	// Re-opening the carveout by its path finds a different object.
	fixture.objects[fixture.carveout].relaxed.snapshotValue.identity.FileID[0]++
	err := fixture.projection.Apply()
	if !errors.Is(err, policy.ErrTargetChanged) {
		t.Fatalf("a moved carveout = %v, want ErrTargetChanged", err)
	}
	for name, object := range fixture.objects {
		if object.setCalls != 0 || (object.relaxed != nil && object.relaxed.setCalls != 0) {
			t.Fatalf("%v received a DACL write before the carveout check failed", name)
		}
	}

	// The legacy (unpinned) mode keeps the strict read-back.
	fixture = newPinnedTreeFixture(t)
	fixture.projection.pinned = nil
	fixture.objects[fixture.ordinary].snapshotValue.identity.FileID[0]++
	if err := fixture.projection.Apply(); err == nil {
		t.Fatal("legacy retention accepted a changed validation target")
	}
}

// TestACLProjectionDisposableExactSurvivesRenameAndDelete pins M16's exact
// allow projection on a real filesystem: during the lease no handle blocks a
// rename or a delete of the granted file; rollback reopens the renamed file
// by file ID and removes exactly the lease's ACE, and a deleted file counts
// as rolled back (its ACE went with it).
func TestACLProjectionDisposableExactSurvivesRenameAndDelete(t *testing.T) {
	if os.Getenv("SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST") != "1" {
		t.Skip("destructive ACL integration is restricted to a disposable Windows worker")
	}
	requireACLDisposableStandardSourceToken(t)
	for _, scenario := range []string{"rename", "delete"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "granted.txt")
			if err := os.WriteFile(path, []byte("granted"), 0o600); err != nil {
				t.Fatal(err)
			}
			binding, err := policy.CapturePathBinding(path)
			if err != nil {
				t.Fatal(err)
			}
			handle, err := policy.AcquirePathHandle(&binding, binding.CanonicalPath, true)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := identityFromHandle(win.Handle(handle.NativeHandle()), handle.Target())
			if err != nil {
				t.Fatal(err)
			}
			journal, err := OpenRestrictedJournal(root)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = journal.Close() })
			generator, err := NewOneShotSIDGenerator(&brokerTestEntropy{seed: 0x7c}, journal)
			if err != nil {
				t.Fatal(err)
			}
			sid, err := generator.Next()
			if err != nil {
				t.Fatal(err)
			}
			plan, err := BuildACLPlan(ACLPlanRequest{LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeExact, Access: ACLWrite, Root: identity})
			if err != nil {
				t.Fatal(err)
			}
			projection, err := NewRestrictedACLProjection(plan, []*policy.PathHandle{handle}, journal)
			if err != nil {
				t.Fatal(err)
			}
			if err := projection.Apply(); err != nil {
				_ = projection.Close()
				t.Fatal(err)
			}
			// The executor's own policy handle grants delete sharing; drop it
			// here so only the projection could still be blocking.
			if err := handle.Close(); err != nil {
				t.Fatal(err)
			}
			moved := path + "-moved"
			switch scenario {
			case "rename":
				if err := os.Rename(path, moved); err != nil {
					t.Fatalf("a live exact lease blocked a rename: %v", err)
				}
			case "delete":
				if err := os.Remove(path); err != nil {
					t.Fatalf("a live exact lease blocked a delete: %v", err)
				}
			}
			if err := projection.Close(); err != nil {
				t.Fatalf("rollback after %s: %v", scenario, err)
			}
			if scenario == "rename" {
				object, err := openWin32ACLObject(moved, false, false)
				if err != nil {
					t.Fatal(err)
				}
				defer object.close()
				snapshot, err := object.snapshot()
				if err != nil {
					t.Fatal(err)
				}
				for _, ace := range snapshot.aces {
					if len(ace) >= 8 && bytes.Equal(ace[8:], sid.binary()) {
						t.Fatalf("rollback left the lease ACE on the renamed file: %x", ace)
					}
				}
			}
		})
	}
}
