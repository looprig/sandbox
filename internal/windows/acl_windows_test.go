//go:build windows

package windows

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/internal/winpath"
	win "golang.org/x/sys/windows"
)

type fakeACLObject struct {
	snapshotValue  aclObjectSnapshot
	setCalls       int
	failSetAt      int
	snapshotCalls  int
	failSnapshotAt int
	afterSet       func(*fakeACLObject)
	relaxErr       error
	relaxed        *fakeACLObject
	closed         bool
}

func (object *fakeACLObject) snapshot() (aclObjectSnapshot, error) {
	call := object.snapshotCalls
	object.snapshotCalls++
	if call == object.failSnapshotAt {
		object.failSnapshotAt = -1
		return aclObjectSnapshot{}, fmt.Errorf("injected snapshot failure %d", call)
	}
	value := object.snapshotValue
	value.owner = append([]byte(nil), value.owner...)
	value.aces = cloneACEs(value.aces)
	return value, nil
}

func (object *fakeACLObject) setDACL(aces [][]byte) error {
	call := object.setCalls
	object.setCalls++
	if call == object.failSetAt {
		object.failSetAt = -1
		return fmt.Errorf("injected set failure %d", call)
	}
	object.snapshotValue.aces = cloneACEs(aces)
	if object.afterSet != nil {
		object.afterSet(object)
	}
	return nil
}

func (object *fakeACLObject) close() error { object.closed = true; return nil }

func (object *fakeACLObject) prepareWriteShared() (aclProjectionObject, error) {
	if object.relaxErr != nil {
		return nil, object.relaxErr
	}
	if object.relaxed == nil {
		object.relaxed = &fakeACLObject{snapshotValue: aclObjectSnapshot{
			identity: object.snapshotValue.identity,
			owner:    append([]byte(nil), object.snapshotValue.owner...),
			aces:     cloneACEs(object.snapshotValue.aces),
		}, failSetAt: -1, failSnapshotAt: -1}
	}
	return object.relaxed, nil
}

type recordingACLJournal struct {
	prepared  []ACLMutationRecord
	completed []ACLMutationRecord
	failAt    int
}

func (journal *recordingACLJournal) BeforeACLMutation(record ACLMutationRecord) error {
	if len(journal.prepared) == journal.failAt {
		journal.failAt = -1
		return errors.New("injected journal failure")
	}
	journal.prepared = append(journal.prepared, cloneMutationRecord(record))
	return nil
}

func (journal *recordingACLJournal) AfterACLRollback(record ACLMutationRecord) error {
	journal.completed = append(journal.completed, cloneMutationRecord(record))
	return nil
}

func cloneMutationRecord(record ACLMutationRecord) ACLMutationRecord {
	record.ACE = append([]byte(nil), record.ACE...)
	return record
}

func exactProjectionFixture(t *testing.T, access ACLAccess, initial [][]byte, recorder ACLMutationRecorder) (ACLPlan, *fakeACLObject, *ACLProjection) {
	t.Helper()
	sid := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "acl-windows-transaction-test")
	identity := testIdentity(42, ACLObjectFile, 1)
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeExact, Access: access, Root: identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	object := &fakeACLObject{snapshotValue: aclObjectSnapshot{identity: identity, owner: []byte("owner-a"), aces: cloneACEs(initial)}, failSetAt: -1, failSnapshotAt: -1}
	projection, err := newACLProjection(plan, map[aclIdentityKey]aclProjectionObject{identityKey(identity): object}, recorder)
	if err != nil {
		t.Fatal(err)
	}
	return plan, object, projection
}

func TestACLProjectionRollsBackReadbackFailureAtEveryMutation(t *testing.T) {
	for failureIndex := range 3 {
		t.Run(fmt.Sprintf("readback-%d", failureIndex), func(t *testing.T) {
			_, object, projection := exactProjectionFixture(t, ACLRead|ACLExecute|ACLWrite, nil, nil)
			object.snapshotCalls = 0
			object.failSnapshotAt = failureIndex*2 + 1 // pre-read then read-back for each mutation
			if err := projection.Apply(); err == nil {
				t.Fatal("Apply succeeded despite injected DACL read-back failure")
			}
			if len(object.snapshotValue.aces) != 0 || len(projection.applied) != 0 {
				t.Fatalf("read-back failure was not rolled back: aces=%x applied=%d", object.snapshotValue.aces, len(projection.applied))
			}
		})
	}
}

func TestACLProjectionRollsBackInjectedFailureAtEveryMutation(t *testing.T) {
	for failureIndex := range 3 {
		t.Run(fmt.Sprintf("mutation-%d", failureIndex), func(t *testing.T) {
			unrelated := []byte{0, 0, 12, 0, 1, 0, 0, 0, 1, 2, 3, 4}
			_, object, projection := exactProjectionFixture(t, ACLRead|ACLExecute|ACLWrite, [][]byte{unrelated}, nil)
			object.failSetAt = failureIndex
			if err := projection.Apply(); err == nil {
				t.Fatal("Apply succeeded despite injected DACL failure")
			}
			if !equalACELists(object.snapshotValue.aces, [][]byte{unrelated}) {
				t.Fatalf("rollback DACL = %x, want original %x", object.snapshotValue.aces, unrelated)
			}
			if len(projection.applied) != 0 {
				t.Fatalf("rollback retained %d applied mutations", len(projection.applied))
			}
		})
	}
}

func TestACLProjectionJournalIsDurableBeforeWriteAndCompletedAfterReadback(t *testing.T) {
	journal := &recordingACLJournal{failAt: -1}
	plan, object, projection := exactProjectionFixture(t, ACLRead|ACLWrite, nil, journal)
	if err := projection.Apply(); err != nil {
		t.Fatal(err)
	}
	if len(journal.prepared) != len(plan.Mutations()) || len(journal.completed) != 0 {
		t.Fatalf("prepared=%d completed=%d", len(journal.prepared), len(journal.completed))
	}
	if err := projection.Rollback(); err != nil {
		t.Fatal(err)
	}
	if len(journal.completed) != len(journal.prepared) || len(object.snapshotValue.aces) != 0 {
		t.Fatalf("completed=%d prepared=%d aces=%x", len(journal.completed), len(journal.prepared), object.snapshotValue.aces)
	}
	for index := range journal.prepared {
		if journal.prepared[index].BaselineIdentical != 0 || len(journal.prepared[index].ACE) == 0 {
			t.Fatalf("invalid durable mutation record: %+v", journal.prepared[index])
		}
	}
}

func TestACLProjectionJournalFailurePreventsCorrespondingWrite(t *testing.T) {
	journal := &recordingACLJournal{failAt: 1}
	_, object, projection := exactProjectionFixture(t, ACLRead|ACLWrite, nil, journal)
	if err := projection.Apply(); err == nil {
		t.Fatal("Apply succeeded despite journal flush failure")
	}
	if object.setCalls != 2 { // first apply plus its rollback; second apply never occurs
		t.Fatalf("SetDACL calls = %d, want apply+rollback only", object.setCalls)
	}
	if len(object.snapshotValue.aces) != 0 {
		t.Fatalf("journal failure left projected ACEs: %x", object.snapshotValue.aces)
	}
}

func TestACLProjectionRollbackPreservesConcurrentUnrelatedChange(t *testing.T) {
	unrelated := []byte{0, 0, 12, 0, 7, 0, 0, 0, 8, 9, 10, 11}
	_, object, projection := exactProjectionFixture(t, ACLRead, nil, nil)
	injected := false
	object.afterSet = func(object *fakeACLObject) {
		if !injected {
			injected = true
			object.snapshotValue.aces = append(object.snapshotValue.aces, append([]byte(nil), unrelated...))
		}
	}
	if err := projection.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := projection.Rollback(); err != nil {
		t.Fatal(err)
	}
	if !equalACELists(object.snapshotValue.aces, [][]byte{unrelated}) {
		t.Fatalf("rollback overwrote concurrent DACL edit: %x", object.snapshotValue.aces)
	}
}

func TestACLProjectionRollbackRemovesOnlyOccurrenceAboveBaseline(t *testing.T) {
	plan, _, _ := exactProjectionFixture(t, ACLRead, nil, nil)
	identical := plan.Mutations()[0].ACE().Bytes
	journal := &recordingACLJournal{failAt: -1}
	_, object, projection := exactProjectionFixture(t, ACLRead, [][]byte{identical}, journal)
	if err := projection.Apply(); err != nil {
		t.Fatal(err)
	}
	if got := journal.prepared[0].BaselineIdentical; got != 1 {
		t.Fatalf("baseline identical occurrences = %d, want 1", got)
	}
	if err := projection.Rollback(); err != nil {
		t.Fatal(err)
	}
	if countIdenticalACE(object.snapshotValue.aces, identical) != 1 {
		t.Fatalf("rollback did not preserve baseline identical ACE: %x", object.snapshotValue.aces)
	}
}

func TestACLProjectionRollbackPermanentlyRefusesConcurrentIdenticalDeny(t *testing.T) {
	sid := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "identical-deny-collision")
	identity := testIdentity(63, ACLObjectFile, 2)
	deny := ACLACE{Type: ACEDeny, Access: ACLWrite}
	deny.Bytes = encodeACE(sid, identity.Kind, deny)
	object := &fakeACLObject{snapshotValue: aclObjectSnapshot{
		identity: identity, owner: []byte("owner"), aces: [][]byte{deny.Bytes, deny.Bytes},
	}, failSetAt: -1, failSnapshotAt: -1}
	projection := &ACLProjection{applied: []appliedACLMutation{{
		record: ACLMutationRecord{
			Object: identity, ACE: append([]byte(nil), deny.Bytes...), BaselineIdentical: 0,
			Rollback: ACLRollbackMetadata{LeaseID: testLeaseID(), Role: ACERoleRestrictingDeny, SID: sid},
		},
		object: object, owner: []byte("owner"),
	}}}
	if err := projection.Rollback(); !errors.Is(err, errACLIdenticalCollision) {
		t.Fatalf("first rollback error = %v, want permanent identical collision", err)
	}
	if object.setCalls != 0 || countIdenticalACE(object.snapshotValue.aces, deny.Bytes) != 2 {
		t.Fatalf("collision rollback mutated DACL: calls=%d aces=%x", object.setCalls, object.snapshotValue.aces)
	}
	// Even if the concurrent owner later removes one occurrence, the lease can
	// no longer distinguish whose ACE remains and must never retry removal.
	object.snapshotValue.aces = object.snapshotValue.aces[:1]
	for attempt := 0; attempt < 2; attempt++ {
		var err error
		if attempt == 0 {
			err = projection.Rollback()
		} else {
			err = projection.Close()
		}
		if !errors.Is(err, errACLIdenticalCollision) {
			t.Fatalf("retry %d error = %v, want permanent identical collision", attempt, err)
		}
		if object.setCalls != 0 || countIdenticalACE(object.snapshotValue.aces, deny.Bytes) != 1 {
			t.Fatalf("retry %d removed another occurrence: calls=%d aces=%x", attempt, object.setCalls, object.snapshotValue.aces)
		}
	}
}

func TestACLTreeProjectionRollsBackWhenWriteSharingCannotRelax(t *testing.T) {
	sid := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "relax-failure")
	identity := testIdentity(64, ACLObjectDirectory, 1)
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLWrite, Root: identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	object := &fakeACLObject{snapshotValue: aclObjectSnapshot{identity: identity, owner: []byte("owner")},
		failSetAt: -1, failSnapshotAt: -1, relaxErr: errors.New("injected sharing relaxation failure")}
	projection, err := newACLProjection(plan, map[aclIdentityKey]aclProjectionObject{identityKey(identity): object}, nil)
	if err != nil {
		t.Fatal(err)
	}
	projection.relaxTreeSharing = true
	if err := projection.Apply(); err == nil || !strings.Contains(err.Error(), "sharing relaxation failure") {
		t.Fatalf("Apply error = %v, want sharing relaxation failure", err)
	}
	if len(object.snapshotValue.aces) != 0 || len(projection.applied) != 0 {
		t.Fatalf("relaxation failure was not rolled back: aces=%x applied=%d", object.snapshotValue.aces, len(projection.applied))
	}
}

func TestACLTreeProjectionCommitsValidatedSharingReplacementSet(t *testing.T) {
	sid := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "relax-success")
	identity := testIdentity(65, ACLObjectDirectory, 1)
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLWrite, Root: identity,
	})
	if err != nil {
		t.Fatal(err)
	}
	object := &fakeACLObject{snapshotValue: aclObjectSnapshot{identity: identity, owner: []byte("owner")},
		failSetAt: -1, failSnapshotAt: -1}
	projection, err := newACLProjection(plan, map[aclIdentityKey]aclProjectionObject{identityKey(identity): object}, nil)
	if err != nil {
		t.Fatal(err)
	}
	projection.relaxTreeSharing = true
	if err := projection.Apply(); err != nil {
		t.Fatal(err)
	}
	if !object.closed || object.relaxed == nil || projection.objects[identityKey(identity)] != object.relaxed {
		t.Fatal("validated replacement set was not committed and frozen handle closed")
	}
	if len(projection.applied) != 1 || projection.applied[0].object != object.relaxed {
		t.Fatal("rollback ownership did not transfer to relaxed handle")
	}
	if err := projection.Rollback(); err != nil {
		t.Fatal(err)
	}
	if len(object.relaxed.snapshotValue.aces) != 0 {
		t.Fatalf("rollback through replacement left ACEs: %x", object.relaxed.snapshotValue.aces)
	}
}

func TestACLProjectionRejectsIdentityLinkOrOwnerChange(t *testing.T) {
	for name, change := range map[string]func(*fakeACLObject){
		"identity": func(object *fakeACLObject) { object.snapshotValue.identity.FileID[0]++ },
		"link":     func(object *fakeACLObject) { object.snapshotValue.identity.LinkCount++ },
		"owner":    func(object *fakeACLObject) { object.snapshotValue.owner = []byte("owner-b") },
	} {
		t.Run(name, func(t *testing.T) {
			_, object, projection := exactProjectionFixture(t, ACLRead, nil, nil)
			change(object)
			if err := projection.Apply(); err == nil {
				t.Fatal("Apply accepted changed retained object")
			}
			if object.setCalls != 0 {
				t.Fatalf("changed object received %d writes", object.setCalls)
			}
		})
	}
}

func TestACLProjectionCanonicalInsertionOrdersExplicitDenyAllowInherited(t *testing.T) {
	inherited := []byte{0, aceInheritedFlag, 12, 0, 1, 0, 0, 0, 1, 2, 3, 4}
	explicitAllow := []byte{0, 0, 12, 0, 2, 0, 0, 0, 1, 2, 3, 4}
	deny := []byte{1, 0, 12, 0, 3, 0, 0, 0, 1, 2, 3, 4}
	got := insertCanonicalACE([][]byte{explicitAllow, inherited}, deny)
	if !equalACELists(got, [][]byte{deny, explicitAllow, inherited}) {
		t.Fatalf("deny insertion order = %x", got)
	}
	newAllow := []byte{0, 0, 12, 0, 4, 0, 0, 0, 1, 2, 3, 4}
	got = insertCanonicalACE(got, newAllow)
	if !equalACELists(got, [][]byte{deny, explicitAllow, newAllow, inherited}) {
		t.Fatalf("allow insertion order = %x", got)
	}
}

func TestACLProjectionRequiresExactRetainedHandleSet(t *testing.T) {
	plan, object, _ := exactProjectionFixture(t, ACLRead, nil, nil)
	if _, err := newACLProjection(plan, nil, nil); err == nil {
		t.Fatal("missing retained handle accepted")
	}
	extraIdentity := testIdentity(99, ACLObjectFile, 1)
	extra := &fakeACLObject{snapshotValue: aclObjectSnapshot{identity: extraIdentity, owner: []byte("owner")}, failSetAt: -1, failSnapshotAt: -1}
	objects := map[aclIdentityKey]aclProjectionObject{
		identityKey(object.snapshotValue.identity): object,
		identityKey(extraIdentity):                 extra,
	}
	if _, err := newACLProjection(plan, objects, nil); err == nil {
		t.Fatal("unplanned retained handle accepted")
	}
}

func TestACLProjectionRefusesDenyRemovalWhileMatchingAllowRemains(t *testing.T) {
	sid := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "deny-cleanup-safety")
	identity := testIdentity(77, ACLObjectFile, 2)
	deny := ACLACE{Type: ACEDeny, Access: ACLWrite}
	deny.Bytes = encodeACE(sid, identity.Kind, deny)
	allow := ACLACE{Type: ACEAllow, Access: ACLWrite}
	allow.Bytes = encodeACE(sid, identity.Kind, allow)
	object := &fakeACLObject{snapshotValue: aclObjectSnapshot{
		identity: identity, owner: []byte("owner"), aces: [][]byte{deny.Bytes, allow.Bytes},
	}, failSetAt: -1}
	projection := &ACLProjection{applied: []appliedACLMutation{{
		record: ACLMutationRecord{
			Object: identity, ACE: deny.Bytes,
			Rollback: ACLRollbackMetadata{LeaseID: testLeaseID(), Role: ACERoleRestrictingDeny, SID: sid},
		},
		object: object, owner: []byte("owner"),
	}}}
	if err := projection.Rollback(); err == nil {
		t.Fatal("rollback removed a deny while a matching allow remained")
	}
	if !equalACELists(object.snapshotValue.aces, [][]byte{deny.Bytes, allow.Bytes}) {
		t.Fatalf("unsafe deny rollback changed DACL: %x", object.snapshotValue.aces)
	}
	if len(projection.applied) != 1 {
		t.Fatal("failed deny cleanup was forgotten")
	}
}

func TestACLProjectionTreeRollbackRemovesAllowBeforeHardlinkDeny(t *testing.T) {
	sid := deriveModuleTrusteeSID(sidKindOneShot, oneShotSIDDomain, "tree-rollback-order")
	rootIdentity := testIdentity(81, ACLObjectDirectory, 1)
	hardlinkIdentity := testIdentity(82, ACLObjectFile, 2)
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLWrite, Root: rootIdentity,
		Entries: []ACLPlanEntry{{Object: hardlinkIdentity}},
	})
	if err != nil {
		t.Fatal(err)
	}
	root := &fakeACLObject{snapshotValue: aclObjectSnapshot{identity: rootIdentity, owner: []byte("owner")}, failSetAt: -1, failSnapshotAt: -1}
	child := &fakeACLObject{snapshotValue: aclObjectSnapshot{identity: hardlinkIdentity, owner: []byte("owner")}, failSetAt: -1, failSnapshotAt: -1}
	root.afterSet = func(root *fakeACLObject) {
		filtered := child.snapshotValue.aces[:0]
		for _, ace := range child.snapshotValue.aces {
			if !(len(ace) >= 8 && ace[0] == 0 && ace[1]&aceInheritedFlag != 0 && bytes.Equal(ace[8:], sid.binary())) {
				filtered = append(filtered, ace)
			}
		}
		child.snapshotValue.aces = filtered
		for _, ace := range root.snapshotValue.aces {
			if len(ace) >= 8 && ace[0] == 0 && bytes.Equal(ace[8:], sid.binary()) {
				inherited := append([]byte(nil), ace...)
				inherited[1] |= aceInheritedFlag
				child.snapshotValue.aces = append(child.snapshotValue.aces, inherited)
			}
		}
	}
	journal := &recordingACLJournal{failAt: -1}
	projection, err := newACLProjection(plan, map[aclIdentityKey]aclProjectionObject{
		identityKey(rootIdentity): root, identityKey(hardlinkIdentity): child,
	}, journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := projection.Rollback(); err != nil {
		t.Fatal(err)
	}
	if len(root.snapshotValue.aces) != 0 || len(child.snapshotValue.aces) != 0 {
		t.Fatalf("tree rollback left root=%x child=%x", root.snapshotValue.aces, child.snapshotValue.aces)
	}
	if len(journal.completed) != 2 || journal.completed[0].Rollback.Role != ACERoleRestrictingAllow || journal.completed[1].Rollback.Role != ACERoleRestrictingDeny {
		t.Fatalf("unsafe rollback order: %+v", journal.completed)
	}
}

func equalACELists(left, right [][]byte) bool {
	return slices.EqualFunc(left, right, bytes.Equal)
}

func TestACLProjectionDisposableExactAndReadback(t *testing.T) {
	if os.Getenv("SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST") != "1" {
		t.Skip("destructive ACL integration is restricted to a disposable Windows worker")
	}
	root := t.TempDir()
	path := filepath.Join(root, "exact.txt")
	if err := os.WriteFile(path, []byte("positive control"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Positive control: the worker identity can modify the candidate before any
	// projection, which distinguishes an ACL result from an already-denied tree.
	if err := os.WriteFile(path, []byte("positive control updated"), 0o600); err != nil {
		t.Fatalf("positive control cannot modify test tree: %v", err)
	}
	binding, err := policy.CapturePathBinding(path)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := policy.AcquirePathHandle(&binding, binding.CanonicalPath, true)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()
	identity, err := identityFromHandle(win.Handle(handle.NativeHandle()), handle.Target())
	if err != nil {
		t.Fatal(err)
	}
	journal, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	generator, err := NewOneShotSIDGenerator(bytes.NewReader(bytes.Repeat([]byte{0x5a}, sidEntropyBytes)), journal)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := generator.Next()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeExact, Access: ACLRead | ACLWrite, Root: identity,
	})
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
	if err := projection.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestACLProjectionDisposableTreeMatrix(t *testing.T) {
	if os.Getenv("SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST") != "1" {
		t.Skip("destructive ACL integration is restricted to a disposable Windows worker")
	}
	scratch := t.TempDir()
	root := filepath.Join(t.TempDir(), "tree")
	ordinaryDir := filepath.Join(root, "ordinary")
	carveoutDir := filepath.Join(root, "carveout")
	if err := os.MkdirAll(ordinaryDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(carveoutDir, 0o700); err != nil {
		t.Fatal(err)
	}
	ordinaryFile := filepath.Join(ordinaryDir, "ordinary.txt")
	carveoutFile := filepath.Join(carveoutDir, "denied.txt")
	hardlinkFile := filepath.Join(root, "hardlink.txt")
	for _, path := range []string{ordinaryFile, carveoutFile, hardlinkFile} {
		if err := os.WriteFile(path, []byte("positive control"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("positive control updated"), 0o600); err != nil {
			t.Fatalf("positive control cannot modify %q: %v", path, err)
		}
	}
	outsideHardlink := filepath.Join(filepath.Dir(root), "outside-hardlink.txt")
	if err := os.Link(hardlinkFile, outsideHardlink); err != nil {
		t.Fatalf("create hard-link fixture: %v", err)
	}
	outsideTree := filepath.Join(filepath.Dir(root), "outside-reparse-target")
	if err := os.Mkdir(outsideTree, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outsideTree, "must-not-enumerate.txt"), []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	reparsePath := filepath.Join(root, "reparse")
	if err := os.Symlink(outsideTree, reparsePath); err != nil {
		t.Fatalf("create reparse fixture on disposable worker: %v", err)
	}

	binding, err := policy.CapturePathBinding(root)
	if err != nil {
		t.Fatal(err)
	}
	rootHandle, err := policy.AcquirePathHandle(&binding, binding.CanonicalPath, false)
	if err != nil {
		t.Fatal(err)
	}
	defer rootHandle.Close()
	tree, err := EnumerateRetainedACLTree(rootHandle)
	if err != nil {
		t.Fatal(err)
	}
	defer tree.Close()
	if err := os.WriteFile(ordinaryFile, []byte("must be share-blocked"), 0o600); err == nil {
		t.Fatal("retained tree allowed a concurrent file writer")
	}
	concurrentChild := filepath.Join(root, "must-be-share-blocked.txt")
	if err := os.WriteFile(concurrentChild, []byte("must be blocked"), 0o600); err == nil {
		t.Fatal("retained tree allowed a concurrent namespace mutation")
	}

	var entries []ACLPlanEntry
	var reparseCount, hardlinkCount, outsideCount int
	for _, entry := range tree.Entries() {
		deny := ACLAccess(0)
		if winpath.HasPrefix(entry.RelativePath, `carveout\`) || winpath.EqualPath(entry.RelativePath, "carveout") {
			deny = ACLWrite
		}
		if entry.Object.Kind == ACLObjectReparsePoint {
			reparseCount++
		}
		if entry.Object.Kind == ACLObjectFile && entry.Object.LinkCount > 1 {
			hardlinkCount++
		}
		if strings.Contains(strings.ToLower(entry.RelativePath), "must-not-enumerate") {
			outsideCount++
		}
		entries = append(entries, ACLPlanEntry{Object: entry.Object, Deny: deny})
	}
	if reparseCount != 1 || outsideCount != 0 || hardlinkCount != 1 {
		t.Fatalf("enumeration reparse=%d outside=%d hardlink=%d, want 1/0/1", reparseCount, outsideCount, hardlinkCount)
	}

	journal, err := OpenRestrictedJournal(scratch)
	if err != nil {
		t.Fatal(err)
	}
	generator, err := NewOneShotSIDGenerator(bytes.NewReader(bytes.Repeat([]byte{0x6b}, sidEntropyBytes)), journal)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := generator.Next()
	if err != nil {
		t.Fatal(err)
	}
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLRead | ACLWrite,
		Root: tree.Root(), Entries: entries,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.SkippedReparsePoints()) != 1 || !slices.Contains(plan.Narrowings(), "windows.filesystem.hardlink") {
		t.Fatalf("plan skipped=%d narrowings=%v", len(plan.SkippedReparsePoints()), plan.Narrowings())
	}

	baseline := make(map[aclIdentityKey][][]byte, len(tree.objects))
	for key, object := range tree.objects {
		snapshot, err := object.snapshot()
		if err != nil {
			t.Fatal(err)
		}
		baseline[key] = cloneACEs(snapshot.aces)
	}
	projection, err := NewRestrictedACLTreeProjection(plan, tree, journal)
	if err != nil {
		t.Fatal(err)
	}
	if err := projection.Apply(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ordinaryFile, []byte("write allowed after full readback"), 0o600); err != nil {
		t.Fatalf("relaxed retained tree still blocks ordinary writes after Apply: %v", err)
	}
	if err := os.WriteFile(concurrentChild, []byte("create allowed after full readback"), 0o600); err != nil {
		t.Fatalf("relaxed retained root still blocks child creation after Apply: %v", err)
	}
	if err := os.Remove(ordinaryFile); err == nil {
		t.Fatal("relaxed retained file allowed delete sharing")
	}
	if err := os.Rename(root, root+"-swapped"); err == nil {
		_ = os.Rename(root+"-swapped", root)
		t.Fatal("relaxed retained root allowed root swap")
	}
	// Apply performs the authoritative full-plan DACL read-back. Repeat it here
	// so this live matrix explicitly observes inheritance and carveout denies.
	if err := projection.validatePlanReadback(); err != nil {
		t.Fatal(err)
	}
	for _, target := range plan.ValidationTargets() {
		if target.Object.Kind == ACLObjectFile && target.Object.LinkCount > 1 {
			snapshot, err := projection.objects[identityKey(target.Object)].snapshot()
			if err != nil || !containsExpectedACE(snapshot.aces, target.Object.Kind,
				ACLACEExpectation{Role: ACERoleRestrictingDeny, SID: sid, Access: ACLRead}) ||
				!containsExpectedACE(snapshot.aces, target.Object.Kind,
					ACLACEExpectation{Role: ACERoleRestrictingDeny, SID: sid, Access: ACLWrite}) {
				t.Fatalf("hard-link explicit deny missing: %v", err)
			}
		}
	}
	if err := projection.Rollback(); err != nil {
		t.Fatal(err)
	}
	for key, object := range projection.objects {
		snapshot, err := object.snapshot()
		if err != nil {
			t.Fatal(err)
		}
		if !equalACELists(snapshot.aces, baseline[key]) {
			t.Fatalf("rollback DACL mismatch for %+v: got=%x want=%x", snapshot.identity, snapshot.aces, baseline[key])
		}
	}
	if err := projection.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ordinaryFile, []byte("writer restored after rollback"), 0o600); err != nil {
		t.Fatalf("retained writer blockade survived projection close: %v", err)
	}
	if err := os.WriteFile(concurrentChild, []byte("namespace restored after rollback"), 0o600); err != nil {
		t.Fatalf("retained namespace blockade survived projection close: %v", err)
	}
}
