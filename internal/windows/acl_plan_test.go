package windows

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/looprig/sandbox/internal/policy"
)

func testIdentity(id byte, kind ACLObjectKind, links uint32) ACLObjectIdentity {
	var fileID [16]byte
	fileID[15] = id
	identity := ACLObjectIdentity{VolumeSerial: 7, FileID: fileID, Kind: kind, LinkCount: links}
	if kind == ACLObjectReparsePoint {
		identity.ReparseTag = 0xa000000c
	}
	return identity
}

func testLeaseID() ACLLeaseID {
	var lease ACLLeaseID
	lease[15] = 1
	return lease
}

func TestACLPlanSeparatesAxesAndOrdersDeniesBeforeInheritedAllows(t *testing.T) {
	sid, _ := ExecutorSID("install", "executor")
	root := testIdentity(1, ACLObjectDirectory, 1)
	carveout := testIdentity(2, ACLObjectDirectory, 1)
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLRead | ACLWrite,
		Root:    root,
		Entries: []ACLPlanEntry{{Object: carveout, Deny: ACLWrite}},
	})
	if err != nil {
		t.Fatal(err)
	}
	mutations := plan.Mutations()
	if len(mutations) != 3 {
		t.Fatalf("mutations = %+v, want write deny and separate read/write allows", mutations)
	}
	if mutations[0].ACE().Type != ACEDeny || mutations[0].ACE().Access != ACLWrite {
		t.Fatalf("first ACE = %+v, want carveout write deny", mutations[0].ACE())
	}
	if mutations[1].ACE().Access != ACLRead || mutations[2].ACE().Access != ACLWrite {
		t.Fatalf("allow axes not separated: %+v", mutations)
	}
	for _, mutation := range mutations[1:] {
		if mutation.Object() != root || mutation.ACE().Type != ACEAllow || !mutation.ACE().Inheritable {
			t.Fatalf("root inherited allow = %+v", mutation)
		}
	}

	firstBytes := mutations[0].ACE().Bytes
	firstBytes[0] ^= 0xff
	if plan.Mutations()[0].ACE().Bytes[0] == firstBytes[0] {
		t.Fatal("plan ACE bytes are mutable through an accessor")
	}
}

func TestACLPlanPinsExactWindowsACEBytesAndRollbackHash(t *testing.T) {
	sid, _ := ExecutorSID("install", "executor")
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLRead,
		Root: testIdentity(1, ACLObjectDirectory, 1),
	})
	if err != nil {
		t.Fatal(err)
	}
	mutation := plan.Mutations()[0]
	ace := mutation.ACE()
	wantLength := 8 + len(sid.binary())
	if ace.Bytes[0] != 0 || ace.Bytes[1] != 0x03 {
		t.Fatalf("ACE type/flags = %02x/%02x, want allow/OI|CI", ace.Bytes[0], ace.Bytes[1])
	}
	if got := int(binary.LittleEndian.Uint16(ace.Bytes[2:4])); got != wantLength || len(ace.Bytes) != wantLength {
		t.Fatalf("ACE length field/length = %d/%d, want %d", got, len(ace.Bytes), wantLength)
	}
	if got := binary.LittleEndian.Uint32(ace.Bytes[4:8]); got != 0x00120089 {
		t.Fatalf("ACE mask = %#08x, want FILE_GENERIC_READ", got)
	}
	if got := ace.Bytes[8:]; !bytesEqual(got, sid.binary()) {
		t.Fatalf("ACE SID bytes = %x, want %x", got, sid.binary())
	}
	wantHash := sha256.Sum256(ace.Bytes)
	if rollback := mutation.Rollback(); rollback.LeaseID != testLeaseID() || rollback.Role != ACERoleRestrictingAllow || rollback.SID != sid || rollback.ACEHash != wantHash {
		t.Fatalf("rollback = %+v, want SID and exact ACE hash", rollback)
	}
}

func TestACLPlanPinsWindowsFileAccessMasks(t *testing.T) {
	for name, test := range map[string]struct {
		access ACLAccess
		mask   uint32
	}{
		"read":    {ACLRead, 0x00120089},
		"execute": {ACLExecute, 0x001200a0},
		"write":   {ACLWrite, 0x00130116},
	} {
		t.Run(name, func(t *testing.T) {
			if got := windowsFileAccessMask(test.access, ACLObjectFile); got != test.mask {
				t.Fatalf("mask = %#08x, want %#08x", got, test.mask)
			}
		})
	}
	if got := windowsFileAccessMask(ACLWrite, ACLObjectDirectory); got != 0x00130156 {
		t.Fatalf("directory write mask = %#08x, want DELETE|FILE_DELETE_CHILD", got)
	}
}

func TestACLRollbackRoleVocabularyIsStable(t *testing.T) {
	want := []ACERole{
		ACERoleUnknown,
		ACERoleRestrictingAllow,
		ACERoleRestrictingDeny,
		ACERoleAccountNormal,
	}
	for index, role := range want {
		if role != ACERole(index) {
			t.Fatalf("ACE role %d = %d", index, role)
		}
	}
}

func bytesEqual(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func TestACLPlanSkipsReparseTraversal(t *testing.T) {
	sid, _ := ExecutorSID("install", "executor")
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLRead,
		Root: testIdentity(1, ACLObjectDirectory, 1),
		Entries: []ACLPlanEntry{
			{Object: testIdentity(2, ACLObjectReparsePoint, 1), Deny: ACLRead},
			{Object: testIdentity(3, ACLObjectFile, 1)},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.SkippedReparsePoints(); len(got) != 1 || got[0].FileID[15] != 2 {
		t.Fatalf("skipped reparses = %+v", got)
	}
	for _, mutation := range plan.Mutations() {
		if mutation.Object().Kind == ACLObjectReparsePoint {
			t.Fatalf("plan traversed reparse object: %+v", mutation)
		}
	}
}

func TestACLPlanExactMultiLinkIsUnsupported(t *testing.T) {
	sid, _ := ExecutorSID("install", "executor")
	_, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeExact, Access: ACLRead,
		Root: testIdentity(1, ACLObjectFile, 2),
	})
	if !errors.Is(err, policy.ErrUnsupportedClass) {
		t.Fatalf("error = %v, want ErrGrantUnsupported identity", err)
	}
}

func TestACLPlanTreeMultiLinkDeniesAndRecordsNarrowing(t *testing.T) {
	sid, _ := ExecutorSID("install", "executor")
	hardlink := testIdentity(2, ACLObjectFile, 2)
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLRead | ACLWrite,
		Root:    testIdentity(1, ACLObjectDirectory, 1),
		Entries: []ACLPlanEntry{{Object: hardlink}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Narrowings(); len(got) != 1 || got[0] != "windows.filesystem.hardlink" {
		t.Fatalf("narrowings = %v", got)
	}
	mutations := plan.Mutations()
	if len(mutations) != 4 {
		t.Fatalf("mutations = %+v, want two hard-link denies and two root allows", mutations)
	}
	for index, axis := range []ACLAccess{ACLRead, ACLWrite} {
		ace := mutations[index].ACE()
		if mutations[index].Object() != hardlink || ace.Type != ACEDeny || ace.Access != axis {
			t.Fatalf("hard-link mutation %d = %+v", index, mutations[index])
		}
	}
}

func TestACLPlanRejectsUnboundOrWrongShapeRoots(t *testing.T) {
	sid, _ := ExecutorSID("install", "executor")
	for name, request := range map[string]ACLPlanRequest{
		"zero lease":      {SID: sid, Scope: ACLScopeExact, Access: ACLRead, Root: testIdentity(1, ACLObjectFile, 1)},
		"zero identity":   {LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeExact, Access: ACLRead},
		"exact directory": {LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeExact, Access: ACLRead, Root: testIdentity(1, ACLObjectDirectory, 1)},
		"tree file":       {LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLRead, Root: testIdentity(1, ACLObjectFile, 1)},
		"reparse root":    {LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLRead, Root: testIdentity(1, ACLObjectReparsePoint, 1)},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := BuildACLPlan(request); err == nil {
				t.Fatal("invalid request accepted")
			}
		})
	}
}

func TestACLPlanRetainsSortedIdentityReadbackTargets(t *testing.T) {
	sid, _ := ExecutorSID("install", "executor")
	root := testIdentity(3, ACLObjectDirectory, 1)
	ordinary := testIdentity(2, ACLObjectFile, 1)
	protected := testIdentity(1, ACLObjectDirectory, 1)
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLRead | ACLWrite,
		Root:    root,
		Entries: []ACLPlanEntry{{Object: ordinary}, {Object: protected, Deny: ACLWrite}},
	})
	if err != nil {
		t.Fatal(err)
	}
	targets := plan.ValidationTargets()
	if len(targets) != 3 || targets[0].Object != protected || targets[1].Object != ordinary || targets[2].Object != root {
		t.Fatalf("validation targets not complete/sorted: %+v", targets)
	}
	if len(targets[1].Required) != 2 || targets[1].Required[0].Role != ACERoleRestrictingAllow || !targets[1].Required[0].Inherited {
		t.Fatalf("ordinary inherited requirements = %+v", targets[1].Required)
	}
	if len(targets[0].Required) != 3 || targets[0].Required[0].Role != ACERoleRestrictingDeny {
		t.Fatalf("protected requirements = %+v", targets[0].Required)
	}
	targets[0].Required[0].SID = SID{text: "mutated", kind: sidKindExecutor}
	if plan.ValidationTargets()[0].Required[0].SID != sid {
		t.Fatal("validation requirements mutable through accessor")
	}
}

func TestACLPlanRejectsInconsistentReparseShape(t *testing.T) {
	sid, _ := ExecutorSID("install", "executor")
	ordinaryWithTag := testIdentity(2, ACLObjectFile, 1)
	ordinaryWithTag.ReparseTag = 0xa000000c
	reparseWithoutTag := testIdentity(3, ACLObjectReparsePoint, 1)
	reparseWithoutTag.ReparseTag = 0
	for name, object := range map[string]ACLObjectIdentity{
		"ordinary with tag":   ordinaryWithTag,
		"reparse without tag": reparseWithoutTag,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := BuildACLPlan(ACLPlanRequest{
				LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLRead,
				Root: testIdentity(1, ACLObjectDirectory, 1), Entries: []ACLPlanEntry{{Object: object}},
			})
			if err == nil {
				t.Fatal("inconsistent reparse identity accepted")
			}
		})
	}
}
