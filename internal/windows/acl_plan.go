package windows

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"

	"github.com/looprig/sandbox/internal/policy"
)

type ACLObjectKind uint8

const (
	ACLObjectUnknown ACLObjectKind = iota
	ACLObjectFile
	ACLObjectDirectory
	ACLObjectReparsePoint
)

// ACLObjectIdentity is the complete identity required to verify an object
// again immediately before mutation. A path string is deliberately absent.
type ACLObjectIdentity struct {
	VolumeSerial uint64
	FileID       [16]byte
	Kind         ACLObjectKind
	ReparseTag   uint32
	LinkCount    uint32
}

func (identity ACLObjectIdentity) valid() bool {
	// Volume serials and 128-bit file IDs are opaque values; zero is not used
	// as an absence sentinel because the filesystem owns their value space.
	if identity.LinkCount == 0 {
		return false
	}
	switch identity.Kind {
	case ACLObjectReparsePoint:
		return identity.ReparseTag != 0
	case ACLObjectFile, ACLObjectDirectory:
		return identity.ReparseTag == 0
	default:
		return false
	}
}

type ACLLeaseID [16]byte

type ACLScope uint8

const (
	ACLScopeUnknown ACLScope = iota
	ACLScopeExact
	ACLScopeTree
)

type ACLAccess uint8

const (
	ACLRead ACLAccess = 1 << iota
	ACLExecute
	ACLWrite
)

const aclAllAccess = ACLRead | ACLExecute | ACLWrite

type ACLPlanEntry struct {
	Object ACLObjectIdentity
	Deny   ACLAccess
}

// ACLPlanRequest consumes an already no-follow-enumerated object set. Planning
// performs no filesystem traversal and skips every reparse entry.
type ACLPlanRequest struct {
	LeaseID ACLLeaseID
	SID     SID
	Scope   ACLScope
	Access  ACLAccess
	Root    ACLObjectIdentity
	Entries []ACLPlanEntry
}

type ACEType uint8

const (
	ACEAllow ACEType = iota
	ACEDeny
)

type ACLACE struct {
	Type        ACEType
	Access      ACLAccess
	Inheritable bool
	Bytes       []byte
}

type ACERole uint8

const (
	ACERoleUnknown ACERole = iota
	ACERoleRestrictingAllow
	ACERoleRestrictingDeny
	ACERoleAccountNormal
)

// ACLRollbackMetadata identifies one lease-owned ACE without assuming it was
// absent before apply. Task 10 must capture the baseline occurrence count of
// identical ACE bytes atomically with read/apply; rollback removes only the
// lease's added occurrence above that baseline.
type ACLRollbackMetadata struct {
	LeaseID ACLLeaseID
	Role    ACERole
	SID     SID
	ACEHash [sha256.Size]byte
}

// ACLACEExpectation describes an ACE that read-back must find logically. An
// inherited ACE's raw header is produced by Windows, so it is matched by role,
// SID, access, and inheritance rather than by pretending its bytes are stable.
type ACLACEExpectation struct {
	Role      ACERole
	SID       SID
	Access    ACLAccess
	Inherited bool
}

type ACLValidationTarget struct {
	Object   ACLObjectIdentity
	Required []ACLACEExpectation
}

type ACLMutation struct {
	object   ACLObjectIdentity
	ace      ACLACE
	rollback ACLRollbackMetadata
}

func (mutation ACLMutation) Object() ACLObjectIdentity { return mutation.object }
func (mutation ACLMutation) ACE() ACLACE               { return cloneACE(mutation.ace) }
func (mutation ACLMutation) Rollback() ACLRollbackMetadata {
	return mutation.rollback
}

// ACLPlan is immutable after construction. Every slice-returning accessor
// returns a defensive copy so journal/apply code cannot accidentally alter it.
type ACLPlan struct {
	sid       SID
	mutations []ACLMutation
	skipped   []ACLObjectIdentity
	narrowing []string
	targets   []ACLValidationTarget
}

func (plan ACLPlan) SID() SID { return plan.sid }

func (plan ACLPlan) Mutations() []ACLMutation {
	result := make([]ACLMutation, len(plan.mutations))
	for index, mutation := range plan.mutations {
		result[index] = mutation
		result[index].ace = cloneACE(mutation.ace)
	}
	return result
}

func (plan ACLPlan) SkippedReparsePoints() []ACLObjectIdentity {
	return append([]ACLObjectIdentity(nil), plan.skipped...)
}

func (plan ACLPlan) Narrowings() []string { return append([]string(nil), plan.narrowing...) }

// ValidationTargets retains every ordinary identity enumerated for the plan,
// even when it needs no explicit mutation. Task 10 pairs each target with its
// retained OS handle by complete identity and verifies inherited propagation.
func (plan ACLPlan) ValidationTargets() []ACLValidationTarget {
	result := make([]ACLValidationTarget, len(plan.targets))
	for index, target := range plan.targets {
		result[index] = target
		result[index].Required = append([]ACLACEExpectation(nil), target.Required...)
	}
	return result
}

func cloneACE(ace ACLACE) ACLACE {
	ace.Bytes = append([]byte(nil), ace.Bytes...)
	return ace
}

func BuildACLPlan(request ACLPlanRequest) (ACLPlan, error) {
	if request.LeaseID == (ACLLeaseID{}) {
		return ACLPlan{}, errors.New("sandbox: ACL projection lease identity is required")
	}
	if len(request.SID.binary()) == 0 {
		return ACLPlan{}, errors.New("sandbox: invalid ACL projection SID")
	}
	if !request.Root.valid() || request.Access == 0 || request.Access&^aclAllAccess != 0 {
		return ACLPlan{}, errors.New("sandbox: invalid identity-bound ACL plan request")
	}
	if request.Root.Kind == ACLObjectReparsePoint {
		return ACLPlan{}, fmt.Errorf("%w: ACL projection root is a reparse point", policy.ErrUnsupportedClass)
	}
	switch request.Scope {
	case ACLScopeExact:
		return buildExactACLPlan(request)
	case ACLScopeTree:
		return buildTreeACLPlan(request)
	default:
		return ACLPlan{}, errors.New("sandbox: invalid ACL projection scope")
	}
}

func buildExactACLPlan(request ACLPlanRequest) (ACLPlan, error) {
	if request.Root.Kind != ACLObjectFile || len(request.Entries) != 0 {
		return ACLPlan{}, fmt.Errorf("%w: exact ACL grant requires one existing regular file", policy.ErrUnsupportedClass)
	}
	if request.Root.LinkCount > 1 {
		return ACLPlan{}, fmt.Errorf("%w: exact ACL grant names a multi-link file", policy.ErrUnsupportedClass)
	}
	plan := ACLPlan{sid: request.SID}
	for _, axis := range splitAccess(request.Access) {
		plan.appendMutation(request.LeaseID, request.Root, ACEAllow, axis, false)
	}
	plan.targets = append(plan.targets, ACLValidationTarget{
		Object: request.Root, Required: allowExpectations(request.SID, request.Access, false),
	})
	return plan, nil
}

func buildTreeACLPlan(request ACLPlanRequest) (ACLPlan, error) {
	if request.Root.Kind != ACLObjectDirectory {
		return ACLPlan{}, fmt.Errorf("%w: tree ACL grant requires an existing directory", policy.ErrUnsupportedClass)
	}
	plan := ACLPlan{sid: request.SID}
	entries := append([]ACLPlanEntry(nil), request.Entries...)
	slices.SortFunc(entries, func(left, right ACLPlanEntry) int {
		return compareACLIdentity(left.Object, right.Object)
	})
	type objectKey struct {
		volume uint64
		fileID [16]byte
		kind   ACLObjectKind
	}
	key := func(object ACLObjectIdentity) objectKey {
		return objectKey{volume: object.VolumeSerial, fileID: object.FileID, kind: object.Kind}
	}
	seen := make(map[objectKey]struct{}, len(entries)+1)
	seen[key(request.Root)] = struct{}{}
	for _, entry := range entries {
		if !entry.Object.valid() || entry.Deny&^aclAllAccess != 0 {
			return ACLPlan{}, errors.New("sandbox: invalid enumerated ACL object")
		}
		if _, duplicate := seen[key(entry.Object)]; duplicate {
			return ACLPlan{}, errors.New("sandbox: duplicate enumerated ACL object identity")
		}
		seen[key(entry.Object)] = struct{}{}
		if entry.Object.Kind == ACLObjectReparsePoint {
			plan.skipped = append(plan.skipped, entry.Object)
			continue
		}
		deny := entry.Deny & request.Access
		if entry.Object.Kind == ACLObjectFile && entry.Object.LinkCount > 1 {
			deny |= request.Access
			if len(plan.narrowing) == 0 {
				plan.narrowing = append(plan.narrowing, "windows.filesystem.hardlink")
			}
		}
		for _, axis := range splitAccess(deny) {
			plan.appendMutation(request.LeaseID, entry.Object, ACEDeny, axis, entry.Object.Kind == ACLObjectDirectory)
		}
		required := denyExpectations(request.SID, deny)
		required = append(required, allowExpectations(request.SID, request.Access, true)...)
		plan.targets = append(plan.targets, ACLValidationTarget{Object: entry.Object, Required: required})
	}
	// Explicit denies precede the inheritable root allows in canonical DACL
	// order. Read/execute/write remain separate so a lease can remove one axis.
	for _, axis := range splitAccess(request.Access) {
		plan.appendMutation(request.LeaseID, request.Root, ACEAllow, axis, true)
	}
	plan.targets = append(plan.targets, ACLValidationTarget{
		Object: request.Root, Required: allowExpectations(request.SID, request.Access, false),
	})
	slices.SortFunc(plan.targets, func(left, right ACLValidationTarget) int {
		return compareACLIdentity(left.Object, right.Object)
	})
	return plan, nil
}

func allowExpectations(sid SID, access ACLAccess, inherited bool) []ACLACEExpectation {
	result := make([]ACLACEExpectation, 0, 3)
	for _, axis := range splitAccess(access) {
		result = append(result, ACLACEExpectation{Role: ACERoleRestrictingAllow, SID: sid, Access: axis, Inherited: inherited})
	}
	return result
}

func denyExpectations(sid SID, access ACLAccess) []ACLACEExpectation {
	result := make([]ACLACEExpectation, 0, 3)
	for _, axis := range splitAccess(access) {
		result = append(result, ACLACEExpectation{Role: ACERoleRestrictingDeny, SID: sid, Access: axis})
	}
	return result
}

func splitAccess(access ACLAccess) []ACLAccess {
	result := make([]ACLAccess, 0, 3)
	for _, axis := range []ACLAccess{ACLRead, ACLExecute, ACLWrite} {
		if access&axis != 0 {
			result = append(result, axis)
		}
	}
	return result
}

func compareACLIdentity(left, right ACLObjectIdentity) int {
	if left.VolumeSerial < right.VolumeSerial {
		return -1
	}
	if left.VolumeSerial > right.VolumeSerial {
		return 1
	}
	if comparison := slices.Compare(left.FileID[:], right.FileID[:]); comparison != 0 {
		return comparison
	}
	if left.Kind < right.Kind {
		return -1
	}
	if left.Kind > right.Kind {
		return 1
	}
	return 0
}

func (plan *ACLPlan) appendMutation(leaseID ACLLeaseID, object ACLObjectIdentity, aceType ACEType, access ACLAccess, inherited bool) {
	ace := ACLACE{Type: aceType, Access: access, Inheritable: inherited}
	ace.Bytes = encodeACE(plan.sid, object.Kind, ace)
	role := ACERoleRestrictingAllow
	if aceType == ACEDeny {
		role = ACERoleRestrictingDeny
	}
	plan.mutations = append(plan.mutations, ACLMutation{
		object: object,
		ace:    ace,
		rollback: ACLRollbackMetadata{
			LeaseID: leaseID,
			Role:    role,
			SID:     plan.sid,
			ACEHash: sha256.Sum256(ace.Bytes),
		},
	})
}

func encodeACE(sid SID, kind ACLObjectKind, ace ACLACE) []byte {
	sidBytes := sid.binary()
	result := make([]byte, 8+len(sidBytes))
	if ace.Type == ACEDeny {
		result[0] = 1 // ACCESS_DENIED_ACE_TYPE
	}
	if ace.Inheritable {
		result[1] = 0x01 | 0x02 // OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE
	}
	binary.LittleEndian.PutUint16(result[2:4], uint16(len(result)))
	binary.LittleEndian.PutUint32(result[4:8], windowsFileAccessMask(ace.Access, kind))
	copy(result[8:], sidBytes)
	return result
}

func windowsFileAccessMask(access ACLAccess, kind ACLObjectKind) uint32 {
	switch access {
	case ACLRead:
		return 0x00120089 // FILE_GENERIC_READ
	case ACLExecute:
		return 0x001200a0 // FILE_GENERIC_EXECUTE
	case ACLWrite:
		mask := uint32(0x00120116 | 0x00010000) // FILE_GENERIC_WRITE | DELETE
		if kind == ACLObjectDirectory {
			mask |= 0x00000040 // FILE_DELETE_CHILD
		}
		return mask
	default:
		panic("combined ACL axis reached ACE encoder")
	}
}
