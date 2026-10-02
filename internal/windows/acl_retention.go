package windows

import "strings"

// ACLTreeEntry is one deterministic, no-follow enumeration result. Reparse
// entries are represented for planning and audit, but never retained or
// traversed. RelativePath is descriptive only and is never used for mutation.
type ACLTreeEntry struct {
	Object       ACLObjectIdentity
	RelativePath string
}

// aclIdentityKey is an object's identity without the fields that may change
// while the object itself does not (link count) or that only a no-follow
// open reports (reparse tag): volume serial, 128-bit file ID and kind.
type aclIdentityKey struct {
	volume uint64
	fileID [16]byte
	kind   ACLObjectKind
}

func identityKey(identity ACLObjectIdentity) aclIdentityKey {
	return aclIdentityKey{volume: identity.VolumeSerial, fileID: identity.FileID, kind: identity.Kind}
}

// planPinnedACLTreeObjects decides which objects of a restricted tree
// projection keep a no-delete-sharing handle for the whole lease (review
// M16). Before this, every enumerated object kept one, so for the executor's
// lifetime nothing in the workspace could be deleted or renamed by anyone
// (git checkout, atomic saves and build outputs all broke), and a compile
// failed whenever any file was open for writing elsewhere.
//
// The exclusion is load-bearing for exactly one threat: renaming or deleting
// an object that carries a deny ACE and then recreating its name, which
// would give the new object the root's inherited allow — a write through the
// carveout's path. The pinned set is therefore:
//
//   - the projected root itself (it carries the lease's inheritable allows);
//   - every object the plan puts a deny ACE on (carveouts, and multi-link
//     files denied as windows.filesystem.hardlink); and
//   - every directory between the root and such an object, because renaming
//     an ancestor moves the carveout (deny intact) out from under its policy
//     path and lets the old path be recreated beneath the root's allow.
//
// Every other object — the ordinary, allow-by-inheritance majority — is
// retained only until its read-back has been checked and is then released,
// so it stays freely renameable and deletable. Relative paths come from one
// enumeration, which builds each child's path as parent + `\` + name, so an
// ancestor's path is an exact byte prefix of its descendants' and plain
// string matching is sufficient here.
func planPinnedACLTreeObjects(root ACLObjectIdentity, entries []ACLTreeEntry, plan ACLPlan) map[aclIdentityKey]struct{} {
	pinned := map[aclIdentityKey]struct{}{identityKey(root): {}}
	denied := make(map[aclIdentityKey]struct{})
	for _, mutation := range plan.Mutations() {
		if mutation.ACE().Type == ACEDeny {
			denied[identityKey(mutation.Object())] = struct{}{}
		}
	}
	byPath := make(map[string]ACLObjectIdentity, len(entries))
	for _, entry := range entries {
		byPath[entry.RelativePath] = entry.Object
	}
	for _, entry := range entries {
		if _, ok := denied[identityKey(entry.Object)]; !ok {
			continue
		}
		pinned[identityKey(entry.Object)] = struct{}{}
		for ancestor := entry.RelativePath; ; {
			separator := strings.LastIndexByte(ancestor, '\\')
			if separator <= 0 {
				break
			}
			ancestor = ancestor[:separator]
			if object, ok := byPath[ancestor]; ok && object.Kind == ACLObjectDirectory {
				pinned[identityKey(object)] = struct{}{}
			}
		}
	}
	return pinned
}
