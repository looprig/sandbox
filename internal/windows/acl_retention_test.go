package windows

import "testing"

// TestPlanPinnedACLTreeObjectsPinsOnlyRootCarveoutsAndTheirAncestors pins
// M16's retention rule on a tree shaped like a real workspace:
//
//	root\
//	  src\            (ordinary)
//	    main.go       (ordinary)
//	  secrets\        (ancestor of a carveout)
//	    nested\       (ancestor of a carveout)
//	      key.pem     (write-denied carveout)
//	  .git\           (write-denied carveout directory)
//	    index         (write-denied: inherits the carveout's resolved deny)
//	  linked.txt      (multi-link file: denied as windows.filesystem.hardlink)
//	  link\           (reparse point: never retained)
func TestPlanPinnedACLTreeObjectsPinsOnlyRootCarveoutsAndTheirAncestors(t *testing.T) {
	sid, err := ExecutorSID("install", "executor")
	if err != nil {
		t.Fatal(err)
	}
	root := testIdentity(1, ACLObjectDirectory, 1)
	src := testIdentity(2, ACLObjectDirectory, 1)
	main := testIdentity(3, ACLObjectFile, 1)
	secrets := testIdentity(4, ACLObjectDirectory, 1)
	nested := testIdentity(5, ACLObjectDirectory, 1)
	key := testIdentity(6, ACLObjectFile, 1)
	git := testIdentity(7, ACLObjectDirectory, 1)
	index := testIdentity(8, ACLObjectFile, 1)
	linked := testIdentity(9, ACLObjectFile, 2)
	link := testIdentity(10, ACLObjectReparsePoint, 1)
	entries := []ACLTreeEntry{
		{Object: src, RelativePath: `src`},
		{Object: main, RelativePath: `src\main.go`},
		{Object: secrets, RelativePath: `secrets`},
		{Object: nested, RelativePath: `secrets\nested`},
		{Object: key, RelativePath: `secrets\nested\key.pem`},
		{Object: git, RelativePath: `.git`},
		{Object: index, RelativePath: `.git\index`},
		{Object: linked, RelativePath: `linked.txt`},
		{Object: link, RelativePath: `link`},
	}
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLWrite, Root: root,
		Entries: []ACLPlanEntry{
			{Object: src}, {Object: main}, {Object: secrets}, {Object: nested},
			{Object: key, Deny: ACLWrite}, {Object: git, Deny: ACLWrite}, {Object: index, Deny: ACLWrite},
			{Object: linked}, {Object: link},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	pinned := planPinnedACLTreeObjects(root, entries, plan)
	want := map[string]ACLObjectIdentity{
		"root": root, "secrets": secrets, "nested": nested, "key": key,
		".git": git, "index": index, "linked": linked,
	}
	for name, object := range want {
		if _, ok := pinned[identityKey(object)]; !ok {
			t.Errorf("%s is not pinned", name)
		}
	}
	for name, object := range map[string]ACLObjectIdentity{"src": src, "main.go": main, "link": link} {
		if _, ok := pinned[identityKey(object)]; ok {
			t.Errorf("%s is pinned although it carries no deny and holds none beneath it", name)
		}
	}
	if len(pinned) != len(want) {
		t.Fatalf("pinned %d objects, want %d", len(pinned), len(want))
	}
}

// TestPlanPinnedACLTreeObjectsWithoutCarveoutsPinsOnlyTheRoot: an ordinary
// workspace with no denies keeps exactly one no-delete-sharing handle.
func TestPlanPinnedACLTreeObjectsWithoutCarveoutsPinsOnlyTheRoot(t *testing.T) {
	sid, _ := ExecutorSID("install", "executor")
	root := testIdentity(1, ACLObjectDirectory, 1)
	file := testIdentity(2, ACLObjectFile, 1)
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLWrite, Root: root,
		Entries: []ACLPlanEntry{{Object: file}},
	})
	if err != nil {
		t.Fatal(err)
	}
	pinned := planPinnedACLTreeObjects(root, []ACLTreeEntry{{Object: file, RelativePath: "file.txt"}}, plan)
	if _, ok := pinned[identityKey(root)]; !ok || len(pinned) != 1 {
		t.Fatalf("pinned = %v, want only the root", pinned)
	}
}
