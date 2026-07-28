//go:build linux

package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnumeratePinnedFSRulesPreservesDescendantsOfEqualPathExactDeny(t *testing.T) {
	root := t.TempDir()
	child := filepath.Join(root, "child")
	if err := os.Mkdir(child, 0o700); err != nil {
		t.Fatal(err)
	}
	leaf := filepath.Join(child, "leaf")
	if err := os.WriteFile(leaf, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	binding, err := CapturePathBinding(root)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := AcquirePathHandle(&binding, root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	compiled := CompileFSWithPathHandles([]FSEntry{
		{Path: root, Access: AllAccess, Canonical: true},
		{Path: root, Denied: AllAccess, Exact: true, Canonical: true},
	}, []*PathHandle{handle})
	rules, files, err := EnumerateFSRulesWithPathHandles(compiled, []*PathHandle{handle})
	if err != nil {
		t.Fatal(err)
	}
	defer CloseRuleFiles(files)

	var childRule *FSRule
	for index := range rules {
		rule := &rules[index]
		if rule.Target == root {
			t.Fatalf("exactly denied pinned root received rule: %+v", *rule)
		}
		if rule.Target == child {
			childRule = rule
		}
	}
	if childRule == nil || childRule.ParentFD <= FirstPathHandleChildFD || childRule.Access != AllAccess || !childRule.IsDir {
		t.Fatalf("pinned child rule = %+v, want full directory rule via enumerated child FD; rules=%+v", childRule, rules)
	}
}

func TestEnumeratePinnedFSRulesDerivesWriteDenyAcrossRecursiveReadDeny(t *testing.T) {
	root := t.TempDir()
	denied := filepath.Join(root, "denied")
	restored := filepath.Join(denied, "source")
	if err := os.Mkdir(denied, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(restored, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	binding, err := CapturePathBinding(root)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := AcquirePathHandle(&binding, root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	compiled := CompileFSWithPathHandles([]FSEntry{
		{Path: root, Access: AllAccess, Canonical: true},
		{Path: denied, Denied: ReadAccess | ExecAccess},
		{Path: restored, Access: ReadAccess | ExecAccess, Exact: true, Canonical: true},
	}, []*PathHandle{handle})
	rules, files, err := EnumerateFSRulesWithPathHandles(compiled, []*PathHandle{handle})
	if err != nil {
		t.Fatal(err)
	}
	defer CloseRuleFiles(files)

	var restoredAccess FSAccess
	for _, rule := range rules {
		if rule.Target == denied && rule.Access&WriteAccess != 0 {
			t.Fatalf("pinned recursive denied scope received topology write: %+v", rule)
		}
		if rule.Target == restored {
			restoredAccess |= rule.Access
		}
	}
	if restoredAccess != ReadAccess|ExecAccess {
		t.Fatalf("pinned restored source access = %#x, want read+execute without write; rules=%+v", restoredAccess, rules)
	}
}
