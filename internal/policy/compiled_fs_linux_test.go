//go:build linux

package policy

import (
	"errors"
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

func TestEnumeratePinnedFSRulesOmitsDirectHardlinkedFiles(t *testing.T) {
	root := t.TempDir()
	public := filepath.Join(root, "public")
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(public, []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(public, secret); err != nil {
		t.Skipf("hard links unavailable: %v", err)
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
		{Path: secret, Denied: ReadAccess | ExecAccess},
	}, []*PathHandle{handle})
	rules, files, err := EnumerateFSRulesWithPathHandles(compiled, []*PathHandle{handle})
	if err != nil {
		t.Fatal(err)
	}
	defer CloseRuleFiles(files)
	for _, rule := range rules {
		if rule.Target == public || rule.Target == secret {
			t.Fatalf("multiply-linked pinned file received direct rule: %+v; rules=%+v", rule, rules)
		}
	}
}

func TestAcquireExactPathHandleRejectsHardlinkedFile(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	alias := filepath.Join(root, "alias")
	if err := os.WriteFile(target, []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, alias); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	binding, err := CapturePathBinding(target)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := AcquirePathHandle(&binding, target, true)
	if handle != nil {
		_ = handle.Close()
		t.Fatal("exact hardlinked file returned a path handle")
	}
	if !errors.Is(err, ErrUnsupportedClass) {
		t.Fatalf("AcquirePathHandle error = %v, want ErrUnsupportedClass", err)
	}
}
