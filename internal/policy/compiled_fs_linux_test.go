//go:build linux

package policy

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
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

func TestEnumeratedDirectFileRuleRetainsCheckedInodeAcrossPathSwap(t *testing.T) {
	root := t.TempDir()
	public := filepath.Join(root, "public")
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(public, []byte("checked-public"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("unchecked-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	compiled := CompileFS([]FSEntry{
		{Path: root, Access: AllAccess},
		{Path: secret, Denied: AllAccess},
	})
	rules, files, err := EnumerateFSRulesWithPathHandles(compiled, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer CloseRuleFiles(files)

	var publicRule *FSRule
	for index := range rules {
		rule := &rules[index]
		if rule.Target == public {
			publicRule = rule
		}
		if rule.Path == public {
			t.Fatalf("direct regular-file rule remained pathname-backed: %+v", *rule)
		}
	}
	if publicRule == nil {
		t.Fatalf("rules = %+v, want retained public file rule", rules)
	}
	if publicRule.ParentFD != FirstPathHandleChildFD || publicRule.Access != AllAccess {
		t.Fatalf("public rule = %+v, want merged all-access child FD %d", *publicRule, FirstPathHandleChildFD)
	}
	if len(files) != 1 {
		t.Fatalf("retained rule files = %d, want one reused across access axes", len(files))
	}

	moved := filepath.Join(root, "moved-public")
	if err := os.Rename(public, moved); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(secret, public); err != nil {
		t.Fatal(err)
	}
	checked, err := os.ReadFile("/proc/self/fd/" + strconv.Itoa(int(files[0].Fd())))
	if err != nil {
		t.Fatal(err)
	}
	if string(checked) != "checked-public" {
		t.Fatalf("retained rule FD names %q, want checked-public inode", checked)
	}
	current, err := os.ReadFile(public)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != "unchecked-secret" {
		t.Fatalf("swapped pathname contains %q, want unchecked-secret test fixture", current)
	}

	CloseRuleFiles(files)
	if _, err := files[0].Stat(); err == nil {
		t.Fatal("retained direct rule FD remained open after cleanup")
	}
	files = nil
}

func TestEnumeratedDirectFileRuleRejectsSwapBeforeRetain(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	moved := filepath.Join(root, "moved")
	if err := os.WriteFile(target, []byte("inspected"), 0o600); err != nil {
		t.Fatal(err)
	}
	resolver := NewPinnedPathResolver(nil, FirstPathHandleChildFD)
	var opened *os.File
	resolver.openDirect = func(path string) (*os.File, error) {
		if err := os.Rename(path, moved); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
			return nil, err
		}
		file, err := openDirectRuleFile(path)
		opened = file
		return file, err
	}

	rules, files, err := enumerateFSRulesWithResolver(CompiledFS{Allows: []FSAllow{{
		Path: target, Access: ReadAccess,
	}}}, nil, resolver)
	if !errors.Is(err, ErrTargetChanged) {
		t.Fatalf("error = %v, want ErrTargetChanged", err)
	}
	if rules != nil || files != nil {
		t.Fatalf("error result rules=%+v files=%v, want nil outputs", rules, files)
	}
	if opened == nil {
		t.Fatal("replacement file was not opened")
	}
	if _, err := opened.Stat(); err == nil {
		t.Fatal("mismatched replacement descriptor remained open")
	}
}

func TestEnumeratedDirectFileRuleFDStartsAfterGrantHandles(t *testing.T) {
	root := t.TempDir()
	handleRoot := filepath.Join(root, "handle-root")
	if err := os.Mkdir(handleRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	direct := filepath.Join(root, "direct")
	if err := os.WriteFile(direct, []byte("direct"), 0o600); err != nil {
		t.Fatal(err)
	}
	binding, err := CapturePathBinding(handleRoot)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := AcquirePathHandle(&binding, handleRoot, false)
	if err != nil {
		t.Fatal(err)
	}
	defer handle.Close()

	compiled := CompileFSWithPathHandles([]FSEntry{
		{Path: direct, Access: AllAccess, Exact: true},
	}, []*PathHandle{handle})
	rules, files, err := EnumerateFSRulesWithPathHandles(compiled, []*PathHandle{handle})
	if err != nil {
		t.Fatal(err)
	}
	defer CloseRuleFiles(files)
	if len(rules) != 1 || len(files) != 1 {
		t.Fatalf("rules=%+v files=%d, want one merged rule and one retained file", rules, len(files))
	}
	if rules[0].Target != direct || rules[0].Path != "" ||
		rules[0].ParentFD != FirstPathHandleChildFD+1 || rules[0].Access != AllAccess {
		t.Fatalf("direct rule=%+v, want FD %d after one grant handle", rules[0], FirstPathHandleChildFD+1)
	}
}

func TestEnumerateDirectFileErrorClosesAlreadyRetainedFiles(t *testing.T) {
	root := t.TempDir()
	good := filepath.Join(root, "good")
	bad := filepath.Join(root, "bad")
	for _, path := range []string{good, bad} {
		if err := os.WriteFile(path, []byte(filepath.Base(path)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	closed, err := os.Open(bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	resolver := NewPinnedPathResolver(nil, FirstPathHandleChildFD)
	resolver.direct[bad] = PinnedPathResolution{
		File: closed, ChildFD: FirstPathHandleChildFD + 1,
	}
	compiled := CompiledFS{Allows: []FSAllow{
		{Path: good, Access: ReadAccess},
		{Path: bad, Access: ReadAccess},
	}}

	rules, files, err := enumerateFSRulesWithResolver(compiled, nil, resolver)
	if !errors.Is(err, ErrUnsupportedClass) {
		t.Fatalf("error = %v, want ErrUnsupportedClass", err)
	}
	if rules != nil || files != nil {
		t.Fatalf("error result rules=%+v files=%v, want nil outputs", rules, files)
	}
	retained, ok := resolver.direct[good]
	if !ok {
		t.Fatal("good file was not retained before the injected cached-FD error")
	}
	if _, err := retained.File.Stat(); err == nil {
		t.Fatal("already-retained file remained open after enumeration error")
	}
}

func TestEnumerateDirectNonRegularFileFailsNarrow(t *testing.T) {
	target := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(target, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	rules, files, err := EnumerateFSRulesWithPathHandles(CompiledFS{Allows: []FSAllow{{
		Path: target, Access: AllAccess,
	}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer CloseRuleFiles(files)
	if len(rules) != 0 || len(files) != 0 {
		t.Fatalf("non-regular direct path produced rules=%+v files=%d, want fail-narrow omission", rules, len(files))
	}
}

func TestEnumeratePinnedTreeOmitsNonRegularDirectNode(t *testing.T) {
	root := t.TempDir()
	fifo := filepath.Join(root, "fifo")
	denied := filepath.Join(root, "denied")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	if err := os.WriteFile(denied, []byte("denied"), 0o600); err != nil {
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
		{Path: root, Access: AllAccess},
		{Path: denied, Denied: AllAccess},
	}, []*PathHandle{handle})
	rules, files, err := EnumerateFSRulesWithPathHandles(compiled, []*PathHandle{handle})
	if err != nil {
		t.Fatal(err)
	}
	defer CloseRuleFiles(files)
	for _, rule := range rules {
		if rule.Target == fifo {
			t.Fatalf("pinned non-regular direct node received a rule: %+v; rules=%+v", rule, rules)
		}
	}
}

func TestValidateLandlockExactPathsRejectsNonRegularFile(t *testing.T) {
	target := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(target, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	err := ValidateLandlockExactPaths([]FSEntry{{
		Path: target, Access: ReadAccess, Exact: true, Canonical: true,
	}}, nil)
	if !errors.Is(err, ErrUnsupportedClass) {
		t.Fatalf("error = %v, want ErrUnsupportedClass", err)
	}
}
