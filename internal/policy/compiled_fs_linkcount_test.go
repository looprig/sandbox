//go:build darwin || linux

package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The single-link rule these tests pin is a Landlock rule (SPEC §5: an exact
// Landlock grant must name a regular file whose link count is exactly one;
// SPEC §7.5: a directly enumerated regular-file rule is inode-scoped, so a
// multiple-link inode is omitted fail-narrow). Every production path that
// reaches it — ValidateLandlockExactPaths and the spawn-time rule enumeration —
// starts in the Linux backend. directRegularFileRuleSafe reads the count from
// the Lstat result's syscall.Stat_t, which exists on darwin and Linux
// (linkcount_unix.go), so the rule runs — and is tested — there; darwin keeps
// the tests because the policy logic, not the kernel, is what they exercise.
//
// Off those platforms (linkcount_other.go) the predicate reports every file as
// single-link, so these assertions would fail without describing any reachable
// behaviour. Windows in particular cannot answer from an os.FileInfo at all —
// its Sys() is a Win32FileAttributeData with no link count — and it does not
// consume this rule: the Windows backend enforces through handle-identity ACL
// planning, where winpath.Object.LinkCount (FileStandardInfo.NumberOfLinks
// from GetFileInformationByHandleEx on the owned handle) already refuses a
// multiply-linked exact file at path-handle acquisition (pathhandle_windows.go;
// design §10.2-§10.3). Re-opening by path to count links here would add an
// unbound second lookup to a rule no Windows path calls, so the tests are
// scoped to the platforms the rule exists on.

func TestEnumerateFSRulesOmitsDirectHardlinkedFiles(t *testing.T) {
	root := t.TempDir()
	public := filepath.Join(root, "public")
	secret := filepath.Join(root, "secret")
	if err := os.WriteFile(public, []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(public, secret); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	compiled := CompileFS([]FSEntry{
		{Path: root, Access: AllAccess},
		{Path: secret, Denied: ReadAccess | ExecAccess},
	})
	rules := enumerateFSRulesForTest(t, compiled)
	for _, path := range []string{public, secret} {
		if got := resolveEnumeratedRules(rules, path); got != DenyAccess {
			t.Fatalf("hardlinked path %q access = %#x, want fail-narrow deny; rules=%+v", path, got, rules)
		}
	}

	exact := enumerateFSRulesForTest(t, CompileFS([]FSEntry{{
		Path: public, Access: ReadAccess, Exact: true,
	}}))
	if got := resolveEnumeratedRules(exact, public); got != DenyAccess {
		t.Fatalf("direct exact hardlink access = %#x, want fail-narrow deny; rules=%+v", got, exact)
	}
}

// TestValidateLandlockExactPathsRejectsMultiplyLinkedFile is the
// multiply-linked row of TestValidateLandlockExactPaths: an exact Landlock
// grant on an inode reachable by a second name would authorize that other
// name too, so it is ErrUnsupportedClass, never a narrowed or widened grant.
func TestValidateLandlockExactPathsRejectsMultiplyLinkedFile(t *testing.T) {
	root := t.TempDir()
	linkedSource := filepath.Join(root, "linked-source")
	linked := filepath.Join(root, "linked")
	if err := os.WriteFile(linkedSource, []byte("shared"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(linkedSource, linked); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	err := ValidateLandlockExactPaths([]FSEntry{{Path: linked, Access: ReadAccess, Exact: true, Canonical: true}}, nil)
	if !errors.Is(err, ErrUnsupportedClass) {
		t.Fatalf("error = %v, want ErrUnsupportedClass", err)
	}
}
