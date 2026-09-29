//go:build linux

package policy

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestEnumerateFSRulesKeepsDirectCharDeviceGrant pins that a directly named
// character device keeps its Landlock rule. The descriptor-bound file rules
// once admitted only regular files, which silently dropped the backend's own
// NullDevicePath grant: every confined `cmd >/dev/null` then failed with EACCES
// on both Linux rungs. (TestEnumerateDirectNonRegularFileFailsNarrow keeps FIFOs refused.)
func TestEnumerateFSRulesKeepsDirectCharDeviceGrant(t *testing.T) {
	if info, err := os.Stat(NullDevicePath); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		t.Skipf("%s is not a character device here: %v", NullDevicePath, err)
	}
	if fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC}); err != nil {
		t.Skipf("openat2 unavailable (descriptor-bound rules need it): %v", err)
	} else {
		_ = unix.Close(fd)
	}
	compiled := CompileFS([]FSEntry{{Path: NullDevicePath, Access: ReadAccess | WriteAccess, Exact: true}})
	rules, files, err := EnumerateFSRulesWithPathHandles(compiled, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer CloseRuleFiles(files)
	var got FSAccess
	for _, rule := range rules {
		if rule.Target != NullDevicePath {
			continue
		}
		if rule.IsDir || rule.ParentFD == 0 {
			t.Fatalf("rule %+v: want a descriptor-bound file rule", rule)
		}
		got |= rule.Access
	}
	if want := ReadAccess | WriteAccess; got != want {
		t.Fatalf("%s rule access = %v, want %v (rules=%+v)", NullDevicePath, got, want, rules)
	}

}

// TestEnumerateFSRulesCarvesNoCharDevices pins how narrow the device exception
// is. Carving a granted tree around an exclusion (rw /dev with /dev/pts denied)
// emits children through the same direct-rule path; they must keep the
// regular-file-only rule, so no device the policy never named (/dev/kmsg,
// /dev/tty, even /dev/null) gains a rule. An explicit entry for any device
// other than NullDevicePath gets none either.
func TestEnumerateFSRulesCarvesNoCharDevices(t *testing.T) {
	if fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC}); err != nil {
		t.Skipf("openat2 unavailable (descriptor-bound rules need it): %v", err)
	} else {
		_ = unix.Close(fd)
	}
	if _, err := os.Stat("/dev/pts"); err != nil {
		t.Skipf("/dev/pts unavailable: %v", err)
	}
	compiled := CompileFS([]FSEntry{
		{Path: "/dev", Access: ReadAccess | WriteAccess},
		{Path: "/dev/pts", Denied: AllAccess},
	})
	rules, files, err := EnumerateFSRulesWithPathHandles(compiled, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer CloseRuleFiles(files)
	carved := 0
	for _, rule := range rules {
		target := rule.Target
		if target == "" {
			target = rule.Path
		}
		if target == "/dev" {
			t.Fatalf("rule %+v: /dev itself granted despite the /dev/pts exclusion; nothing was carved", rule)
		}
		carved++
		info, err := os.Lstat(target)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeDevice != 0 {
			t.Errorf("carving /dev emitted a rule for device %s (%+v)", target, rule)
		}
	}
	if carved == 0 {
		t.Fatal("carving /dev emitted no rules at all; the check above proves nothing")
	}

	zero := "/dev/zero"
	if info, err := os.Stat(zero); err != nil || info.Mode()&os.ModeCharDevice == 0 {
		t.Skipf("%s is not a character device here: %v", zero, err)
	}
	rules, files, err = EnumerateFSRulesWithPathHandles(CompileFS([]FSEntry{{Path: zero, Access: ReadAccess | WriteAccess, Exact: true}}), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer CloseRuleFiles(files)
	if len(rules) != 0 {
		t.Fatalf("explicit %s entry got rules %+v; only NullDevicePath may", zero, rules)
	}
}
