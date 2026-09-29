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
