//go:build integration && linux

package exec

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// escapeGrandchildAlive reports whether any live host process carries token in
// its argv. It deliberately ignores the pid file: at Rung 1 the recorded pid is
// namespace-local and names an unrelated host process. Scanning the host's
// /proc sees every pid namespace's processes, so a grandchild that escaped the
// run's PID namespace or cgroup teardown is found here. Zombies are not alive:
// their teardown already happened, only reaping is pending.
func escapeGrandchildAlive(t *testing.T, _ string, token string) bool {
	t.Helper()
	dirs, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		t.Fatalf("scan /proc: %v", err)
	}
	for _, dir := range dirs {
		cmdline, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil || !bytes.Contains(cmdline, []byte(token)) {
			continue
		}
		stat, err := os.ReadFile(filepath.Join(dir, "stat"))
		if err != nil {
			continue // exited between the two reads
		}
		// The state field follows the parenthesised comm, which may itself
		// contain spaces or parentheses.
		if i := bytes.LastIndexByte(stat, ')'); i >= 0 && i+2 < len(stat) && stat[i+2] == 'Z' {
			continue
		}
		return true
	}
	return false
}
