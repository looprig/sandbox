//go:build linux

package exec

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/looprig/sandbox/internal/linux"
)

// TestRung1CarveoutDoesNotFollowPlantedSymlink is the review L10 runtime
// proof. A previous run that could write the workspace replaced its .looprig
// carveout with an absolute symlink to a host directory outside the view.
// The old mount view resolved the carveout's mountpoint as the host path
// <newroot>/<ws>/.looprig, which the kernel followed out of the new root: the
// read-only bind landed on the host directory in the stage-2 namespace —
// outside the view, confining nothing — and the spawn ran. The mount view now
// resolves targets inside the new root and refuses a symlink beneath a
// writable bind, so the spawn fails closed and the host directory is
// untouched.
func TestRung1CarveoutDoesNotFollowPlantedSymlink(t *testing.T) {
	requireRung1Caps(t)
	ws := realpath(t, t.TempDir())
	if err := os.Mkdir(filepath.Join(ws, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	host := realpath(t, t.TempDir())
	if err := os.WriteFile(filepath.Join(host, "marker"), []byte("host"), 0o644); err != nil {
		t.Fatalf("seed host dir: %v", err)
	}
	if err := os.Symlink(host, filepath.Join(ws, ".looprig")); err != nil {
		t.Fatalf("plant symlink: %v", err)
	}
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureScopedRuntime, ws, fixtureWithWritable(ws)), withBackend(linux.NewBackendRung1()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	out, code, err := e.RunCommand(context.Background(), ws, "echo RAN")
	if err == nil && code == 0 {
		t.Fatalf("spawn ran with a symlinked carveout beneath a writable bind (out=%q)", out)
	}
	if strings.Contains(string(out), "RAN") {
		t.Fatalf("target ran: out=%q", out)
	}
	if !strings.Contains(string(out), "mount-view") || !strings.Contains(string(out), "too many levels of symbolic links") {
		t.Errorf("stage 2 did not fail closed on the planted link in the mount view: code=%d err=%v out=%q", code, err, out)
	}
	entries, err := os.ReadDir(host)
	if err != nil {
		t.Fatalf("read host dir: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "marker" {
		t.Errorf("host directory changed: %v", entries)
	}
}
