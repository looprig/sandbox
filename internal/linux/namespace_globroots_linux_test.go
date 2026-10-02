//go:build linux

package linux

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/looprig/sandbox/internal/policy"
)

// TestCompileMountViewGlobScanRootsIncludeReadOnlyBinds pins review M6: the
// Rung-1 glob-deny scan used to walk only the writable binds, the workspace and
// $HOME, so a `.env` inside a read-only bound root (e.g. a read-only project
// directory or a read grant) was visible in the view although the report
// called glob denies "Enforced". Read-only binds are now scanned too — an
// empty read-only mask over a read-only bind is harmless — except the
// filesystem root "/" (a HostRead-Allow rbind), whose depth-bounded walk would
// cost the whole host on every spawn and is disclosed as narrowed instead.
func TestCompileMountViewGlobScanRootsIncludeReadOnlyBinds(t *testing.T) {
	t.Parallel()
	workspace := filepath.Join(string(filepath.Separator), "work", "repo")
	readOnly := filepath.Join(string(filepath.Separator), "srv", "readonly")
	plan := CompileMountView(policy.Effective{
		Workspace: workspace,
		FS: []policy.FSEntry{
			{Path: "/", Access: policy.ReadAccess | policy.ExecAccess},
			{Path: workspace, Access: policy.AllAccess},
			{Path: readOnly, Access: policy.ReadAccess},
			{Path: "**/.env*", Denied: policy.AllAccess},
		},
	})
	if !slices.Contains(plan.ROBinds, readOnly) || !slices.Contains(plan.ROBinds, "/") {
		t.Fatalf("fixture drift: ROBinds = %v, want %q and %q", plan.ROBinds, readOnly, "/")
	}
	if !slices.Contains(plan.scanRoots, readOnly) {
		t.Errorf("glob scan roots %v omit read-only bind %q", plan.scanRoots, readOnly)
	}
	if !slices.Contains(plan.scanRoots, workspace) {
		t.Errorf("glob scan roots %v omit workspace %q", plan.scanRoots, workspace)
	}
	if slices.Contains(plan.scanRoots, "/") {
		t.Errorf("glob scan roots %v include the filesystem root; a per-spawn host walk is unbounded in cost", plan.scanRoots)
	}
}
