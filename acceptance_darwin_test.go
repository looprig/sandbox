//go:build darwin

package sandbox

// macOS Seatbelt acceptance coverage. This file compiles on
// every platform's darwin cross-build (GOOS=darwin go test -c) but only RUNS on
// macOS, where /usr/bin/sandbox-exec is present. The compile-time posture
// (Level/Guarantees) is asserted unconditionally; the runtime enforcement checks
// are gated on requireSandboxExec (defined in backend_seatbelt_test.go).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAcceptanceMatrixDarwin runs the macOS Seatbelt writable-profile row: the
// write boundary + .git carveout hold, a ~/.ssh read is denied, Level = Full
// (loopback+ports+DNS enforced; Private/metadata compile-to-blocked, so a policy
// needing address-scoping would be Degraded), and AddressNetwork is always false
// (SBPL cannot address-scope, Task M1).
func TestAcceptanceMatrixDarwin(t *testing.T) {
	// A temp HOME so the ~/.ssh deny is anchored under a directory we control, and
	// so the executor's home guard resolves. Set before NewExecutor.
	home := t.TempDir()
	t.Setenv("HOME", home)
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir ~/.ssh: %v", err)
	}
	sshKey := filepath.Join(sshDir, "id_rsa")
	if err := os.WriteFile(sshKey, []byte("PRIVATE"), 0o600); err != nil {
		t.Fatalf("seed ~/.ssh/id_rsa: %v", err)
	}

	ws := t.TempDir()
	gitDir := filepath.Join(ws, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: ws, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
		AdditionalRoots: []RootAccess{{Path: gitDir, Read: Allow, Write: Deny}},
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	e, err := set.For("acceptance")
	if err != nil {
		t.Fatalf("ExecutorSet.For: %v", err)
	}

	// Per-row Guarantees() + Level (compile posture; no sandbox-exec needed).
	g := e.Guarantees()
	if !(g.ProcessBoundary && g.WriteBoundary && g.ReadBoundary && g.EnvScrub && g.NetworkBoundary) {
		t.Errorf("Guarantees() = %+v; want ProcessBoundary && WriteBoundary && ReadBoundary && EnvScrub && NetworkBoundary", g)
	}
	if g.AddressNetwork {
		t.Errorf("Guarantees().AddressNetwork = true, want false (SBPL cannot address-scope)")
	}
	if g.ResourceLimits {
		t.Errorf("Guarantees().ResourceLimits = true, want false (darwin ulimit approximation not enforced)")
	}
	if lvl := e.Level(); lvl != LevelFull {
		t.Errorf("Level() = %d, want LevelFull (%d) for Write on Seatbelt", lvl, LevelFull)
	}

	// Runtime enforcement requires real sandbox-exec.
	requireSandboxExec(t)
	ctx := context.Background()

	// Write inside ws succeeds; write to a sibling dir (not ws, not /tmp) is denied.
	inside := filepath.Join(ws, "f")
	if out, code, rerr := e.RunCommand(ctx, ws, "echo hi > "+inside); rerr != nil || code != 0 {
		t.Errorf("write inside ws: code=%d err=%v (out=%s), want exit 0", code, rerr, out)
	}
	outside := filepath.Join(t.TempDir(), "f") // sibling temp dir
	if out, code, rerr := e.RunCommand(ctx, ws, "echo hi > "+outside); rerr != nil {
		t.Fatalf("write outside ws: spawn err %v", rerr)
	} else if code == 0 {
		t.Errorf("write outside ws succeeded — FAIL-OPEN: write boundary leaked (out=%s)", out)
	}

	// Write into ws/.git is denied (read-only carveout).
	if out, code, rerr := e.RunCommand(ctx, ws, "echo hi > "+filepath.Join(ws, ".git", "x")); rerr != nil {
		t.Fatalf(".git write: spawn err %v", rerr)
	} else if code == 0 {
		t.Errorf(".git write succeeded — FAIL-OPEN: carveout leaked (out=%s)", out)
	}

	// Read of ~/.ssh/id_rsa is denied (fixed secret deny).
	if out, code, rerr := e.RunCommand(ctx, ws, "cat "+sshKey); rerr != nil {
		t.Fatalf("~/.ssh read: spawn err %v", rerr)
	} else if code == 0 || strings.Contains(string(out), "PRIVATE") {
		t.Errorf("~/.ssh read succeeded — FAIL-OPEN: secret deny leaked (code=%d out=%s)", code, out)
	}
}
