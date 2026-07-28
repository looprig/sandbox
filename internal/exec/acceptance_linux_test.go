//go:build linux

package exec

// Linux-rung acceptance coverage. On THIS host Landlock ABI
// v4 is live (rung 2 RUNS) and Userns is BLOCKED (rung-1 rows SKIP with a recorded
// reason). Each row asserts its mechanism AND its Guarantees() posture — the
// matrix's load-bearing auto-approval signal. Rows reuse the enforcement helpers
// from the rung-2 e2e tests (tryRead/tryWrite/newFSExecutor/runNetProbe/…).

import (
	"context"
	"github.com/looprig/sandbox/internal/linux"
	"github.com/looprig/sandbox/internal/policy"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAcceptanceMatrixLinux runs the Linux rows. Absent-mechanism rows
// t.Skip with a recorded reason — never a silent pass.
func TestAcceptanceMatrixLinux(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T)
	}{
		{"linux-rung2/write-mode", acceptLinuxRung2Write},
		{"linux-rung1/write-mode", acceptLinuxRung1Write},
		{"Dns-under-trusted/rung2", acceptLinuxDNSUnderTrusted},
		{"cgroup-v2-unavailable", acceptLinuxCgroupUnavailable},
		{"metadata-fetch-under-trusted/rung1", acceptLinuxMetadataUnderTrusted},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { tt.run(t) })
	}
}

// acceptLinuxRung2Write proves the rung-2 boundary when prerequisites exist:
// workspace writes, a read-only carveout, and a fixed deny hold; TCP is limited to Ports;
// Level = Degraded; the guarantee posture is WriteBoundary && ReadBoundary &&
// EnvScrub && NetworkBoundary with AddressNetwork == false.
func acceptLinuxRung2Write(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("UserHomeDir: %v", err)
	}

	// --- FS boundary, .git carveout, fixed secret deny (one workspace) ---
	ws := t.TempDir()
	if err := os.Mkdir(filepath.Join(ws, ".git"), 0o700); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	secret := filepath.Join(ws, "secret.txt")
	if err := os.WriteFile(secret, []byte("token"), 0o600); err != nil {
		t.Fatalf("seed secret: %v", err)
	}
	e := newFSExecutor(t, backendFixturePolicy(fixtureWorkspaceWrite, ws, fixtureWithDenyRead(secret)))

	// Write outside ws (+ not /tmp) is denied.
	outside := filepath.Join(home, ".lrsandbox-accept-rung2-DONOTEXIST")
	t.Cleanup(func() { _ = os.Remove(outside) })
	if code := tryWrite(t, e, ws, outside); code == 0 {
		t.Errorf("write OUTSIDE workspace succeeded — FAIL-OPEN: write boundary leaked")
	}
	// Write into .git is denied (read-only carveout).
	if code := tryWrite(t, e, ws, filepath.Join(ws, ".git", "x")); code == 0 {
		t.Errorf("write into .git succeeded — FAIL-OPEN: carveout leaked")
	}
	// The fixed secret deny is enforced for the subprocess read.
	if code := tryRead(t, e, ws, secret); code == 0 {
		t.Errorf("read of denied secret succeeded — FAIL-OPEN: fixed-path deny leaked")
	}

	// Per-row Guarantees() + Level.
	g := e.Guarantees()
	if !(g.WriteBoundary && g.ReadBoundary && g.EnvScrub && g.NetworkBoundary) {
		t.Errorf("Guarantees() = %+v; want WriteBoundary && ReadBoundary && EnvScrub && NetworkBoundary", g)
	}
	if g.ProcessBoundary || g.AddressNetwork {
		t.Errorf("Guarantees() = %+v; want ProcessBoundary=false && AddressNetwork=false (not linux.Enforced at linux.Rung 2)", g)
	}
	if lvl := e.Level(); lvl != LevelDegraded {
		t.Errorf("Level() = %d, want LevelDegraded (%d)", lvl, LevelDegraded)
	}

	// --- TCP limited to Ports: allowlisted port permitted, others denied ---
	got := runNetProbe(t, fixtureWithNet(policy.NetPolicy{Ports: []uint16{netProbeAllowP}}))
	if got[netKeyPortA] != netValAllowed {
		t.Errorf("allowlisted port %d = %q, want %q", netProbeAllowP, got[netKeyPortA], netValAllowed)
	}
	if got[netKeyPortB] != netValDenied {
		t.Errorf("non-allowlisted port %d = %q, want %q — FAIL-OPEN: port allowlist leaked", netProbeBlockP, got[netKeyPortB], netValDenied)
	}
}

// acceptLinuxRung1Write proves the rung-1 write boundary. Rung 1 needs a usable
// user namespace (Userns+Mountns/Netns). This host has Userns BLOCKED, so the row
// SKIPS with a recorded reason; on a Userns-enabled host (CI) it asserts the
// rung-1 distinguishers: Level = Full plus the ProcessBoundary and AddressNetwork
// guarantees rung 2 cannot provide.
func acceptLinuxRung1Write(t *testing.T) {
	if !linux.ProbeCaps().Userns {
		t.Skip("RECORDED SKIP: linux.Rung 1 needs a usable user namespace (Userns+Mountns/Netns for the bind-mount view + in-Netns nftables); this host reports linux.ProbeCaps().Userns=false (Userns BLOCKED), so the linux.Rung-1 write-mode row — restricted-read in zerotrust, metadata IP unreachable under trusted, Level=Full, all guarantee bits — cannot run here. Exercised in CI on a Userns-enabled host.")
	}
	requireLandlockV4(t)
	requireSeccomp(t)

	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws)) // platformBackend selects linux.Rung 1 here
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	if lvl := e.Level(); lvl != LevelFull {
		t.Errorf("Level() = %d, want LevelFull (%d) for linux.Rung 1", lvl, LevelFull)
	}
	g := e.Guarantees()
	if !(g.ProcessBoundary && g.AddressNetwork && g.WriteBoundary && g.ReadBoundary && g.EnvScrub && g.NetworkBoundary) {
		t.Errorf("Guarantees() = %+v; want the full linux.Rung-1 posture incl. ProcessBoundary && AddressNetwork", g)
	}
}

// acceptLinuxDNSUnderTrusted proves DNS behavior under broad network access: a
// DNS-enabled policy forces resolution over TCP by injecting RES_OPTIONS=use-vc
// into the target env (asserted by running the real `env` under the sandbox) and
// records the Dns/narrowed report entry. Guarantee posture: NetworkBoundary true,
// AddressNetwork false.
func acceptLinuxDNSUnderTrusted(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)
	ws := t.TempDir()

	e := newFSExecutor(t, backendFixturePolicy(fixtureBroadNetwork, ws)) // fixture grants DNS

	if !reportHas(e.Report(), "Dns", "narrowed") {
		t.Errorf("CompileReport missing Dns/narrowed entry; report=%+v", e.Report())
	}
	g := e.Guarantees()
	if !g.NetworkBoundary {
		t.Errorf("Guarantees().NetworkBoundary = false, want true (fixture is port-Confined at linux.Rung 2)")
	}
	if g.AddressNetwork {
		t.Errorf("Guarantees().AddressNetwork = true, want false (linux.Rung 2 cannot address-scope)")
	}

	out, code, err := e.RunArgv(context.Background(), ws, []string{"/usr/bin/env"})
	if err != nil {
		t.Fatalf("RunArgv(env): %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("env exit=%d, want 0 (out=%q)", code, out)
	}
	if !containsLine(out, linux.ResOptionsEnvKey+"="+linux.ResOptionUseVC) {
		t.Errorf("target env missing %s=%s; env output:\n%s", linux.ResOptionsEnvKey, linux.ResOptionUseVC, out)
	}
}

// acceptLinuxCgroupUnavailable proves behavior when cgroup v2 is unavailable: with
// pids delegation pinned absent, the command still runs sandboxed, the report
// records resource-limits/unenforced, Level is unchanged, and the ResourceLimits
// guarantee is cleared (limits are containment-of-cost, not authority).
func acceptLinuxCgroupUnavailable(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)
	ws := t.TempDir()

	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws), withBackend(&linux.Backend{CgroupPids: ""}))
	if err != nil {
		t.Fatalf("NewExecutor (no delegation): %v", err)
	}
	// Per-row Guarantees(): ResourceLimits cleared.
	if e.Guarantees().ResourceLimits {
		t.Errorf("Guarantees().ResourceLimits = true with no delegation, want false (fail-secure)")
	}
	if !reportHas(e.Report(), "resource-limits", "unenforced") {
		t.Errorf("CompileReport missing resource-limits/unenforced entry; report=%+v", e.Report())
	}
	// Level unchanged vs the delegation-available backend.
	avail := newFSExecutor(t, backendFixturePolicy(fixtureWorkspaceWrite, ws))
	if e.Level() != avail.Level() {
		t.Errorf("Level differs by delegation availability: unavailable=%d available=%d; want equal (§7.4)", e.Level(), avail.Level())
	}
	// The command still runs — limits are best-effort, their absence never fatal.
	out, code, err := e.RunCommand(context.Background(), ws, "printf ok")
	if err != nil {
		t.Fatalf("spawn without limits errored (should be best-effort): %v (out=%q)", err, out)
	}
	if code != 0 || string(out) != "ok" {
		t.Errorf("spawn without limits: code=%d out=%q, want 0 / %q", code, out, "ok")
	}
}

// acceptLinuxMetadataUnderTrusted proves metadata denial under broad network access.
// The cloud-metadata hard-deny (curl 169.254.169.254 fails; curl example.com
// succeeds) is a rung-1 Netns+nftables address rule. Userns is BLOCKED here so
// there is no Netns to install it into; and it needs live external egress anyway.
// SKIP with a recorded reason on both counts.
func acceptLinuxMetadataUnderTrusted(t *testing.T) {
	if !linux.ProbeCaps().Userns {
		t.Skip("RECORDED SKIP: the metadata hard-deny is linux.Enforced by linux.Rung-1 in-Netns nftables (§5.2, §5.4); Userns is BLOCKED on this host (linux.ProbeCaps().Userns=false), so there is no Netns to install the 169.254.0.0/16 deny into. Rung 2 cannot address-scope, so metadata is only vacuously denied (:80 not in the default trusted port set). Live metadata/external reachability is exercised in the CI integration environment on a Userns-enabled host.")
	}
	t.Skip("RECORDED SKIP: even on a Userns host this row requires live external egress (reach 169.254.169.254 and example.com), which is not available/deterministic in the unit-test environment; asserted by the CI integration suite.")
}

// containsLine reports whether out contains want as a full, trimmed line — a
// stricter check than substring so a value embedded in another variable cannot
// masquerade as a match.
func containsLine(out []byte, want string) bool {
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}
