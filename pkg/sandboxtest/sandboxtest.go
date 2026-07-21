// Package sandboxtest is a reusable conformance suite for sandbox executors,
// modelled on the storekit `storetest` pattern: a consumer supplies a factory
// that builds an executor, and RunSuite asserts the core sandbox invariants hold
// against it. It is the executor analogue of storetest — one suite any backend
// (null / seatbelt / the Linux ladder) is run through, so
// a new or downstream backend proves the load-bearing security contract without
// re-deriving the assertions.
//
// # What it asserts (the contract, not a mechanism)
//
// Every assertion is gated on what the executor REPORTS (Guarantees bits / Level),
// never on the host platform. The SAME suite therefore passes against the null
// backend (LevelNone, no OS enforcement), a rung-2 Linux executor (LevelDegraded),
// a rung-1 executor (LevelFull), and Seatbelt — each is held
// only to the guarantees it actually claims:
//
//  1. Write boundary — Guarantees.WriteBoundary ⟺ writes are actually confined.
//     A write inside a policy-writable root succeeds; a write to a path OUTSIDE
//     every writable root is denied IFF the executor claims WriteBoundary. A
//     no-op backend that honestly reports WriteBoundary=false is conformant
//     precisely because it does NOT claim confinement it cannot deliver. The
//     security-critical direction — claiming the bit while writes leak — is the
//     fail-open this catches.
//  2. Env scrub — a secret planted in the parent environment is absent from a
//     spawned child whenever the executor claims EnvScrub. This is the harness
//     secret-leak boundary and holds independently of any OS mechanism.
//  3. Self-consistency — the reported guarantees and Level are internally
//     coherent and fail-secure: LevelNone claims no OS-enforcement bit beyond
//     EnvScrub; address-scoped networking implies a network boundary; a write
//     boundary implies at least a degraded level; LevelFull implies a write
//     boundary. An incoherent posture (a set bit with no honest backing) is the
//     signal the auto-approval interlock must never trust.
//
// # Dependency posture
//
// This package deliberately imports ONLY the standard library. The executor is
// consumed through the minimal structural interface [SUT], and the guarantee-bit
// and level constants are mirrored from the sandbox package's stdlib-only seam
// (SPEC §6: "Bit positions are exported constants; ... the consumer builds each
// posture's required mask from them" — designed for probing without importing the
// package). Keeping sandboxtest import-free of sandbox is what lets the sandbox
// package's own tests drive this suite against internal backends (e.g. the null
// backend, reachable only through an unexported seam) with no import cycle. A
// drift guard in the sandbox package asserts these mirrored constants stay equal
// to the originals.
package sandboxtest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Guarantee bits mirror the sandbox package's seam-facing bitmask (SPEC §6,
// Bit order matches sandbox.Guarantee* exactly; a drift guard in the
// sandbox package pins the correspondence. They are the machine-readable posture
// the suite gates every assertion on.
const (
	GuaranteeProcessBoundary uint64 = 1 << iota
	GuaranteeWriteBoundary
	GuaranteeReadBoundary
	GuaranteeEnvScrub
	GuaranteeNetworkBoundary
	GuaranteeAddressNetwork
	GuaranteeResourceLimits
	GuaranteeTargetNetwork
)

// Isolation levels mirror the sandbox package's achieved-isolation rollup
// (SPEC §6). The zero value LevelNone is fail-closed.
const (
	LevelNone uint8 = iota
	LevelDegraded
	LevelFull
)

// SUT is the minimal structural surface the conformance suite exercises on an
// executor. *sandbox.Executor satisfies it. It is deliberately narrow (interface
// segregation): the suite spawns commands and reads the achieved posture, nothing
// more, so any conforming executor — present or future — can be run through it
// without this package importing the sandbox package.
type SUT interface {
	// RunCommand runs a shell command string in dir under the executor's policy
	// and returns combined output, the process exit code, and an error that is
	// non-nil only when the process did not complete normally (spawn/setup
	// failure, signal, or context cancellation) — a ran-but-nonzero command
	// returns a nil error and the real code.
	RunCommand(ctx context.Context, dir, command string) ([]byte, int, error)
	// Level reports the achieved isolation level (LevelNone..LevelFull).
	Level() uint8
	// GuaranteeBits reports the per-property guarantee bitmask.
	GuaranteeBits() uint64
}

// Factory builds a fresh, WRITE-CONFINING executor for the given workspace. The
// contract the suite relies on: the workspace
// is a writable root, the process's $HOME is NOT writable, and the environment is
// scrubbed (non-inherit). The factory is invoked once per sub-test — AFTER the
// suite plants any environment it needs — because an executor snapshots the
// environment at construction, so a later-planted secret must be visible when the
// factory builds the executor for the env-scrub check to be meaningful.
type Factory func(t *testing.T, workspace string) SUT

// plantedSecretKey is an environment variable name the suite injects to prove
// scrubbing. It is not in the §5.5 baseline allowlist, so a conformant EnvScrub
// backend must drop it; a made-up prefix avoids clashing with any real variable a
// host might legitimately export.
const plantedSecretKey = "LRSANDBOXTEST_PLANTED_SECRET"

// plantedSecretVal is the sentinel value written to plantedSecretKey. The suite
// asserts this exact string never reaches a scrubbed child.
// #nosec G101 -- this is the opposite of a credential: it is the sentinel the
// suite plants in the parent environment precisely to assert it never reaches
// a scrubbed child. It grants nothing and authenticates to nothing.
const plantedSecretVal = "lrsandboxtest-must-not-leak"

// RunSuite runs the full conformance suite against newSUT under a named subtest.
// A consumer typically calls it once per backend they can construct, e.g.:
//
//	sandboxtest.RunSuite(t, "live", func(t *testing.T, ws string) sandboxtest.SUT {
//	    profile, err := sandbox.NewProfile(sandbox.ProfileConfig{
//	        WorkspaceRoot: ws, WorkspaceRead: sandbox.Allow,
//	        WorkspaceWrite: sandbox.Allow, HostWrite: sandbox.Deny,
//	    })
//	    if err != nil { t.Fatalf("NewProfile: %v", err) }
//	    set, err := sandbox.NewExecutorSet(profile,
//	        sandbox.WithScratchRoot(t.TempDir()), sandbox.WithMaxExecutors(1))
//	    if err != nil { t.Fatalf("NewExecutorSet: %v", err) }
//	    t.Cleanup(func() { _ = set.Close() })
//	    e, err := set.For("conformance")
//	    if err != nil { t.Fatalf("ExecutorSet.For: %v", err) }
//	    return e
//	})
//
// Sub-tests use t.Setenv (env-scrub) and therefore do not run in parallel.
func RunSuite(t *testing.T, name string, newSUT Factory) {
	t.Helper()
	// A resolvable, non-writable $HOME is the out-of-policy write target and is
	// also required by any non-inherit executor's construction. Provide a stable
	// one when the host leaves it unset, so the suite probes a real denied path
	// rather than skipping. Set once at the parent (non-parallel) level.
	if os.Getenv("HOME") == "" {
		t.Setenv("HOME", t.TempDir())
	}

	// The suite is a table of conformance checks; each gets a fresh workspace and
	// a freshly-built executor so no check observes another's spawned state.
	checks := []struct {
		name string
		run  func(t *testing.T, newSUT Factory)
	}{
		{"write-boundary", checkWriteBoundary},
		{"env-scrub", checkEnvScrub},
		{"self-consistency", checkSelfConsistency},
	}
	t.Run(name, func(t *testing.T) {
		for _, c := range checks {
			c := c
			t.Run(c.name, func(t *testing.T) { c.run(t, newSUT) })
		}
	})
}

// checkWriteBoundary asserts the WriteBoundary contract: a write inside a
// writable root always succeeds, and a write outside every writable root is
// denied exactly when the executor claims WriteBoundary. The biconditional is the
// point — a backend may honestly report WriteBoundary=false (no confinement), but
// claiming it while an outside write lands is the fail-open the auto-approval
// interlock must never see.
func checkWriteBoundary(t *testing.T, newSUT Factory) {
	ws := t.TempDir()
	e := newSUT(t, ws)

	home, err := os.UserHomeDir()
	if err != nil {
		t.Skipf("SKIP write-boundary outside probe: home unresolvable (%v); no out-of-policy write target", err)
	}
	// The outside target must be OS-writable-if-unconfined (so a null backend
	// actually creates it) yet outside the workspace. ExecutorSet-owned HOME and
	// TMPDIR are private paths unknown to this external conformance seam.
	if isUnder(home, ws) {
		t.Skipf("SKIP write-boundary outside probe: home %q sits under a writable root; cannot probe a denied write there", home)
	}

	ctx := context.Background()

	// Positive half: a write inside the workspace (a writable root) must succeed
	// under every honest backend — a backend that denies it is broken regardless
	// of its WriteBoundary claim.
	inside := filepath.Join(ws, "inside.txt")
	if code := runWrite(t, e, ctx, ws, inside); code != 0 {
		t.Errorf("write INSIDE workspace denied (exit %d), want permitted — a writable root must be writable", code)
	}

	// Negative half: attempt a write outside every writable root, then reconcile
	// the observed confinement with the claimed guarantee.
	outside := filepath.Join(home, ".lrsandboxtest-writeboundary-DONOTEXIST")
	t.Cleanup(func() { _ = os.Remove(outside) })
	outsideCode := runWrite(t, e, ctx, ws, outside)
	confined := outsideCode != 0
	_, statErr := os.Stat(outside)
	created := statErr == nil

	claimsWriteBoundary := e.GuaranteeBits()&GuaranteeWriteBoundary != 0

	// The load-bearing biconditional.
	if claimsWriteBoundary != confined {
		t.Errorf("WriteBoundary contract violated: Guarantees claims WriteBoundary=%v but the out-of-policy write was %s (exit %d) — the bit and the mechanism must agree",
			claimsWriteBoundary, confinedWord(confined), outsideCode)
	}
	// Security-critical corollary: a claimed boundary must not have left a file.
	if claimsWriteBoundary && created {
		t.Errorf("FAIL-OPEN: WriteBoundary claimed but the out-of-policy file %q was created", outside)
	}
}

// checkEnvScrub asserts the EnvScrub contract: when the executor claims EnvScrub,
// a secret planted in the parent environment must be absent from a spawned
// child's environment. The secret is planted BEFORE the executor is built (an
// executor snapshots os.Environ at construction), so the factory is invoked here,
// after t.Setenv.
func checkEnvScrub(t *testing.T, newSUT Factory) {
	t.Setenv(plantedSecretKey, plantedSecretVal)
	ws := t.TempDir()
	e := newSUT(t, ws)

	out, code, err := e.RunCommand(context.Background(), ws, "env")
	if err != nil {
		t.Fatalf("RunCommand(env): %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("RunCommand(env) exit=%d, want 0 (out=%q)", code, out)
	}

	claimsEnvScrub := e.GuaranteeBits()&GuaranteeEnvScrub != 0
	leaked := strings.Contains(string(out), plantedSecretVal)

	// The honest direction the interlock relies on: a claimed scrub must remove
	// the secret. (A backend that does NOT claim EnvScrub — e.g. an inherit
	// policy — is permitted to pass the secret through; nothing to assert there.)
	if claimsEnvScrub && leaked {
		t.Errorf("FAIL-OPEN: EnvScrub claimed but planted secret %s=%s leaked into the child env:\n%s",
			plantedSecretKey, plantedSecretVal, out)
	}
}

// checkSelfConsistency asserts the reported Guarantees/Level are internally
// coherent and fail-secure — the structural invariants the auto-approval signal
// depends on, checkable without spawning. It is table-driven over the
// implications that must hold for any honest posture.
func checkSelfConsistency(t *testing.T, newSUT Factory) {
	ws := t.TempDir()
	e := newSUT(t, ws)
	bits := e.GuaranteeBits()
	lvl := e.Level()

	has := func(b uint64) bool { return bits&b != 0 }

	// osEnforcementBits are every guarantee except EnvScrub, which the executor
	// provides itself regardless of any OS mechanism. LevelNone means no OS
	// enforcement was achieved, so none of these may be claimed.
	const osEnforcementBits = GuaranteeProcessBoundary | GuaranteeWriteBoundary |
		GuaranteeReadBoundary | GuaranteeNetworkBoundary | GuaranteeAddressNetwork |
		GuaranteeResourceLimits | GuaranteeTargetNetwork

	invariants := []struct {
		name string
		ok   bool
	}{
		{
			// LevelNone ⟹ no OS-enforcement bit beyond EnvScrub.
			name: "LevelNone claims no OS-enforcement bit beyond EnvScrub",
			ok:   lvl != LevelNone || bits&osEnforcementBits == 0,
		},
		{
			// Address-scoped network rules presuppose a network boundary.
			name: "AddressNetwork implies NetworkBoundary",
			ok:   !has(GuaranteeAddressNetwork) || has(GuaranteeNetworkBoundary),
		},
		{
			name: "TargetNetwork implies NetworkBoundary",
			ok:   !has(GuaranteeTargetNetwork) || has(GuaranteeNetworkBoundary),
		},
		{
			// A write boundary is at least the degraded threshold (SPEC §7.5:
			// "Anything less that still enforces the write boundary = Degraded").
			name: "WriteBoundary implies Level >= LevelDegraded",
			ok:   !has(GuaranteeWriteBoundary) || lvl >= LevelDegraded,
		},
		{
			// LevelFull enforces every mechanism feature, which includes the write
			// boundary (SPEC §7.5).
			name: "LevelFull implies WriteBoundary",
			ok:   lvl != LevelFull || has(GuaranteeWriteBoundary),
		},
		{
			// The level is a defined value; a value above LevelFull is an
			// uninitialized/garbage posture and must never be trusted.
			name: "Level is a defined value",
			ok:   lvl <= LevelFull,
		},
	}
	for _, inv := range invariants {
		if !inv.ok {
			t.Errorf("self-consistency violated: %s (bits=%#b level=%d)", inv.name, bits, lvl)
		}
	}
}

// runWrite opens path for write via a shell redirect (`: > path`) under the
// executor and returns the exit code: 0 == the write was permitted, non-zero ==
// denied. The `:` builtin plus redirect touches no external binary, so the code
// reflects exactly whether the filesystem policy permitted the open. A spawn/setup
// failure (non-nil error) fails the test — that is not a policy signal.
func runWrite(t *testing.T, e SUT, ctx context.Context, dir, path string) int {
	t.Helper()
	_, code, err := e.RunCommand(ctx, dir, ": > "+shQuote(path))
	if err != nil {
		t.Fatalf("RunCommand(write %s): unexpected spawn error %v", path, err)
	}
	return code
}

// shQuote single-quotes a filesystem path for safe embedding in a /bin/sh
// command. Test paths (temp dirs, home) never contain single quotes, so wrapping
// in single quotes fully neutralizes spaces and shell metacharacters.
func shQuote(p string) string { return "'" + p + "'" }

// isUnder reports whether path is equal to or nested within root, comparing
// cleaned absolute-style paths so a suffix match (e.g. "/tmpfoo" under "/tmp")
// does not falsely register.
func isUnder(path, root string) bool {
	path = filepath.Clean(path)
	root = filepath.Clean(root)
	if path == root {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// confinedWord renders the confinement outcome for an error message.
func confinedWord(confined bool) string {
	if confined {
		return "denied"
	}
	return "permitted"
}
