//go:build linux

// Package landlockspike is a THROWAWAY Phase 0.5 spike (Task M2). It proves
// that a re-exec'd stage-2 child which applies a go-landlock read-only rule to
// a directory gets EACCES on write there, while the parent process is
// unaffected. This validates the Task 11/12 architecture where the sandbox
// re-execs /proc/self/exe as a stage-2 helper and applies Landlock in the child
// before exec'ing the target: Landlock confinement is child-local and survives
// a re-exec.
//
// It is NOT shipped code. It lives in its own package, isolated from the root
// `package sandbox`, and runs only as a capability-gated test.
package landlockspike

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/landlock-lsm/go-landlock/landlock"
	lsyscall "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// Sentinel + parameter env vars driving the two re-exec hops. The parent sets
// envStage2 to launch the stage-2 child; the stage-2 child applies Landlock and
// then execve's the TARGET (envTarget) — a fresh program image that runs the
// probes. This mirrors the real backend exactly: re-exec stage-2 → apply
// Landlock → execve the target → target runs confined. A passing RO-write=EACCES
// in the target therefore proves the ruleset SURVIVES the second execve, not
// merely that it applied in the stage-2 process.
const (
	envStage2 = "LRSANDBOX_SPIKE_STAGE2"
	envTarget = "LRSANDBOX_SPIKE_TARGET"
	envRODir  = "LRSANDBOX_SPIKE_RODIR"
	envRWDir  = "LRSANDBOX_SPIKE_RWDIR"
)

// Marker keys the child prints (one "KEY=VALUE" line each) and the parent
// parses. Keeping them as shared constants stops the two halves from drifting.
const (
	keyApply   = "APPLY"
	keyROWrite = "RO_WRITE"
	keyRWWrite = "RW_WRITE"
	keyRORead  = "RO_READ"
)

// Probe outcome values.
const (
	valOK     = "OK"
	valEACCES = "EACCES"
)

// existingFile is pre-created by the parent under the RO dir so the child can
// prove that reads there still succeed after the restriction.
const existingFile = "existing.txt"

// requiredABI is the Landlock ABI version this spike asserts against.
const requiredABI = 4

// Child exit codes.
const (
	exitConfig   = 2 // env misconfiguration (missing dir params)
	exitApplyErr = 3 // Landlock restriction itself failed to apply
	exitExecErr  = 4 // execve into the target failed after Landlock applied
)

// TestMain multiplexes the two re-exec hops. envTarget is checked FIRST: the
// post-execve target runs the probes. envStage2 next: the stage-2 child applies
// Landlock and execve's the target. Neither set: run the normal suite.
func TestMain(m *testing.M) {
	if os.Getenv(envTarget) != "" {
		os.Exit(runTarget())
	}
	if os.Getenv(envStage2) != "" {
		os.Exit(runStage2Child())
	}
	os.Exit(m.Run())
}

// restrictReadOnly confines the CURRENT process (and its future children,
// including anything it execve's) via Landlock ABI v4: read+exec on the whole
// filesystem (so the target binary and its dynamic loader/libs remain
// executable across the upcoming execve — this mirrors the real "write" policy
// shape: broad host read, RW only on workspace/tmp) and read+WRITE only on
// rwDir.
//
// rwDir is deliberately writable so the target CAN write somewhere: that proves
// the RO deny is path-specific, not a blanket deny masquerading as "the rule
// worked". roDir is covered only by the "/" read grant, so writes there are
// denied while reads succeed.
//
// BestEffort() would silently no-op on a kernel without Landlock; that fail-open
// is defended against two ways: the parent gates on a real ABI-version probe
// before re-exec, AND the positive RW-write/RO-read assertions turn any no-op or
// blanket-deny into a RED failure rather than a false green.
func restrictReadOnly(rwDir string) error {
	return landlock.V4.BestEffort().RestrictPaths(
		landlock.RODirs("/"),
		landlock.RWDirs(rwDir),
	)
}

// runStage2Child applies the Landlock restriction and then execve's the target
// (a fresh program image of this same test binary in envTarget mode). It does
// NOT run the probes itself — the whole point is that the probes run AFTER a
// second execve, proving the ruleset survives execve into the target, which is
// exactly what the real backend relies on (stage-2 applies Landlock, then
// execs the command). On success this function never returns (execve replaces
// the image); it returns only on a setup/exec failure.
func runStage2Child() int {
	roDir := os.Getenv(envRODir)
	rwDir := os.Getenv(envRWDir)
	if roDir == "" || rwDir == "" {
		fmt.Printf("%s=ERR:missing-dirs\n", keyApply)
		return exitConfig
	}
	if err := restrictReadOnly(rwDir); err != nil {
		fmt.Printf("%s=ERR:%v\n", keyApply, err)
		return exitApplyErr
	}
	// execve the target. If the ruleset (correctly) still permits exec of the
	// binary via the "/" read+exec grant, this replaces the image and never
	// returns; the target then runs the probes under the inherited restriction.
	env := append(os.Environ(), envTarget+"=1")
	if err := syscall.Exec(os.Args[0], []string{os.Args[0]}, env); err != nil {
		fmt.Printf("%s=ERR:exec:%v\n", keyApply, err)
		return exitExecErr
	}
	return 0 // unreachable: Exec replaced the process image on success
}

// runTarget is the post-execve target: it runs under the Landlock restriction
// INHERITED across the stage-2 execve. It emits APPLY=OK (reaching here at all
// proves Landlock applied AND execve of a fresh image succeeded under it), then
// runs the three filesystem probes and prints their "KEY=VALUE" markers.
func runTarget() int {
	roDir := os.Getenv(envRODir)
	rwDir := os.Getenv(envRWDir)
	if roDir == "" || rwDir == "" {
		fmt.Printf("%s=ERR:missing-dirs\n", keyApply)
		return exitConfig
	}
	fmt.Printf("%s=%s\n", keyApply, valOK)

	// The three scenarios, exercised post-execve as a table.
	probes := []struct {
		key    string
		result string
	}{
		{keyROWrite, classifyWrite(filepath.Join(roDir, "should_fail.txt"))},
		{keyRWWrite, classifyWrite(filepath.Join(rwDir, "ok.txt"))},
		{keyRORead, classifyRead(filepath.Join(roDir, existingFile))},
	}
	for _, p := range probes {
		fmt.Printf("%s=%s\n", p.key, p.result)
	}
	return 0
}

// classifyWrite attempts to create-and-open a file for writing and reports the
// outcome as a marker value: valOK, valEACCES, or "ERR:<detail>".
func classifyWrite(path string) string {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err == nil {
		if cerr := f.Close(); cerr != nil {
			return "ERR:close:" + cerr.Error()
		}
		return valOK
	}
	if errors.Is(err, syscall.EACCES) {
		return valEACCES
	}
	return "ERR:" + err.Error()
}

// classifyRead attempts to read an existing file and reports the outcome.
func classifyRead(path string) string {
	if _, err := os.ReadFile(path); err != nil {
		if errors.Is(err, syscall.EACCES) {
			return valEACCES
		}
		return "ERR:" + err.Error()
	}
	return valOK
}

// parseMarkers turns the child's "KEY=VALUE" lines into a map.
func parseMarkers(out []byte) map[string]string {
	markers := make(map[string]string)
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		markers[key] = val
	}
	return markers
}

// TestLandlockReexecReadOnly drives the full backend-shaped flow: the parent
// re-execs the test binary as a stage-2 child, the stage-2 child applies a
// Landlock restriction and execve's the TARGET (a second fresh image), and the
// target runs the probes under the ruleset inherited across that execve. It then
// makes the 4-way anti-fail-open assertion: (1) target write under RO is denied
// with EACCES, (2) target write under RW still succeeds (deny is scoped, not
// blanket), (3) target read of an existing RO file still succeeds, (4) the
// PARENT can still write under the RO dir (confinement is child-local and did
// not leak). Assertion (1) succeeding proves the ruleset survived the second
// execve — the exact leg the real backend depends on.
func TestLandlockReexecReadOnly(t *testing.T) {
	// Capability gate: probe the kernel's Landlock ABI. Skip with a recorded
	// reason on hosts without ABI v4 (this host has it, so no skip here).
	if v, err := lsyscall.LandlockGetABIVersion(); err != nil {
		t.Skipf("landlock ABI v%d unavailable: probe error: %v", requiredABI, err)
	} else if v < requiredABI {
		t.Skipf("landlock ABI v%d unavailable: kernel reports ABI v%d", requiredABI, v)
	}

	root := t.TempDir()
	roDir := filepath.Join(root, "ro")
	rwDir := filepath.Join(root, "rw")
	for _, d := range []string{roDir, rwDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	// Pre-create a file under the RO dir so the child can prove reads survive.
	if err := os.WriteFile(filepath.Join(roDir, existingFile), []byte("hello"), 0o600); err != nil {
		t.Fatalf("seed RO file: %v", err)
	}

	// Re-exec this very test binary as the stage-2 child.
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(),
		envStage2+"=1",
		envRODir+"="+roDir,
		envRWDir+"="+rwDir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("stage-2 child exited non-zero: %v\nchild output:\n%s", err, out)
	}
	got := parseMarkers(out)

	// Assertions 1-3: the child's observed capabilities under confinement.
	childChecks := []struct {
		name string
		key  string
		want string
	}{
		{"landlock applied and survived execve into target", keyApply, valOK},
		{"target write under RO denied with EACCES", keyROWrite, valEACCES},
		{"target write under RW still allowed (deny is scoped)", keyRWWrite, valOK},
		{"target read of existing RO file still allowed", keyRORead, valOK},
	}
	for _, tt := range childChecks {
		t.Run(tt.name, func(t *testing.T) {
			if got[tt.key] != tt.want {
				t.Errorf("child %s = %q, want %q\nfull child output:\n%s", tt.key, got[tt.key], tt.want, out)
			}
		})
	}

	// Assertion 4: the parent (this process) was never confined.
	t.Run("parent write under RO dir unaffected (child-local)", func(t *testing.T) {
		p := filepath.Join(roDir, "parent_write.txt")
		if werr := os.WriteFile(p, []byte("parent"), 0o600); werr != nil {
			t.Errorf("parent write under RO dir failed (confinement leaked into parent): %v", werr)
		}
	})
}
