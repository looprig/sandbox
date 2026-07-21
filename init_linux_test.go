//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"github.com/looprig/sandbox/internal/policy"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// realpath resolves symlinks so a workspace under /tmp (often a symlink) can be
// compared against the physical cwd that `pwd` prints.
func realpath(t *testing.T, p string) string {
	t.Helper()
	rp, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatalf("EvalSymlinks(%q): %v", p, err)
	}
	return rp
}

// TestStage2RoundTrip is the headline end-to-end proof: NewExecutor(withBackend
// linuxBackend).RunCommand re-execs /proc/self/exe -> the test binary's TestMain
// calls Init() -> Init dispatches the stage-2 sentinel -> runStage2 reads the
// sealed spec from the pipe (fd 3) -> chdir(ws) -> execve(/bin/sh) with the
// SCRUBBED env. It asserts the target ran in ws, exited 0, saw the forced
// marker, and did NOT see the dispatch sentinel (proving the target env is the
// scrubbed spec.Env, sentinel-free).
func TestStage2RoundTrip(t *testing.T) {
	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(
		backendFixturePolicy(fixtureWorkspaceWrite, ws, fixtureWithEnv(policy.EnvPolicy{Set: map[string]string{"LRSANDBOX_MARKER": "present"}})),
		withBackend(newLinuxBackend()),
	)
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	out, code, err := e.RunCommand(ctx, ws,
		`pwd; printf 'MARKER=%s\n' "$LRSANDBOX_MARKER"; printf 'SENTINEL=%s\n' "$LRSANDBOX_STAGE2"`)
	if err != nil {
		t.Fatalf("RunCommand: err = %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("RunCommand exit = %d, want 0 (out=%q)", code, out)
	}

	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	if len(lines) < 1 {
		t.Fatalf("no output: %q", out)
	}
	if gotPwd, wantPwd := realpath(t, lines[0]), realpath(t, ws); gotPwd != wantPwd {
		t.Errorf("target cwd = %q, want %q (out=%q)", gotPwd, wantPwd, out)
	}
	if !strings.Contains(string(out), "MARKER=present") {
		t.Errorf("target did not see forced marker; out=%q", out)
	}
	// The dispatch sentinel MUST be absent in the target env: the line is
	// "SENTINEL=" with an empty value, never "SENTINEL=1".
	if strings.Contains(string(out), "SENTINEL=1") {
		t.Errorf("target saw the stage-2 dispatch sentinel LRSANDBOX_STAGE2; out=%q", out)
	}
	if !strings.Contains(string(out), "SENTINEL=\n") {
		t.Errorf("expected an empty SENTINEL line (sentinel scrubbed); out=%q", out)
	}
}

// TestRunArgvViaLinuxBackend runs a direct argv (no shell) through the stage-2
// re-exec and asserts it ran and produced the expected output.
func TestRunArgvViaLinuxBackend(t *testing.T) {
	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws), withBackend(newLinuxBackend()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	out, code, err := e.RunArgv(context.Background(), ws, []string{"/bin/echo", "hi"})
	if err != nil {
		t.Fatalf("RunArgv: err = %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("RunArgv exit = %d, want 0 (out=%q)", code, out)
	}
	if got := strings.TrimRight(string(out), "\n"); got != "hi" {
		t.Errorf("RunArgv output = %q, want %q", got, "hi")
	}
}

// TestEnvScrubHoldsViaLinuxBackend proves the stage-2 execve carries the SCRUBBED
// environment: a parent secret is absent in the target while the forced TMPDIR
// (baseline, set by every non-unconfined mode) is present.
func TestEnvScrubHoldsViaLinuxBackend(t *testing.T) {
	ws := t.TempDir()
	t.Setenv("GITHUB_TOKEN", "super-secret") // must NOT reach the target

	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws), withBackend(newLinuxBackend()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	out, code, err := e.RunArgv(context.Background(), ws, []string{"/usr/bin/env"})
	if err != nil {
		// Fall back to printenv location differences by trying /bin/env is not
		// portable; env under /usr/bin is standard on this host. Surface the error.
		t.Fatalf("RunArgv(env): err = %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("RunArgv(env) exit = %d, want 0 (out=%q)", code, out)
	}
	if strings.Contains(string(out), "GITHUB_TOKEN") {
		t.Errorf("secret GITHUB_TOKEN leaked into target env; out=%q", out)
	}
	if !strings.Contains(string(out), "TMPDIR=") {
		t.Errorf("baseline TMPDIR missing from scrubbed target env; out=%q", out)
	}
	if strings.Contains(string(out), stage2SentinelEnv) {
		t.Errorf("dispatch sentinel %s leaked into target env; out=%q", stage2SentinelEnv, out)
	}
}

// TestStage2SpecCodecRoundTrip is the codec unit test: encoding then decoding a
// stage2Spec through the same gob helpers the re-exec uses yields an equal spec.
func TestStage2SpecCodecRoundTrip(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		spec stage2Spec
	}{
		{name: "typical", spec: stage2Spec{Dir: "/work", Argv: []string{"/bin/sh", "-c", "echo hi"}, Env: []string{"TMPDIR=/tmp", "A=b"}}},
		{name: "empty dir + single argv", spec: stage2Spec{Dir: "", Argv: []string{"/bin/true"}, Env: []string{}}},
		{name: "nil slices", spec: stage2Spec{Dir: "/x"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var buf bytes.Buffer
			if err := encodeStage2Spec(&buf, tt.spec); err != nil {
				t.Fatalf("encodeStage2Spec: %v", err)
			}
			got, err := decodeStage2Spec(fileFromBuf(t, &buf))
			if err != nil {
				t.Fatalf("decodeStage2Spec: %v", err)
			}
			if got.Dir != tt.spec.Dir {
				t.Errorf("Dir = %q, want %q", got.Dir, tt.spec.Dir)
			}
			if !slicesEqual(got.Argv, tt.spec.Argv) {
				t.Errorf("Argv = %v, want %v", got.Argv, tt.spec.Argv)
			}
			if !slicesEqual(got.Env, tt.spec.Env) {
				t.Errorf("Env = %v, want %v", got.Env, tt.spec.Env)
			}
		})
	}
}

// fileFromBuf writes buf to a temp file and reopens it for reading, so the codec
// helpers (which take *os.File, as fd 3 is) can be exercised without a pipe.
func fileFromBuf(t *testing.T, buf *bytes.Buffer) *os.File {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "spec")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

// slicesEqual compares two string slices, treating nil and empty as equal (gob
// decodes an empty slice as nil, which is semantically identical here).
func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestDecodeStage2SpecFailsClosed asserts a garbage/truncated payload yields a
// typed stage2Error rather than a zero-value spec that would let the child
// proceed — the decode seam fails closed.
func TestDecodeStage2SpecFailsClosed(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	buf.WriteString("this is not a gob stream")
	_, err := decodeStage2Spec(fileFromBuf(t, &buf))
	if err == nil {
		t.Fatal("decodeStage2Spec on garbage: err = nil, want a decode error")
	}
	var se *stage2Error
	if !errors.As(err, &se) {
		t.Fatalf("decode error = %T (%v), want *stage2Error", err, err)
	}
}

// TestStage2FailsClosedWithoutSpec re-execs the test binary with only the
// dispatch sentinel set and NO spec pipe (no fd 3). The child's TestMain -> Init
// -> runStage2 must fail closed: read the missing spec, fail to decode, and exit
// non-zero — it must NEVER fall through to run the test suite (exit 0).
func TestStage2FailsClosedWithoutSpec(t *testing.T) {
	cmd := exec.Command("/proc/self/exe")
	cmd.Env = append(os.Environ(), stage2SentinelEnv+"="+stage2SentinelValue)
	// Deliberately no ExtraFiles: fd 3 is absent in the child.
	err := cmd.Run()
	if err == nil {
		t.Fatal("stage-2 child without a spec exited 0; want a fail-closed non-zero exit")
	}
	var ee *exec.ExitError
	if !errors.As(err, &ee) {
		t.Fatalf("stage-2 child error = %T (%v), want *exec.ExitError", err, err)
	}
	if ee.ExitCode() == 0 {
		t.Fatalf("stage-2 child exit = 0, want non-zero fail-closed code")
	}
}

// TestRunArgvBareNameResolvesPATH proves the #5 fix: a direct argv whose argv[0]
// is a BARE name (no slash) is PATH-resolved in stage-2 against the target's own
// PATH, so RunArgv is a faithful drop-in for the null/seatbelt backends (which
// PATH-resolve via exec.Command). Without the fix syscall.Exec would fail with
// ENOENT on a bare name.
func TestRunArgvBareNameResolvesPATH(t *testing.T) {
	ws := t.TempDir()
	e, err := newExecutorForEffectivePolicy(backendFixturePolicy(fixtureWorkspaceWrite, ws), withBackend(newLinuxBackend()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	// "echo" bare (not "/bin/echo"): the stage-2 child must resolve it via PATH.
	out, code, err := e.RunArgv(context.Background(), ws, []string{"echo", "hi"})
	if err != nil {
		t.Fatalf("RunArgv(bare echo): err = %v (out=%q)", err, out)
	}
	if code != 0 {
		t.Fatalf("RunArgv(bare echo) exit = %d, want 0 (out=%q)", code, out)
	}
	if got := strings.TrimRight(string(out), "\n"); got != "hi" {
		t.Errorf("RunArgv(bare echo) output = %q, want %q", got, "hi")
	}
}

// TestLookPathIn unit-tests the target-PATH resolver used by stage-2.
func TestLookPathIn(t *testing.T) {
	dir := t.TempDir()
	// A real executable and a non-executable file in dir.
	exe := filepath.Join(dir, "tool")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	nonExe := filepath.Join(dir, "data")
	if err := os.WriteFile(nonExe, []byte("x"), 0o644); err != nil {
		t.Fatalf("write nonexe: %v", err)
	}

	tests := []struct {
		name    string
		bin     string
		env     []string
		want    string
		wantErr bool
	}{
		{"resolves executable in PATH", "tool", []string{"PATH=" + dir}, exe, false},
		{"non-executable file is not resolved", "data", []string{"PATH=" + dir}, "", true},
		{"missing binary errors", "absent", []string{"PATH=" + dir}, "", true},
		{"no PATH in env errors", "tool", []string{"HOME=/x"}, "", true},
		{"last PATH assignment wins", "tool", []string{"PATH=/nonexistent", "PATH=" + dir}, exe, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := lookPathIn(tt.bin, tt.env)
			if (err != nil) != tt.wantErr {
				t.Fatalf("lookPathIn(%q) err = %v, wantErr %v", tt.bin, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("lookPathIn(%q) = %q, want %q", tt.bin, got, tt.want)
			}
		})
	}
}
