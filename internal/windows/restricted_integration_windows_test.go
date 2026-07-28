//go:build windows

package windows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
	win "golang.org/x/sys/windows"
)

const restrictedDisposableGate = "SANDBOX_WINDOWS_DISPOSABLE_RESTRICTED_TEST"

func requireRestrictedDisposableWorker(t *testing.T) {
	t.Helper()
	if os.Getenv(restrictedDisposableGate) != "1" {
		t.Skip(restrictedDisposableGate + "=1 is required; this skip is an outstanding live phase gate, not a pass")
	}
	var token win.Token
	if err := win.OpenProcessToken(win.CurrentProcess(), win.TOKEN_QUERY, &token); err != nil {
		t.Fatalf("inspect disposable-worker token: %v", err)
	}
	defer token.Close()
	if err := ValidateDisposableStandardUserToken(token); err != nil {
		t.Fatalf("validate disposable-worker source token: %v", err)
	}
}

func TestRestrictedDisposableDirectAdversarialMatrix(t *testing.T) {
	requireRestrictedDisposableWorker(t)
	helper := buildEscapeProbe(t)
	fixture := t.TempDir()
	workspace := filepath.Join(fixture, "workspace")
	sibling := filepath.Join(fixture, "sibling")
	profileRoot := filepath.Join(fixture, "profile")
	stateRoot := filepath.Join(fixture, "state")
	deniedLong := filepath.Join(workspace, "LongDeniedDirectoryName")
	gitRoot := filepath.Join(workspace, ".git")
	for _, directory := range []string{workspace, sibling, profileRoot, stateRoot, deniedLong, gitRoot} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	symlink := filepath.Join(workspace, "symlink-out")
	if err := os.Symlink(sibling, symlink); err != nil {
		t.Fatalf("disposable worker must permit directory symlink fixtures: %v", err)
	}
	junction := filepath.Join(workspace, "junction-out")
	if output, err := exec.Command("cmd.exe", "/D", "/S", "/C", fmt.Sprintf(`mklink /J "%s" "%s"`, junction, sibling)).CombinedOutput(); err != nil {
		t.Fatalf("disposable worker must permit junction fixtures: %v: %s", err, output)
	}

	hardlinkTarget := filepath.Join(sibling, "hardlink-target.txt")
	if err := os.WriteFile(hardlinkTarget, []byte("baseline"), 0o600); err != nil {
		t.Fatal(err)
	}
	hardlinkAlias := filepath.Join(workspace, "hardlink-alias.txt")
	if err := os.Link(hardlinkTarget, hardlinkAlias); err != nil {
		t.Fatalf("create hard-link fixture: %v", err)
	}
	adsCarrier := filepath.Join(deniedLong, "carrier.txt")
	if err := os.WriteFile(adsCarrier, []byte("carrier"), 0o600); err != nil {
		t.Fatal(err)
	}

	otherRoot := os.Getenv("SANDBOX_WINDOWS_OTHER_DRIVE_ROOT")
	if otherRoot == "" || strings.EqualFold(filepath.VolumeName(otherRoot), filepath.VolumeName(workspace)) {
		t.Fatal("SANDBOX_WINDOWS_OTHER_DRIVE_ROOT must name a writable directory on a distinct supported local volume")
	}
	otherFixture, err := os.MkdirTemp(otherRoot, "sandbox-restricted-other-drive-")
	if err != nil {
		t.Fatalf("create other-drive fixture: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(otherFixture) })

	shortDenied := mustShortPath(t, deniedLong)
	if strings.EqualFold(shortDenied, deniedLong) {
		t.Fatal("8.3 fixture did not produce a distinct short path; enable 8.3 names on the disposable volume")
	}

	// Positive control for the root-swap denial below: before compilation owns
	// no-delete identity handles, the exact same populated workspace root must be
	// renameable and restorable by this standard-user worker.
	assertUnleasedRootRenameControl(t, workspace)

	p := policy.Effective{
		Workspace: workspace,
		FS: []policy.FSEntry{
			{Path: workspace, Access: policy.AllAccess},
			{Path: gitRoot, Denied: policy.WriteAccess},
			{Path: deniedLong, Denied: policy.WriteAccess},
			{Path: sibling, Denied: policy.WriteAccess},
			{Path: profileRoot, Denied: policy.WriteAccess},
			{Path: stateRoot, Denied: policy.WriteAccess},
			{Path: otherFixture, Denied: policy.WriteAccess},
		},
		ProjectionRoots:    []string{workspace},
		Env:                policy.EnvPolicy{Inherit: false},
		Isolation:          profile.Sandboxed,
		RequiredGuarantees: profile.GuaranteeEnvScrub,
	}
	runtime := NewRestrictedRuntime(stateRoot)
	t.Cleanup(func() {
		if err := runtime.Close(); err != nil {
			t.Errorf("close restricted runtime: %v", err)
		}
	})
	backend := newRestrictedBackend(Config{Mode: RestrictedToken}, runtime)
	spec, report, level, bits, err := backend.Compile(p)
	if err != nil {
		t.Fatalf("compile production restricted backend: %v", err)
	}
	t.Cleanup(func() {
		if err := spec.Release(); err != nil {
			t.Errorf("release restricted spec: %v", err)
		}
	})
	if level != profile.LevelNone || bits != profile.GuaranteeEnvScrub {
		t.Fatalf("restricted claims = level %d bits %#x", level, bits)
	}
	for _, entry := range report.Entries {
		if entry.Status == "Enforced" && entry.Feature != "environment" {
			t.Fatalf("restricted report overclaims enforcement: %+v", entry)
		}
	}

	inside := filepath.Join(workspace, "inside.txt")
	if output, err := runRestrictedProbe(context.Background(), spec, helper, "write", inside, "inside"); err != nil {
		t.Fatalf("inside write denied: %v: %s", err, output)
	}
	outsideReadable := filepath.Join(sibling, "readable.txt")
	if err := os.WriteFile(outsideReadable, []byte("outside-readable"), 0o600); err != nil {
		t.Fatal(err)
	}
	if control, err := exec.Command(helper, "read", outsideReadable).CombinedOutput(); err != nil || string(control) != "outside-readable" {
		t.Fatalf("unconfined outside-read positive control = %q, %v", control, err)
	}
	// NUL is the ordinary Win32 null-device baseline. Keep it separate from
	// actual raw/device namespace probes so a DOS alias is never presented as
	// evidence that raw namespaces were denied.
	assertUnconfinedWriteControl(t, helper, "NUL")
	if output, err := runRestrictedProbe(context.Background(), spec, helper, "write", "NUL", "restricted-null-baseline"); err != nil {
		t.Fatalf("restricted runtime-baseline NUL became unusable: %v: %s", err, output)
	}
	deviceTarget := filepath.Join(deniedLong, "device-namespace.txt")
	deviceAlias := globalRootAlias(t, deviceTarget)
	t.Run("raw-device-namespace", func(t *testing.T) {
		assertUnconfinedWriteControl(t, helper, deviceAlias)
		output, err := runRestrictedProbe(context.Background(), spec, helper, "write", deviceAlias, "restricted")
		if err == nil {
			t.Fatalf("restricted GLOBALROOT device-namespace write unexpectedly succeeded: %s", output)
		}
		if data, readErr := os.ReadFile(deviceTarget); readErr == nil && string(data) == "restricted" {
			t.Fatal("restricted device-namespace marker was written despite failing process")
		}
	})
	if output, err := runRestrictedProbe(context.Background(), spec, helper, "read", outsideReadable); err != nil || string(output) != "outside-readable" {
		t.Fatalf("WRITE_RESTRICTED unexpectedly acted as a read boundary: %q, %v", output, err)
	}

	denials := []struct {
		name string
		path string
	}{
		{"profile", filepath.Join(profileRoot, "marker.txt")},
		{"sibling", filepath.Join(sibling, "marker.txt")},
		{"git", filepath.Join(gitRoot, "marker.txt")},
		{"state", filepath.Join(stateRoot, "marker.txt")},
		{"other-drive", filepath.Join(otherFixture, "marker.txt")},
		{"symlink", filepath.Join(symlink, "marker.txt")},
		{"junction", filepath.Join(junction, "marker.txt")},
		{"case-fold", strings.ToUpper(filepath.Join(deniedLong, "case.txt"))},
		{"extended", `\\?\` + filepath.Join(deniedLong, "extended.txt")},
		{"8dot3", filepath.Join(shortDenied, "short.txt")},
		{"ads", adsCarrier + ":sandbox-stream"},
	}
	for _, test := range denials {
		t.Run(test.name, func(t *testing.T) {
			assertUnconfinedWriteControl(t, helper, test.path)
			output, err := runRestrictedProbe(context.Background(), spec, helper, "write", test.path, "restricted")
			if err == nil {
				t.Fatalf("restricted write unexpectedly succeeded: %s", output)
			}
			if data, readErr := os.ReadFile(test.path); readErr == nil && string(data) == "restricted" {
				t.Fatal("denied marker was written despite failing process")
			}
		})
	}

	t.Run("hardlink", func(t *testing.T) {
		if output, err := exec.Command(helper, "write", hardlinkAlias, "unconfined-control").CombinedOutput(); err != nil {
			t.Fatalf("unconfined hard-link positive control failed: %v: %s", err, output)
		}
		if err := os.WriteFile(hardlinkTarget, []byte("baseline"), 0o600); err != nil {
			t.Fatal(err)
		}
		if output, err := runRestrictedProbe(context.Background(), spec, helper, "write", hardlinkAlias, "restricted"); err == nil {
			t.Fatalf("hard-link write unexpectedly succeeded: %s", output)
		}
		if data, err := os.ReadFile(hardlinkTarget); err != nil || string(data) != "baseline" {
			t.Fatalf("hard-link target changed: %q, %v", data, err)
		}
	})

	t.Run("root-swap", func(t *testing.T) {
		if err := os.Rename(workspace, workspace+"-swapped"); err == nil {
			_ = os.Rename(workspace+"-swapped", workspace)
			t.Fatal("compiled root was replaceable while its ACL lease was active")
		}
	})
}

func globalRootAlias(t *testing.T, path string) string {
	t.Helper()
	volume := filepath.VolumeName(path)
	if len(volume) != 2 || volume[1] != ':' {
		t.Fatalf("GLOBALROOT fixture lacks a DOS drive volume: %q", path)
	}
	name, err := win.UTF16PtrFromString(volume)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, 1024)
	n, err := win.QueryDosDevice(name, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 {
		t.Fatalf("QueryDosDevice(%q): n=%d err=%v", volume, n, err)
	}
	device := win.UTF16ToString(buffer[:n])
	relative := strings.TrimPrefix(path, volume)
	return `\\?\GLOBALROOT` + device + relative
}

func assertUnleasedRootRenameControl(t *testing.T, root string) {
	t.Helper()
	swapped := root + "-unleased-rename-control"
	if err := os.Rename(root, swapped); err != nil {
		t.Fatalf("unleased root-swap positive control cannot rename workspace: %v", err)
	}
	restored := false
	t.Cleanup(func() {
		if !restored {
			_ = os.Rename(swapped, root)
		}
	})
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		_ = os.Rename(swapped, root)
		restored = true
		t.Fatalf("unleased root-swap positive control left original root visible: %v", err)
	}
	if info, err := os.Stat(swapped); err != nil || !info.IsDir() {
		_ = os.Rename(swapped, root)
		restored = true
		t.Fatalf("unleased root-swap positive control did not move directory: info=%v err=%v", info, err)
	}
	if err := os.Rename(swapped, root); err != nil {
		t.Fatalf("unleased root-swap positive control cannot restore workspace: %v", err)
	}
	restored = true
}

func TestUnleasedRootRenamePositiveControl(t *testing.T) {
	root := filepath.Join(t.TempDir(), "workspace")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "populated.marker")
	if err := os.WriteFile(marker, []byte("preserved"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertUnleasedRootRenameControl(t, root)
	if contents, err := os.ReadFile(marker); err != nil || string(contents) != "preserved" {
		t.Fatalf("rename-and-restore did not preserve populated root: contents=%q err=%v", contents, err)
	}
}

func TestRestrictedDisposableJournalRecoveryAndSIDNonReuse(t *testing.T) {
	requireRestrictedDisposableWorker(t)
	helper := buildEscapeProbe(t)
	root := t.TempDir()
	journal, err := OpenRestrictedJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = journal.Close() })
	makeExactProjection := func(name string) (string, SID, *ACLProjection) {
		t.Helper()
		target := filepath.Join(root, name)
		if err := os.WriteFile(target, []byte("baseline"), 0o600); err != nil {
			t.Fatal(err)
		}
		generator, err := NewOneShotSIDGenerator(nil, journal)
		if err != nil {
			t.Fatal(err)
		}
		sid, err := generator.Next()
		if err != nil {
			t.Fatal(err)
		}
		binding, err := policy.CapturePathBinding(target)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := policy.AcquirePathHandle(&binding, binding.CanonicalPath, true)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = handle.Close() })
		identity, err := identityFromHandle(win.Handle(handle.NativeHandle()), handle.Target())
		if err != nil {
			t.Fatal(err)
		}
		var lease ACLLeaseID
		copy(lease[:], []byte("task12-live-lease"))
		lease[0] ^= byte(len(name))
		plan, err := BuildACLPlan(ACLPlanRequest{LeaseID: lease, SID: sid, Scope: ACLScopeExact, Access: ACLWrite, Root: identity})
		if err != nil {
			t.Fatal(err)
		}
		projection, err := NewRestrictedACLProjection(plan, []*policy.PathHandle{handle}, journal)
		if err != nil {
			t.Fatal(err)
		}
		if err := projection.Apply(); err != nil {
			_ = projection.Close()
			t.Fatal(err)
		}
		return target, sid, projection
	}

	t.Run("next-construction-sweep", func(t *testing.T) {
		_, _, projection := makeExactProjection("recover.txt")
		reopened, report, err := OpenRestrictedJournalAndSweep(root, RestrictedACLCleaner{})
		if err != nil {
			t.Fatal(err)
		}
		if reopened == nil || report.Removed == 0 {
			t.Fatalf("next construction did not recover live journaled allow: %+v", report)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		if err := projection.Close(); err != nil {
			t.Fatalf("trusted close after recovery: %v", err)
		}
	})

	t.Run("deleted-journal-stale-sid-is-inert", func(t *testing.T) {
		target, staleSID, projection := makeExactProjection("stale.txt")
		if output, err := exec.Command(helper, "write", target, "unconfined-control").CombinedOutput(); err != nil {
			t.Fatalf("unconfined stale-target positive control: %v: %s", err, output)
		}
		if err := os.WriteFile(target, []byte("baseline"), 0o600); err != nil {
			t.Fatal(err)
		}
		records, err := os.ReadDir(journal.recordsDir)
		if err != nil || len(records) == 0 {
			t.Fatalf("journal record missing before hostile deletion: %v", err)
		}
		for _, record := range records {
			if err := os.Remove(filepath.Join(journal.recordsDir, record.Name())); err != nil {
				t.Fatal(err)
			}
		}
		newSID, err := newRetiredExecutorSID(bytes.NewReader(bytes.Repeat([]byte{0x5a}, sidEntropyBytes)), journal, root)
		if err != nil {
			t.Fatal(err)
		}
		if newSID == staleSID {
			t.Fatal("retired stale SID was reused")
		}
		spec := enforce.Spec{Wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd) error, func()) {
			var cleanup func()
			return argv, func(cmd *exec.Cmd) (err error) {
					cleanup, err = configureRestrictedSpawn(cmd, []SID{newSID})
					return err
				}, func() {
					if cleanup != nil {
						cleanup()
					}
				}
		}}
		if output, err := runRestrictedProbe(context.Background(), spec, helper, "write", target, "new-sid"); err == nil {
			t.Fatalf("stale ACE authorized a never-before-issued SID: %s", output)
		}
		if data, err := os.ReadFile(target); err != nil || string(data) != "baseline" {
			t.Fatalf("stale target changed: %q, %v", data, err)
		}
		if err := projection.Close(); err != nil {
			t.Fatalf("trusted close after hostile record deletion: %v", err)
		}
	})

	t.Run("corrupt-journal-is-not-grant-authority", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(journal.recordsDir, strings.Repeat("a", 64)+".json"), []byte(`{"forged":true}`), 0o600); err != nil {
			t.Fatal(err)
		}
		reopened, report, err := OpenRestrictedJournalAndSweep(root, RestrictedACLCleaner{})
		if err != nil {
			t.Fatal(err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		if report.Corrupt == 0 || report.Retained == 0 {
			t.Fatalf("forged journal was not retained as inert corruption: %+v", report)
		}
	})
}

func TestRestrictedDisposableJobUIAndHandleCanaries(t *testing.T) {
	requireRestrictedDisposableWorker(t)
	job, err := NewJob(JobOptions{Sandboxed: true, MaxProcesses: 4, MaxMemoryBytes: 128 << 20, MaxCPUPct: 50})
	if err != nil {
		t.Fatal(err)
	}
	defer job.Close()
	if !job.ResourceLimitsInstalled() {
		t.Fatal("Job read-back did not confirm requested resource/UI restrictions")
	}
	if _, err := handleGrantedAccess(job.Handle()); err != nil {
		t.Fatalf("Job handle canary is invalid: %v", err)
	}
	// The exhaustive inherited-handle process probe is shared with Task 7; run
	// it here under the same disposable gate so this milestone cannot omit it.
	helper := buildHandleProbe(t)
	runHandleProbe(t, helper, createHandleCanaries(t))
}

func runRestrictedProbe(ctx context.Context, spec enforce.Spec, helper string, args ...string) ([]byte, error) {
	argv, configure, cleanup := spec.Wrap("", append([]string{helper}, args...))
	defer cleanup()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if configure != nil {
		if err := configure(cmd); err != nil {
			return output.Bytes(), err
		}
	}
	handleCleanup, err := ConfigureExplicitHandleList(cmd, nil)
	if err != nil {
		return output.Bytes(), err
	}
	defer handleCleanup()
	err = cmd.Run()
	return output.Bytes(), err
}

func assertUnconfinedWriteControl(t *testing.T, helper, target string) {
	t.Helper()
	cmd := exec.Command(helper, "write", target, "unconfined-control")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("unconfined positive control cannot write %q: %v: %s", target, err, output)
	}
	if target != "NUL" {
		if err := os.Remove(target); err != nil && !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("remove positive-control marker %q: %v", target, err)
		}
	}
}

func mustShortPath(t *testing.T, path string) string {
	t.Helper()
	input, err := win.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, win.MAX_PATH)
	n, err := win.GetShortPathName(input, &buffer[0], uint32(len(buffer)))
	if err != nil || n == 0 || n >= uint32(len(buffer)) {
		t.Fatalf("GetShortPathName(%q): n=%d err=%v", path, n, err)
	}
	return win.UTF16ToString(buffer[:n])
}

func buildEscapeProbe(t *testing.T) string {
	t.Helper()
	output := filepath.Join(t.TempDir(), "escapeprobe.exe")
	command := exec.Command("go", "build", "-o", output, "./testdata/escapeprobe")
	command.Dir = filepath.Dir(mustCurrentTestFile(t))
	if buildOutput, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build escape probe: %v: %s", err, buildOutput)
	}
	return output
}

func mustCurrentTestFile(t *testing.T) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("locate restricted integration test source")
	}
	return source
}
