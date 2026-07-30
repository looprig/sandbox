package exec

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/sandbox/pkg/profile"
)

// newProcessTestExecutor builds a minimal, unconfined (Isolation: Unconfined)
// executor with the given Command authority. Unconfined keeps these tests
// backend-independent (selectExecutorBackend resolves straight to
// enforce.NewNull), which matters because this microtask's PrepareProcess/
// Start deliberately do not compile or apply any policy — they only read the
// executor's Settings.Command/WorkspaceWrite, exactly as the rest of this
// file documents.
func newProcessTestExecutor(t *testing.T, command Access) *Executor {
	t.Helper()
	// validateUnconfined requires workspace/host/network access to be Allow
	// for an Isolation: Unconfined profile; Command is the one authority it
	// leaves free, which is exactly what these tests vary.
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot:  t.TempDir(),
		WorkspaceRead:  Allow,
		WorkspaceWrite: Allow,
		HostRead:       Allow,
		HostWrite:      Allow,
		Network:        Allow,
		Command:        command,
		Isolation:      Unconfined,
		AckUnconfined:  true,
	})
	executor, err := newTestExecutor(prof)
	if err != nil {
		t.Fatalf("newTestExecutor: %v", err)
	}
	return executor
}

func portableDistinctStreamsCommand() string {
	if runtime.GOOS == "windows" {
		return "echo out & echo err 1>&2"
	}
	return "printf out; printf err 1>&2"
}

func portableStreamThenSleepCommand(seconds int) string {
	if runtime.GOOS == "windows" {
		return "echo first & " + portableSleepCommand(seconds) + " & echo second"
	}
	return "printf 'first\\n'; " + portableSleepCommand(seconds) + "; printf 'second\\n'"
}

func portableCatCommand() string {
	if runtime.GOOS == "windows" {
		return "more"
	}
	return "cat"
}

// TestPrepareProcessDoesNotSpawn is a queued Phase Gate 3 selector test.
func TestPrepareProcessDoesNotSpawn(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	marker := filepath.Join(dir, "marker")
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory:   dir,
		Command:     portableWriteCommand(marker, "spawned"),
		ExecutionID: "prepare-no-spawn",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	t.Cleanup(func() { _ = prepared.Close() })

	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("PrepareProcess appears to have spawned: marker stat err = %v, want IsNotExist", err)
	}
}

// TestPreparedProcessStartOnce is a queued Phase Gate 3 selector test.
func TestPreparedProcessStartOnce(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableSuccessCommand(), ExecutionID: "start-once",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}

	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("first Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })

	if _, err := prepared.Start(context.Background()); !errors.Is(err, ErrProcessAlreadyStarted) {
		t.Fatalf("second Start error = %v, want ErrProcessAlreadyStarted", err)
	}

	if result, err := proc.Wait(context.Background()); err != nil || result.ExitCode != 0 {
		t.Fatalf("Wait = (%+v, %v), want (ExitCode 0, nil)", result, err)
	}
}

// TestPreparedProcessCloseBeforeStart is a queued Phase Gate 3 selector test.
// It also covers "closing an unstarted preparation releases reservations":
// this microtask reserves nothing beyond validated input, so the only
// observable contract is that Close is idempotent and that it permanently
// prevents Start from spawning anything afterward.
func TestPreparedProcessCloseBeforeStart(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableSuccessCommand(), ExecutionID: "close-before-start",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}

	if err := prepared.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatalf("second Close (idempotent): %v", err)
	}
	if proc, err := prepared.Start(context.Background()); !errors.Is(err, ErrProcessClosed) || proc != nil {
		t.Fatalf("Start after Close = (%v, %v), want (nil, ErrProcessClosed)", proc, err)
	}
}

// TestProcessStreamsBeforeExit is a queued Phase Gate 3 selector test. It
// proves Stdout is a live pipe the caller can read from incrementally, not a
// buffer only populated after the process exits.
func TestProcessStreamsBeforeExit(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableStreamThenSleepCommand(2), ExecutionID: "streams-before-exit",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })

	began := time.Now()
	reader := bufio.NewReader(proc.Stdout())
	line, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("ReadString: %v", err)
	}
	if got := strings.TrimSpace(line); got != "first" {
		t.Fatalf("first line = %q, want %q", got, "first")
	}
	if elapsed := time.Since(began); elapsed >= 2*time.Second {
		t.Fatalf("first line arrived after %s: stdout appears buffered until exit, not streamed", elapsed)
	}

	if result, err := proc.Wait(context.Background()); err != nil || result.ExitCode != 0 {
		t.Fatalf("Wait = (%+v, %v), want (ExitCode 0, nil)", result, err)
	}
}

func TestProcessStdoutStderrDistinctInPipeMode(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableDistinctStreamsCommand(), ExecutionID: "distinct-streams",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })

	var stdoutBuf, stderrBuf bytes.Buffer
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(&stdoutBuf, proc.Stdout()) }()
	go func() { defer wg.Done(); _, _ = io.Copy(&stderrBuf, proc.Stderr()) }()
	wg.Wait()

	if result, err := proc.Wait(context.Background()); err != nil || result.ExitCode != 0 {
		t.Fatalf("Wait = (%+v, %v), want (ExitCode 0, nil)", result, err)
	}

	stdout, stderr := stdoutBuf.String(), stderrBuf.String()
	if !strings.Contains(stdout, "out") || strings.Contains(stdout, "err") {
		t.Fatalf("stdout = %q, want to contain %q and not %q", stdout, "out", "err")
	}
	if !strings.Contains(stderr, "err") || strings.Contains(stderr, "out") {
		t.Fatalf("stderr = %q, want to contain %q and not %q", stderr, "err", "out")
	}
}

func TestProcessStdinWriteAndIdempotentEOF(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableCatCommand(), ExecutionID: "stdin-write-eof",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })

	var stdoutBuf bytes.Buffer
	copyDone := make(chan struct{})
	go func() { defer close(copyDone); _, _ = io.Copy(&stdoutBuf, proc.Stdout()) }()

	if _, err := proc.Stdin().Write([]byte("hello\n")); err != nil {
		t.Fatalf("Stdin Write: %v", err)
	}
	if err := proc.Stdin().Close(); err != nil {
		t.Fatalf("first Stdin Close (EOF): %v", err)
	}
	if err := proc.Stdin().Close(); err != nil {
		t.Fatalf("second Stdin Close (idempotent): %v", err)
	}
	if _, err := proc.Stdin().Write([]byte("late")); !errors.Is(err, ErrProcessStdinClosed) {
		t.Fatalf("Write after Close error = %v, want ErrProcessStdinClosed", err)
	}

	<-copyDone
	if result, err := proc.Wait(context.Background()); err != nil || result.ExitCode != 0 {
		t.Fatalf("Wait = (%+v, %v), want (ExitCode 0, nil)", result, err)
	}
	if got := stdoutBuf.String(); !strings.Contains(got, "hello") {
		t.Fatalf("stdout = %q, want it to contain %q", got, "hello")
	}
}

func TestProcessNonzeroExitIsResult(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableFailureCommand(), ExecutionID: "nonzero-exit",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })

	result, err := proc.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait error = %v, want nil (a ran-but-nonzero process is a result, not an error)", err)
	}
	if result.ExitCode == 0 {
		t.Fatalf("Wait ExitCode = 0, want non-zero")
	}
}

// TestProcessSpawnFailureIsError exercises spawnProcess directly (this file
// is an internal, white-box test) rather than through PrepareProcess/Start,
// because PrepareProcess already rejects a non-existent directory during
// validation; this test isolates the distinct "the OS spawn itself failed"
// failure surface that Start's contract also promises.
func TestProcessSpawnFailureIsError(t *testing.T) {
	proc, err := spawnProcess(ProcessOptions{
		Command:   portableSuccessCommand(),
		Directory: filepath.Join(t.TempDir(), "does-not-exist"),
	})
	if err == nil {
		t.Fatal("spawnProcess with a missing directory unexpectedly succeeded")
	}
	if proc != nil {
		t.Fatalf("spawnProcess returned a non-nil Process alongside an error: %v", proc)
	}
}

func TestProcessWaitCachedForConcurrentCallers(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableFailureCommand(), ExecutionID: "wait-cached",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })

	const callers = 16
	results := make([]ProcessResult, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func(i int) {
			defer wg.Done()
			results[i], errs[i] = proc.Wait(context.Background())
		}(i)
	}
	wg.Wait()

	for i := 1; i < callers; i++ {
		if errs[i] != errs[0] {
			t.Fatalf("caller %d error = %v, want identical to caller 0's %v", i, errs[i], errs[0])
		}
		if results[i] != results[0] {
			t.Fatalf("caller %d result = %+v, want identical to caller 0's %+v", i, results[i], results[0])
		}
	}
	if results[0].ExitCode == 0 {
		t.Fatalf("ExitCode = 0, want the portable failure command's non-zero code")
	}
}

func TestProcessCloseIsIdempotent(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableSleepCommand(0), ExecutionID: "close-idempotent",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	if err := proc.Close(context.Background()); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := proc.Close(context.Background()); err != nil {
		t.Fatalf("second Close (idempotent): %v", err)
	}

	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait after Close: %v", err)
	}
}

// TestProcessResultExposesNoOSPID guards the public-shape contract by
// reflection so a future field addition cannot silently reintroduce an OS
// process identifier onto the public result type.
func TestProcessResultExposesNoOSPID(t *testing.T) {
	resultType := reflect.TypeOf(ProcessResult{})
	for i := 0; i < resultType.NumField(); i++ {
		name := strings.ToLower(resultType.Field(i).Name)
		if strings.Contains(name, "pid") || strings.Contains(name, "processid") {
			t.Fatalf("ProcessResult exposes an OS process identifier field: %s", resultType.Field(i).Name)
		}
	}
}

// TestExecutorEffectiveProcessAccessMapsWorkspaceWriteAuthority tests
// effectiveProcessAccess's mapping directly against a minimal literal
// Executor rather than through a fully constructed profile: NewProfile's
// validateUnconfined requires workspace/host/network access to be Allow on
// every Isolation: Unconfined profile (the only isolation this microtask's
// unconfined os/exec.Cmd spawn is meant to exercise), so a real profile can
// never itself carry a non-Allow WorkspaceWrite alongside Unconfined. The
// mapping logic itself does not care how a Settings value was produced, so
// this is a faithful, isolated unit test of exactly that logic.
func TestExecutorEffectiveProcessAccessMapsWorkspaceWriteAuthority(t *testing.T) {
	anyProfile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: t.TempDir(), WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Allow, Network: Allow, Command: Allow,
		Isolation: Unconfined, AckUnconfined: true,
	})
	tests := []struct {
		name           string
		workspaceWrite Access
		want           ProcessAccessKind
	}{
		{name: "deny is read-only", workspaceWrite: Deny, want: ProcessAccessReadOnly},
		{name: "gated is scoped write", workspaceWrite: Gated, want: ProcessAccessScopedWrite},
		{name: "allow is broad write", workspaceWrite: Allow, want: ProcessAccessBroadWrite},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := &Executor{profile: anyProfile, settings: profile.Settings{WorkspaceWrite: tt.workspaceWrite}}
			got := executor.effectiveProcessAccess()
			if got.Kind != tt.want {
				t.Fatalf("effectiveProcessAccess Kind = %v, want %v", got.Kind, tt.want)
			}
			if paths := got.WritePaths(); paths != nil {
				t.Fatalf("WritePaths = %v, want nil in this microtask", paths)
			}
			if trees := got.WriteTrees(); trees != nil {
				t.Fatalf("WriteTrees = %v, want nil in this microtask", trees)
			}
		})
	}
}

func TestPreparedProcessEffectiveAccessIsAuthoritativeAndImmutable(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableSuccessCommand(), ExecutionID: "effective-access",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}

	first := prepared.EffectiveAccess()
	if first.Kind != ProcessAccessBroadWrite {
		t.Fatalf("EffectiveAccess Kind = %v, want ProcessAccessBroadWrite", first.Kind)
	}

	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })

	// Authoritative: the value observed before Start must be identical to the
	// value observed after, proving Start cannot silently widen or narrow
	// what was already reserved.
	second := prepared.EffectiveAccess()
	if !reflect.DeepEqual(second, first) {
		t.Fatalf("EffectiveAccess changed after Start: before=%+v after=%+v", first, second)
	}

	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	// Immutable across Close too.
	third := prepared.EffectiveAccess()
	if !reflect.DeepEqual(third, first) {
		t.Fatalf("EffectiveAccess changed after Wait: before=%+v after=%+v", first, third)
	}
}

func TestPreparedProcessEffectiveAccessSharesNoBackingStorage(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableSuccessCommand(), ExecutionID: "immutable-backing",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	t.Cleanup(func() { _ = prepared.Close() })

	first := prepared.EffectiveAccess()
	paths := first.WritePaths()
	paths = append(paths, "/should-not-leak")

	second := prepared.EffectiveAccess()
	if len(second.WritePaths()) != 0 {
		t.Fatalf("mutating an earlier WritePaths() call leaked into a later EffectiveAccess(): %v", second.WritePaths())
	}
}

func TestPrepareProcessRejectsTTY(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	if _, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableSuccessCommand(), ExecutionID: "tty-rejected", TTY: true,
	}); !errors.Is(err, ErrProcessTTYUnsupported) {
		t.Fatalf("PrepareProcess with TTY error = %v, want ErrProcessTTYUnsupported", err)
	}
}

func TestPrepareProcessCommandAuthority(t *testing.T) {
	tests := []struct {
		name    string
		command Access
		grants  []string
		wantErr error
	}{
		{name: "deny always refuses", command: Deny, grants: nil, wantErr: ErrGrantDenied},
		{name: "deny refuses even with a grant", command: Deny, grants: []string{"g"}, wantErr: ErrGrantDenied},
		{name: "gated without a grant is refused", command: Gated, grants: nil, wantErr: ErrGrantRequired},
		{name: "gated with a grant is admitted", command: Gated, grants: []string{"g"}, wantErr: nil},
		{name: "allow needs no grant", command: Allow, grants: nil, wantErr: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			executor := newProcessTestExecutor(t, tt.command)
			dir := t.TempDir()
			prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
				Directory: dir, Command: portableSuccessCommand(), ExecutionID: "command-authority", Grants: tt.grants,
			})
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("PrepareProcess error = %v, want %v", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("PrepareProcess: %v", err)
			}
			t.Cleanup(func() { _ = prepared.Close() })
		})
	}
}

func TestProcessActivitiesClosesBeforeWaitReturns(t *testing.T) {
	executor := newProcessTestExecutor(t, Allow)
	dir := t.TempDir()
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: dir, Command: portableSuccessCommand(), ExecutionID: "activities-close-order",
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = proc.Close(context.Background()) })

	if _, err := proc.Wait(context.Background()); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	select {
	case _, ok := <-proc.Activities():
		if ok {
			t.Fatal("Activities channel produced a value; want it already closed once Wait has returned")
		}
	default:
		t.Fatal("Activities channel not yet closed even though Wait already returned")
	}
}

func TestProcessActivityEffectiveKindIsConservativeForInvalidActivity(t *testing.T) {
	valid := ProcessActivity{Kind: ProcessActivityWrite}
	if got := valid.EffectiveKind(); got != ProcessActivityWrite {
		t.Fatalf("EffectiveKind(valid) = %v, want ProcessActivityWrite", got)
	}

	invalid := ProcessActivity{Kind: ProcessActivityKind(99)}
	if got := invalid.EffectiveKind(); got != ProcessActivityBroadWrite {
		t.Fatalf("EffectiveKind(invalid) = %v, want conservative ProcessActivityBroadWrite", got)
	}

	zero := ProcessActivity{}
	if got := zero.EffectiveKind(); got != ProcessActivityBroadWrite {
		t.Fatalf("EffectiveKind(zero) = %v, want conservative ProcessActivityBroadWrite", got)
	}
}
