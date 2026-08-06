//go:build integration

package exec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/looprig/sandbox/internal/windows"
	"github.com/looprig/sandbox/pkg/sandboxtest"
	win "golang.org/x/sys/windows"
)

// This file is Task 22C's tagged integration coverage for the Windows ConPTY
// path, proving what process_conpty_windows_test.go's own captureBackend
// test double (see that file's own top-of-file doc comment) structurally
// cannot: that a real production Windows backend — restricted or elevated —
// preserves its own security posture through a ConPTY-backed (TTY: true)
// spawn exactly like it already does through the plain pipe-backed path.
//
// TestIntegrationConPTYRestricted is this task's decisive containment proof:
// before Task 22C's fix to createSuspended (process_tree_windows.go), a
// ConPTY-backed launch against the real restrictedBackend ran the child under
// the CALLER's own full token instead of the restricted one — the Job
// containment still held, but the entire token/ACL restriction was silently
// dropped. That write-denial assertion, below, is the one that would have
// been red before the fix and is green after it.
//
// TestIntegrationConPTYElevated proves the opposite, already-reviewed
// contract still holds under a REAL elevated broker, not just the fake
// launchOnlyBackend unit test: PrepareProcess admits TTY: true (ttySupported
// is platform-wide true) but Start fails closed with ErrProcessTTYUnsupported,
// because the elevated/broker backend has no ConPTY wiring of its own
// (startBackendOwned, process.go). Its own control run (TTY: false) proves
// the broker itself is genuinely live, so the TTY rejection is not merely a
// broken/unavailable broker masquerading as a deliberate fail-closed result.
//
// Both tests provision through the same setup machinery
// github.com/looprig/sandbox/sandbox.go's own SetupWindowsSandbox/
// WithWindowsSandboxMode/WithWindowsSandboxStateRoot forward to
// unmodified — internal/windows.Setup/Inspect and this package's own
// WithWindowsSandboxMode/WithWindowsSandboxStateRoot — rather than a fake or
// partial setup: package exec cannot import the top-level sandbox facade
// itself without an import cycle (sandbox imports exec), but every call
// below is the exact same production function that facade forwards to,
// performing the identical real work (installing the broker service,
// projecting ACLs, minting restricted tokens, etc.) — never a shortcut that
// would make either test's proof vacuous.

// TestIntegrationConPTYRestricted exercises the REAL production
// restrictedBackend end to end through a ConPTY-backed (TTY: true) spawn —
// no captureBackend test double — mirroring
// requireWindowsDisposableStandardSourceToken's own existing callers
// (acceptance_windows_test.go) for the skip-if-unavailable convention this
// exact real-backend exercise already uses elsewhere in this package.
func TestIntegrationConPTYRestricted(t *testing.T) {
	requireWindowsDisposableStandardSourceToken(t)

	workspace := t.TempDir()
	// outside is a sibling directory, never part of workspace or any other
	// projection root this executor's restricted SID will ever be
	// ACL-projected onto (writableProjectionRoots, internal/windows/
	// backend_windows.go): the restricted token's own restricting-SID
	// mechanism denies access to any such location by construction, with no
	// per-test ACL setup required to prove it. The positive control proves
	// this location is ordinarily user-writable at all — a location that
	// were NOT writable to begin with would make the eventual denial
	// meaningless.
	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "conpty-restricted-outside.txt")
	if err := os.WriteFile(outside, []byte("positive"), 0o600); err != nil {
		t.Fatalf("outside write positive control: %v", err)
	}
	if err := os.Remove(outside); err != nil {
		t.Fatalf("remove outside write positive control: %v", err)
	}

	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Allow, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		WithWindowsSandboxMode(windows.RestrictedToken))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("conpty-restricted")
	if err != nil {
		t.Fatalf("For: %v", err)
	}

	// A real, live interactive round trip through the REAL restricted
	// backend, mirroring TestProcessConPTYInteractive
	// (process_conpty_windows_test.go) exactly, but with no captureBackend
	// test double standing in for it.
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: `findstr "^"`, ExecutionID: "conpty-restricted-echo", TTY: true,
	})
	if err != nil {
		t.Fatalf("PrepareProcess (echo): %v", err)
	}
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start (echo): %v", err)
	}
	if proc.StreamMode() != ProcessStreamModePTY {
		t.Fatalf("StreamMode() = %v, want ProcessStreamModePTY (a silent pipe fallback would report Pipes instead)", proc.StreamMode())
	}
	if _, err := proc.Stdin().Write([]byte("hello-restricted-conpty\r\n")); err != nil {
		t.Fatalf("Stdin.Write: %v", err)
	}
	conPTYReadUntilContains(t, proc.Stdout(), "hello-restricted-conpty", 5*time.Second)
	if err := proc.Stdin().Close(); err != nil {
		t.Fatalf("Stdin.Close: %v", err)
	}
	result, err := proc.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait (echo): %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("echo ExitCode = %d, want 0", result.ExitCode)
	}
	// Process.Close only closes this Process's own I/O streams (stdin/stdout/
	// stderr/terminal) — mirroring TestProcessConPTYCloseAfterNaturalExit's
	// own doc comment exactly, now exercised through the real backend instead
	// of captureBackend. The actual Job-emptiness proof is a SEPARATE,
	// stronger guarantee this test asserts below via set.Close(): see that
	// call's own doc comment for why.
	if err := proc.Close(context.Background()); err != nil {
		t.Fatalf("Close (echo) after natural exit = %v, want nil", err)
	}

	// The decisive containment proof: from inside a SECOND real restricted
	// ConPTY child, attempt to write to outside — a location this restricted
	// token was never granted. Before Task 22C's fix, createSuspended
	// launched via raw windows.CreateProcess, which never reads
	// cmd.SysProcAttr.Token at all: the ConPTY-spawned child ran with the
	// CALLER's own full token instead of the restricted one, so this exact
	// write would have SUCCEEDED and the assertions below would have failed.
	// After the fix, createSuspended launches via CreateProcessAsUser with
	// the identical restricted token configureRestrictedSpawn already built,
	// so the write is denied exactly like the non-TTY pipe-backed path
	// already proves elsewhere in this package's own acceptance coverage
	// (acceptance_windows_test.go).
	writeCommand := "echo denied-write> " + quoteCmdArgument(outside)
	writePrepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: writeCommand, ExecutionID: "conpty-restricted-write", TTY: true,
	})
	if err != nil {
		t.Fatalf("PrepareProcess (write): %v", err)
	}
	writeProc, err := writePrepared.Start(context.Background())
	if err != nil {
		t.Fatalf("Start (write): %v", err)
	}
	if writeProc.StreamMode() != ProcessStreamModePTY {
		t.Fatalf("StreamMode() = %v, want ProcessStreamModePTY", writeProc.StreamMode())
	}
	writeResult, err := writeProc.Wait(context.Background())
	if err != nil {
		t.Fatalf("Wait (write): %v", err)
	}
	if writeResult.ExitCode == 0 {
		t.Fatalf("write ExitCode = 0, want nonzero (cmd.exe's own redirection should have failed to open a location this restricted token was never granted)")
	}
	if _, statErr := os.Stat(outside); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("outside write landed despite a denied restricted token — FAIL-OPEN: stat err = %v", statErr)
	}
	if err := writeProc.Close(context.Background()); err != nil {
		t.Fatalf("Close (write) after natural exit = %v, want nil", err)
	}

	// The real Job-emptiness proof: ExecutorSet.Close's own
	// lifecycle.waitCleanup (executor_lifecycle.go) blocks on a WaitGroup
	// that PreparedProcess.supervise's background goroutine (process.go) only
	// releases once spawn.prover.terminateAndWait() — this Windows Job's own
	// WaitActiveProcessesZero — has returned a successful proof for EVERY
	// spawn this executor made, including through the asynchronous
	// quarantine-reaper retry path (process_quarantine.go) if the first
	// attempt did not observe zero immediately. set.Close() returning at all
	// is therefore already conclusive: it cannot return before both this
	// test's ConPTY-spawned Jobs have genuinely reached zero active
	// processes. A nil error additionally confirms every other release step
	// (handle/grant/spawn cleanup) succeeded too.
	if err := set.Close(); err != nil {
		t.Fatalf("set.Close() = %v, want nil (both ConPTY spawns' Jobs must be left empty and cleaned up)", err)
	}
}

// TestIntegrationConPTYElevated proves 22B's own fail-closed guard
// (startBackendOwned, process.go: "p.options.TTY is rejected here, first,
// before anything else") holds under a REAL elevated broker installation,
// not merely the fake launchOnlyBackend unit test. It provisions through
// internal/windows.Setup/Inspect — the exact functions
// github.com/looprig/sandbox's own SetupWindowsSandbox/InspectWindowsSandbox
// forward to unmodified — mirroring internal/windows/
// elevated_integration_windows_test.go's own TestElevatedDisposableAcceptance
// gating and setup flow (reimplemented here because package exec cannot
// import the top-level sandbox facade without an import cycle: sandbox
// itself imports exec).
func TestIntegrationConPTYElevated(t *testing.T) {
	sandboxtest.RequireLiveGate(t, sandboxtest.LiveGate{
		OptInEnv: "SANDBOX_WINDOWS_ELEVATED_TEST", Description: "installed elevated ConPTY fail-closed proof",
		Supported: elevatedConPTYWorkerSupported,
		Evidence:  elevatedConPTYWorkerPrerequisites,
	})

	config := elevatedConPTYSetupConfig(t)
	setupCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := windows.Setup(setupCtx, config); err != nil {
		t.Fatalf("setup elevated Windows sandbox: %v", err)
	}
	status, err := windows.Inspect(context.Background(), config)
	if err != nil {
		t.Fatalf("inspect elevated Windows sandbox: %v", err)
	}
	if !status.Ready || len(status.Problems) != 0 {
		t.Fatalf("elevated setup is not ready: %+v", status)
	}

	workspace := t.TempDir()
	prof := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	set, err := NewExecutorSet(prof, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		WithWindowsSandboxMode(windows.Elevated), WithWindowsSandboxStateRoot(config.StateRoot))
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("conpty-elevated")
	if err != nil {
		t.Fatalf("For: %v", err)
	}

	// The control run FIRST: a TTY: false request through the SAME real
	// elevated broker must succeed. Without this, a TTY rejection below would
	// be indistinguishable from "the broker itself is broken or unavailable"
	// masquerading as a deliberate fail-closed result — this run is what
	// proves the broker genuinely works, so the TTY-specific rejection that
	// follows is a real, targeted proof and not a vacuous pass.
	if _, code, runErr := executor.RunCommand(context.Background(), workspace, portableSuccessCommand()); runErr != nil || code != 0 {
		t.Fatalf("TTY:false control run through the real elevated broker: code=%d err=%v, want (0, nil)", code, runErr)
	}

	marker := filepath.Join(workspace, "conpty-elevated-marker")
	prepared, err := executor.PrepareProcess(context.Background(), ProcessOptions{
		Directory: workspace, Command: portableWriteCommand(marker, "spawned"),
		ExecutionID: "conpty-elevated-tty", TTY: true,
	})
	if err != nil {
		t.Fatalf("PrepareProcess(TTY:true) = %v, want admission at prepare time (ttySupported is platform-wide true on Windows)", err)
	}
	defer func() { _ = prepared.Close() }()
	proc, err := prepared.Start(context.Background())
	if !errors.Is(err, ErrProcessTTYUnsupported) {
		t.Fatalf("Start(TTY:true) error = %v, want it to wrap ErrProcessTTYUnsupported", err)
	}
	if proc != nil {
		// Defensive only: if a future change makes Start succeed without real
		// ConPTY wiring for the elevated backend, do not leak the process this
		// test never expected to exist.
		_ = proc.Signal(context.Background(), ProcessSignalKill)
		_, _ = proc.Wait(context.Background())
		t.Fatal("Start returned a non-nil Process alongside ErrProcessTTYUnsupported")
	}

	// The core proof: the spawn was rejected before any target process was
	// ever created, so the target never ran and never wrote its marker.
	time.Sleep(2 * time.Second)
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("marker exists even though TTY was rejected before any spawn: stat err = %v", statErr)
	}
}

// elevatedConPTYWorkerSupported mirrors elevatedWorkerSupported
// (internal/windows/elevated_integration_windows_test.go) exactly: a
// supported Windows 11/Server disposable worker with an already-elevated
// token.
func elevatedConPTYWorkerSupported() (bool, string) {
	version := win.RtlGetVersion()
	supported := version.MajorVersion == 10 && version.MinorVersion == 0 &&
		((version.ProductType == 1 && version.BuildNumber >= 22000) || version.ProductType == 2 || version.ProductType == 3)
	if !supported {
		return false, fmt.Sprintf("supported Windows 11/Server worker is required; got product=%d build=%d", version.ProductType, version.BuildNumber)
	}
	if !win.GetCurrentProcessToken().IsElevated() {
		return false, "elevated worker token is required"
	}
	return true, ""
}

// elevatedConPTYWorkerPrerequisites mirrors elevatedWorkerPrerequisites
// (internal/windows/elevated_integration_windows_test.go): the harness
// itself must carry no ambient Job authority, and every SANDBOX_WINDOWS_*
// setup variable the same live elevated CI job already exports must be
// present and well-formed.
func elevatedConPTYWorkerPrerequisites() (bool, string) {
	var inJob uint32
	ok, _, callErr := win.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob").
		Call(uintptr(win.CurrentProcess()), 0, uintptr(unsafe.Pointer(&inJob)))
	if ok == 0 {
		return false, fmt.Sprintf("query ambient Job membership: %v", callErr)
	}
	if inJob != 0 {
		return false, "elevated disposable worker must not place the test harness in an ambient Job"
	}
	for _, name := range []string{
		"SANDBOX_WINDOWS_HOST_BINARY", "SANDBOX_WINDOWS_STATE_ROOT",
		"SANDBOX_WINDOWS_INSTALLATION_ID", "SANDBOX_WINDOWS_PROXY_PORTS",
		"SANDBOX_WINDOWS_RUNTIME_EVIDENCE",
	} {
		if strings.TrimSpace(os.Getenv(name)) == "" {
			return false, name + " is required"
		}
	}
	for _, name := range []string{"SANDBOX_WINDOWS_HOST_BINARY", "SANDBOX_WINDOWS_RUNTIME_EVIDENCE"} {
		path := os.Getenv(name)
		if !filepath.IsAbs(path) {
			return false, name + " must be absolute"
		}
		if info, statErr := os.Stat(path); statErr != nil || info.IsDir() {
			return false, name + " is missing or not a file"
		}
	}
	root := os.Getenv("SANDBOX_WINDOWS_STATE_ROOT")
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return false, "SANDBOX_WINDOWS_STATE_ROOT must be canonical and absolute"
	}
	return true, ""
}

// elevatedConPTYSetupConfig mirrors elevatedSetupConfig
// (internal/windows/elevated_integration_windows_test.go), reading the same
// SANDBOX_WINDOWS_* variables the owning CI job already exports.
func elevatedConPTYSetupConfig(t *testing.T) windows.SetupConfig {
	t.Helper()
	var ports []uint16
	for _, raw := range strings.Split(os.Getenv("SANDBOX_WINDOWS_PROXY_PORTS"), ",") {
		value, err := strconv.ParseUint(strings.TrimSpace(raw), 10, 16)
		if err != nil {
			t.Fatalf("invalid SANDBOX_WINDOWS_PROXY_PORTS value %q: %v", raw, err)
		}
		ports = append(ports, uint16(value))
	}
	return windows.SetupConfig{
		InstallationID:      os.Getenv("SANDBOX_WINDOWS_INSTALLATION_ID"),
		StateRoot:           os.Getenv("SANDBOX_WINDOWS_STATE_ROOT"),
		HostBinary:          os.Getenv("SANDBOX_WINDOWS_HOST_BINARY"),
		ProxyPorts:          ports,
		RuntimeEvidencePath: os.Getenv("SANDBOX_WINDOWS_RUNTIME_EVIDENCE"),
	}
}
