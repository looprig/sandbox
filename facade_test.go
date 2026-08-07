package sandbox_test

import (
	"context"
	"errors"
	"io"
	"runtime"
	"testing"
	"time"

	"github.com/looprig/sandbox"
)

// This file is the guard on the public surface. Every identifier below is one
// that a real consumer outside this module references today — coderig and the
// looprig integration-test module — so if a future refactor moves something out
// of the facade without re-exporting it, this file stops compiling here rather
// than in someone else's repository.
//
// It is an EXTERNAL test package (sandbox_test) on purpose: it can only reach
// the exported surface, exactly as a consumer does.

func TestFacadeExportsTheConsumedSurface(t *testing.T) {
	var (
		_ sandbox.WindowsSandboxMode    = sandbox.WindowsAuto
		_ sandbox.ExecutorSetOption     = sandbox.WithWindowsSandboxMode(sandbox.WindowsRestrictedToken)
		_ sandbox.ExecutorSetOption     = sandbox.WithWindowsSandboxStateRoot(`C:\ProgramData\Looprig`)
		_ []sandbox.WindowsSetupProblem = sandbox.WindowsSetupStatus{}.Problems
	)

	// Authority enums and their values.
	var (
		_ sandbox.Access    = sandbox.Deny
		_ sandbox.Access    = sandbox.Gated
		_ sandbox.Access    = sandbox.Allow
		_ sandbox.Home      = sandbox.IsolatedHome
		_ sandbox.Home      = sandbox.RealHome
		_ sandbox.Isolation = sandbox.Sandboxed
		_ sandbox.Isolation = sandbox.Unconfined
	)

	// Achieved levels and guarantee bits.
	var (
		_ uint8  = sandbox.LevelNone
		_ uint8  = sandbox.LevelDegraded
		_ uint8  = sandbox.LevelFull
		_ uint64 = sandbox.GuaranteeProcessBoundary | sandbox.GuaranteeWriteBoundary |
			sandbox.GuaranteeReadBoundary | sandbox.GuaranteeEnvScrub |
			sandbox.GuaranteeNetworkBoundary | sandbox.GuaranteeAddressNetwork |
			sandbox.GuaranteeResourceLimits | sandbox.GuaranteeTargetNetwork
	)

	// Profile construction, including every ProfileConfig field.
	workspace := t.TempDir()
	config := sandbox.ProfileConfig{
		WorkspaceRoot:   workspace,
		WorkspaceRead:   sandbox.Allow,
		WorkspaceWrite:  sandbox.Allow,
		HostRead:        sandbox.Allow,
		HostWrite:       sandbox.Deny,
		Network:         sandbox.Gated,
		Command:         sandbox.Gated,
		Home:            sandbox.IsolatedHome,
		Isolation:       sandbox.Sandboxed,
		AdditionalRoots: []sandbox.RootAccess{},
		AckUnconfined:   false,
	}
	if runtime.GOOS == "windows" {
		// The no-installation facade smoke uses guarantees available in the
		// restricted tier; elevated guarantee probes run only on its disposable
		// worker gate.
		config.HostWrite = sandbox.Allow
		config.Network = sandbox.Allow
	}
	profile, err := sandbox.NewProfile(config)
	if err != nil {
		t.Fatalf("NewProfile: %v", err)
	}
	if profile.AccessVersion() != 1 {
		t.Fatalf("AccessVersion = %d, want 1", profile.AccessVersion())
	}
	if _, err := profile.AccessFor("command.execute", ""); err != nil {
		t.Fatalf("AccessFor: %v", err)
	}
	if profile.Fingerprint() == "" {
		t.Fatal("Fingerprint is empty")
	}
	if _, err := sandbox.Restrict(profile, profile); err != nil {
		t.Fatalf("Restrict: %v", err)
	}

	// Egress vocabulary.
	direct, err := sandbox.NewDirectEgressRoute()
	if err != nil {
		t.Fatalf("NewDirectEgressRoute: %v", err)
	}
	var (
		_ sandbox.EgressRoute = direct
		_ bool                = direct.TargetGuarantee()
		_ bool                = direct.AddressGuarantee()
		_ string              = direct.Fingerprint()
	)
	if _, err := sandbox.NewUpstreamEgressRoute("http://proxy.example:8080", false); err != nil {
		t.Fatalf("NewUpstreamEgressRoute: %v", err)
	}
	target, err := sandbox.ParseNetworkTarget("tcp:service.example:443")
	if err != nil {
		t.Fatalf("ParseNetworkTarget: %v", err)
	}
	var _ sandbox.NetworkTarget = target
	if _, err := sandbox.NewEgressRouteResolver(
		[]sandbox.EgressRoute{direct},
		func(context.Context, sandbox.NetworkTarget) string { return "" },
	); err != nil {
		t.Fatalf("NewEgressRouteResolver: %v", err)
	}

	// Executor ownership: every option a consumer passes today.
	options := []sandbox.ExecutorSetOption{
		sandbox.WithScratchRoot(t.TempDir()),
		sandbox.WithMaxExecutors(1),
		sandbox.WithGrantTTL(time.Minute),
	}
	// This portable facade test must not require an installed elevated broker;
	// its purpose is API-surface coverage, not the disposable-worker live gate.
	if runtime.GOOS == "windows" {
		options = append(options, sandbox.WithWindowsSandboxMode(sandbox.WindowsRestrictedToken))
	} else {
		options = append(options, sandbox.WithEgressRoute(direct))
	}
	set, err := sandbox.NewExecutorSet(profile, options...)
	if err != nil {
		t.Fatalf("NewExecutorSet: %v", err)
	}
	t.Cleanup(func() { _ = set.Close() })
	var _ *sandbox.ExecutorSet = set

	executor, err := set.For("facade")
	if err != nil {
		t.Fatalf("ExecutorSet.For: %v", err)
	}
	var (
		_          *sandbox.Executor     = executor
		_          uint8                 = executor.Level()
		_          uint16                = executor.GrantVersion()
		_          uint64                = executor.GuaranteeBits()
		_          sandbox.CompileReport = executor.Report()
		guarantees                       = executor.Guarantees()
		_          sandbox.Guarantees    = guarantees
		_          bool                  = guarantees.ProcessBoundary && guarantees.WriteBoundary &&
			guarantees.ReadBoundary && guarantees.EnvScrub && guarantees.NetworkBoundary &&
			guarantees.AddressNetwork && guarantees.ResourceLimits && guarantees.TargetNetwork
	)
	for _, entry := range executor.Report().Entries {
		var _ sandbox.ReportEntry = entry
	}

	// A Gated command with no grant must ask for one rather than run.
	if _, _, err := executor.RunCommand(context.Background(), workspace, "true"); !errors.Is(err, sandbox.ErrGrantRequired) {
		t.Fatalf("gated RunCommand error = %v, want ErrGrantRequired", err)
	}
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "facade-exec", workspace, "true", nil); err == nil {
		t.Fatal("RunCommandWithGrants with no grants unexpectedly succeeded")
	}
	if _, err := executor.IssueGrant(context.Background(), "facade-exec", "true", workspace,
		"command.execute", "", sandbox.GrantClassCommandStart, "true",
		time.Now().Add(time.Minute).UnixMilli()); err != nil {
		t.Fatalf("IssueGrant: %v", err)
	}

	// Pipe-backed asynchronous process API: prepare, start, stream, and wait
	// on a single trivially-successful command. A Gated Command authority (set
	// above) demands at least one grant be present, and PrepareProcess
	// cryptographically verifies and consumes it exactly like
	// RunCommandWithGrants, so this must be a real, freshly-minted grant
	// bound to this exact command/execution/cwd rather than a placeholder.
	processGrant, err := executor.IssueGrant(context.Background(), "facade-process", facadeProcessSuccessCommand(), workspace,
		"command.execute", "", sandbox.GrantClassCommandStart, facadeProcessSuccessCommand(),
		time.Now().Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatalf("IssueGrant (process): %v", err)
	}
	prepared, err := executor.PrepareProcess(context.Background(), sandbox.ProcessOptions{
		Directory:   workspace,
		Command:     facadeProcessSuccessCommand(),
		ExecutionID: "facade-process",
		Grants:      []string{processGrant},
	})
	if err != nil {
		t.Fatalf("PrepareProcess: %v", err)
	}
	var (
		_ sandbox.ProcessAccess       = prepared.EffectiveAccess()
		_ sandbox.ProcessAccessKind   = sandbox.ProcessAccessReadOnly
		_ sandbox.ProcessAccessKind   = sandbox.ProcessAccessScopedWrite
		_ sandbox.ProcessAccessKind   = sandbox.ProcessAccessBroadWrite
		_ sandbox.LifetimeContainment = sandbox.LifetimeContainmentUnspecified
		_ sandbox.LifetimeContainment = sandbox.LifetimeContainmentEnforced
		_ sandbox.LifetimeContainment = sandbox.LifetimeContainmentBestEffort
	)
	// Darwin now takes the same success path as every other platform: the
	// real Seatbelt-backed backend attaches a best-effort supervised proof
	// (process-group SIGKILL plus descendant tracking) instead of failing
	// Start closed (SPEC's earlier Task 12c fail-closed contract was
	// superseded by the best-effort downgrade — see
	// docs/lifetime-containment.md). This untagged test therefore spawns a
	// real Seatbelt-confined process on dev Macs — sandbox-exec is present on
	// every macOS install, and proving the public surface end to end is
	// exactly this file's job. Process/Wait/Close all tolerate a nil receiver
	// (documented, deliberate zero-value safety) regardless.
	proc, err := prepared.Start(context.Background())
	if err != nil {
		t.Fatalf("PreparedProcess.Start: %v", err)
	}
	if runtime.GOOS == "darwin" {
		if got := proc.LifetimeContainment(); got != sandbox.LifetimeContainmentBestEffort {
			t.Fatalf("Process.LifetimeContainment on darwin = %v, want %v", got, sandbox.LifetimeContainmentBestEffort)
		}
	}
	var (
		_ io.ReadCloser  = proc.Stdout()
		_ io.ReadCloser  = proc.Stderr()
		_ io.WriteCloser = proc.Stdin()
	)
	result, err := proc.Wait(context.Background())
	if err != nil {
		t.Fatalf("Process.Wait: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("Process.Wait ExitCode = %d, want 0", result.ExitCode)
	}
	var _ sandbox.ProcessResult = result
	if err := proc.Close(context.Background()); err != nil {
		t.Fatalf("Process.Close: %v", err)
	}
	if err := prepared.Close(); err != nil {
		t.Fatalf("PreparedProcess.Close (post-start no-op): %v", err)
	}

	var (
		_ sandbox.ProcessActivityKind = sandbox.ProcessActivityWrite
		_ sandbox.ProcessActivityKind = sandbox.ProcessActivityBroadWrite
		_ sandbox.ProcessActivity     = sandbox.ProcessActivity{Kind: sandbox.ProcessActivityWrite}
	)
}

// facadeProcessSuccessCommand mirrors the internal/exec package's portable
// test-fixture command strings, kept local here since this file deliberately
// only reaches the exported surface (see the package doc above).
func facadeProcessSuccessCommand() string {
	if runtime.GOOS == "windows" {
		return "exit /b 0"
	}
	return "true"
}

func TestFacadeWindowsSetupUnavailableOnNonWindows(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("non-Windows contract")
	}
	config := sandbox.WindowsSetupConfig{}
	if _, err := sandbox.InspectWindowsSandbox(context.Background(), config); !errors.Is(err, sandbox.ErrSandboxUnavailable) {
		t.Fatalf("InspectWindowsSandbox error = %v, want ErrSandboxUnavailable", err)
	}
	if err := sandbox.SetupWindowsSandbox(context.Background(), config); !errors.Is(err, sandbox.ErrSandboxUnavailable) {
		t.Fatalf("SetupWindowsSandbox error = %v, want ErrSandboxUnavailable", err)
	}
	if err := sandbox.RemoveWindowsSandbox(context.Background(), config); !errors.Is(err, sandbox.ErrSandboxUnavailable) {
		t.Fatalf("RemoveWindowsSandbox error = %v, want ErrSandboxUnavailable", err)
	}
}

// TestFacadeExportsTheConsumedSentinels pins the error values consumers match
// with errors.Is. A sentinel that silently becomes a different value is the
// failure mode this catches: it would compile everywhere and match nowhere.
func TestFacadeExportsTheConsumedSentinels(t *testing.T) {
	for name, err := range map[string]error{
		"ErrInvalidProfile":                 sandbox.ErrInvalidProfile,
		"ErrSandboxUnavailable":             sandbox.ErrSandboxUnavailable,
		"ErrWindowsSetupRequired":           sandbox.ErrWindowsSetupRequired,
		"ErrWindowsSetupStale":              sandbox.ErrWindowsSetupStale,
		"ErrWindowsElevationRequired":       sandbox.ErrWindowsElevationRequired,
		"ErrExecutorClosed":                 sandbox.ErrExecutorClosed,
		"ErrExecutorSetClosed":              sandbox.ErrExecutorSetClosed,
		"ErrExecutorLimit":                  sandbox.ErrExecutorLimit,
		"ErrEgressRouteDenied":              sandbox.ErrEgressRouteDenied,
		"ErrNetworkTargetDenied":            sandbox.ErrNetworkTargetDenied,
		"ErrGrantRequired":                  sandbox.ErrGrantRequired,
		"ErrGrantDenied":                    sandbox.ErrGrantDenied,
		"ErrGrantMalformed":                 sandbox.ErrGrantMalformed,
		"ErrGrantExpired":                   sandbox.ErrGrantExpired,
		"ErrGrantReplay":                    sandbox.ErrGrantReplay,
		"ErrGrantUnsupported":               sandbox.ErrGrantUnsupported,
		"ErrLifetimeContainmentUnavailable": sandbox.ErrLifetimeContainmentUnavailable,
		"ErrGrantBadMAC":                    sandbox.ErrGrantBadMAC,
		"ErrGrantWrongCommand":              sandbox.ErrGrantWrongCommand,
		"ErrGrantWrongExecution":            sandbox.ErrGrantWrongExecution,
		"ErrGrantWrongWorkingDirectory":     sandbox.ErrGrantWrongWorkingDirectory,
		"ErrGrantProfileMismatch":           sandbox.ErrGrantProfileMismatch,
		"ErrGrantGuaranteeMismatch":         sandbox.ErrGrantGuaranteeMismatch,
		"ErrGrantRouteMismatch":             sandbox.ErrGrantRouteMismatch,
		"ErrGrantTargetChanged":             sandbox.ErrGrantTargetChanged,
	} {
		if err == nil {
			t.Errorf("%s is nil", name)
			continue
		}
		if !errors.Is(err, err) {
			t.Errorf("%s does not match itself under errors.Is", name)
		}
	}
	if !errors.Is(sandbox.ErrWindowsSetupRequired, sandbox.ErrSandboxUnavailable) {
		t.Error("ErrWindowsSetupRequired does not unwrap to ErrSandboxUnavailable")
	}
	if !errors.Is(sandbox.ErrWindowsSetupStale, sandbox.ErrSandboxUnavailable) {
		t.Error("ErrWindowsSetupStale does not unwrap to ErrSandboxUnavailable")
	}

	// The grant enforcement classes are a shipped wire contract: these exact
	// strings are what a producer outside this module mints against.
	for want, got := range map[string]string{
		"command.start.v1":         sandbox.GrantClassCommandStart,
		"network.proxy-target.v1":  sandbox.GrantClassNetworkProxyTarget,
		"network.broad.v1":         sandbox.GrantClassNetworkBroad,
		"filesystem.path.read.v1":  sandbox.GrantClassFilesystemPathRead,
		"filesystem.tree.read.v1":  sandbox.GrantClassFilesystemTreeRead,
		"filesystem.host.read.v1":  sandbox.GrantClassFilesystemHostRead,
		"filesystem.path.write.v1": sandbox.GrantClassFilesystemPathWrite,
		"filesystem.tree.write.v1": sandbox.GrantClassFilesystemTreeWrite,
		"filesystem.host.write.v1": sandbox.GrantClassFilesystemHostWrite,
	} {
		if got != want {
			t.Errorf("grant class = %q, want %q", got, want)
		}
	}
}

// TestFacadeInitIsCallable pins Init at the root import path, which is where
// every consumer's main() calls it.
func TestFacadeInitIsCallable(t *testing.T) { sandbox.Init() }
