package sandbox

import (
	"context"
	"errors"
	"os/exec"
	"sync"
	"testing"
	"time"
)

type captureBackend struct {
	mu         sync.Mutex
	policies   []effectivePolicy
	bits       uint64
	compileErr error
}

func (b *captureBackend) compile(policy effectivePolicy) (spawnSpec, CompileReport, uint8, uint64, error) {
	b.mu.Lock()
	b.policies = append(b.policies, cloneEffectivePolicy(policy))
	b.mu.Unlock()
	if b.compileErr != nil {
		return spawnSpec{}, CompileReport{}, LevelNone, 0, b.compileErr
	}
	spec := spawnSpec{wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd), func()) { return argv, nil, nil }}
	return spec, CompileReport{}, LevelNone, b.bits, nil
}

func (b *captureBackend) lastPolicy() effectivePolicy {
	b.mu.Lock()
	defer b.mu.Unlock()
	return cloneEffectivePolicy(b.policies[len(b.policies)-1])
}

func TestGrantVersionAndCommandStart(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	executor, err := NewExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
		withClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	if executor.GrantVersion() != 1 {
		t.Fatalf("GrantVersion = %d, want 1", executor.GrantVersion())
	}

	if _, _, err := executor.RunCommand(context.Background(), workspace, "true"); !errors.Is(err, ErrGrantRequired) {
		t.Fatalf("gated RunCommand error = %v, want ErrGrantRequired", err)
	}
	token := issueTestGrant(t, executor, now, "exec-1", "true", workspace,
		"command.execute", "", "command.start.v1", "true")
	if _, code, err := executor.RunCommandWithGrants(context.Background(), "exec-1", workspace, "true", []string{token}); err != nil || code != 0 {
		t.Fatalf("RunCommandWithGrants = code %d err %v", code, err)
	}
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-1", workspace, "true", []string{token}); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("replay error = %v, want ErrGrantReplay", err)
	}

	wrongCommand := issueTestGrant(t, executor, now, "exec-2", "true", workspace,
		"command.execute", "", "command.start.v1", "true")
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-2", workspace, "false", []string{wrongCommand}); !errors.Is(err, ErrGrantWrongCommand) {
		t.Fatalf("cross-command error = %v, want ErrGrantWrongCommand", err)
	}
	wrongExecution := issueTestGrant(t, executor, now, "exec-3", "true", workspace,
		"command.execute", "", "command.start.v1", "true")
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-other", workspace, "true", []string{wrongExecution}); !errors.Is(err, ErrGrantWrongExecution) {
		t.Fatalf("cross-execution error = %v, want ErrGrantWrongExecution", err)
	}
}

func TestIssueGrantClassesAndBindings(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Gated, WorkspaceWrite: Gated,
		HostRead: Gated, HostWrite: Gated, Network: Gated, Command: Gated,
	})
	backend := &captureBackend{bits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}
	executor, err := NewExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		kind, scope, class, target string
	}{
		{"command.execute", "", "command.start.v1", "true"},
		{"filesystem.read", workspace, "filesystem.path.read.v1", workspace},
		{"filesystem.read", "tree:" + workspace, "filesystem.tree.read.v1", workspace},
		{"filesystem.read", "host:*", "filesystem.host.read.v1", "host:*"},
		{"filesystem.write", workspace, "filesystem.path.write.v1", workspace},
		{"filesystem.write", "tree:" + workspace, "filesystem.tree.write.v1", workspace},
		{"filesystem.write", "host:*", "filesystem.host.write.v1", "host:*"},
		{"network", "", "network.broad.v1", "tcp:*:22"},
	}
	for i, tt := range tests {
		if _, err := executor.IssueGrant(context.Background(), "exec-class", "true", workspace,
			tt.kind, tt.scope, tt.class, tt.target, now.Add(time.Minute).UnixMilli()); err != nil {
			t.Errorf("class %d %s: %v", i, tt.class, err)
		}
	}
	if _, err := executor.IssueGrant(context.Background(), "exec-proxy", "true", workspace,
		"network", "", "network.proxy-target.v1", "tcp:github.com:443", now.Add(time.Minute).UnixMilli()); !errors.Is(err, ErrGrantUnsupported) {
		t.Fatalf("proxy-target error = %v, want ErrGrantUnsupported until proxy enforcement lands", err)
	}
	for _, bad := range []struct{ kind, scope, class, target string }{
		{"command.execute", "", "unknown", "true"},
		{"command.execute", "", "filesystem.path.read.v1", workspace},
		{"filesystem.read", workspace, "filesystem.path.read.v1", "relative"},
		{"network", "", "network.broad.v1", "tcp:*:0"},
	} {
		if _, err := executor.IssueGrant(context.Background(), "exec-bad", "true", workspace,
			bad.kind, bad.scope, bad.class, bad.target, now.Add(time.Minute).UnixMilli()); err == nil {
			t.Errorf("malformed class/target accepted: %#v", bad)
		}
	}
}

func TestIssueGrantRejectsMismatchedScopeAndCommandTarget(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Gated, WorkspaceWrite: Gated,
		HostRead: Deny, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	executor, err := NewExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeEnvScrub}),
		withClock(func() time.Time { return now }),
	)
	if err != nil {
		t.Fatal(err)
	}
	other := workspace + "/other"
	for _, request := range []struct{ scope, class, target string }{
		{workspace, "filesystem.path.read.v1", other},
		{"tree:" + workspace, "filesystem.tree.read.v1", other},
	} {
		if _, err := executor.IssueGrant(context.Background(), "exec-mismatch", "true", workspace,
			"filesystem.read", request.scope, request.class, request.target, now.Add(time.Minute).UnixMilli()); !errors.Is(err, ErrGrantMalformed) {
			t.Errorf("mismatched %s error = %v, want ErrGrantMalformed", request.class, err)
		}
	}
	if _, err := executor.IssueGrant(context.Background(), "exec-mismatch", "true", workspace,
		"command.execute", "", "command.start.v1", "false", now.Add(time.Minute).UnixMilli()); !errors.Is(err, ErrGrantWrongCommand) {
		t.Fatalf("command target mismatch error = %v, want ErrGrantWrongCommand", err)
	}
}

func TestGrantFilesystemDeltaAppliedAndDriftRejected(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	target := workspace + "/generated.txt"
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	backend := &captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}
	executor, err := NewExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	token := issueTestGrant(t, executor, now, "exec-fs", "true", workspace,
		"filesystem.write", target, "filesystem.path.write.v1", target)
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-fs", workspace, "true", []string{token}); err != nil {
		t.Fatalf("RunCommandWithGrants: %v", err)
	}
	if got := resolveFS(backend.lastPolicy().FS, target); got&writeFSAccess == 0 {
		t.Fatalf("verified filesystem grant did not alter compiled policy: access %d", got)
	}

	drift := issueTestGrant(t, executor, now, "exec-drift", "true", workspace,
		"filesystem.write", target, "filesystem.path.write.v1", target)
	executor.guaranteeBits ^= GuaranteeWriteBoundary
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-drift", workspace, "true", []string{drift}); !errors.Is(err, ErrGrantGuaranteeMismatch) {
		t.Fatalf("guarantee drift error = %v, want ErrGrantGuaranteeMismatch", err)
	}
}

func TestGrantCrossExecutorExpiryAndClose(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(2),
		withExecutorSetExecOptions(withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}), withClock(func() time.Time { return now })))
	if err != nil {
		t.Fatal(err)
	}
	a, _ := set.For("a")
	b, _ := set.For("b")
	token := issueTestGrant(t, a, now, "exec-cross", "true", workspace,
		"command.execute", "", "command.start.v1", "true")
	if _, _, err := b.RunCommandWithGrants(context.Background(), "exec-cross", workspace, "true", []string{token}); !errors.Is(err, ErrGrantBadMAC) {
		t.Fatalf("cross-executor error = %v, want ErrGrantBadMAC", err)
	}
	if _, err := a.IssueGrant(context.Background(), "expired", "true", workspace,
		"command.execute", "", "command.start.v1", "true", now.Add(-time.Millisecond).UnixMilli()); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("expired issuance error = %v, want ErrGrantExpired", err)
	}
	if err := set.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.IssueGrant(context.Background(), "closed", "true", workspace,
		"command.execute", "", "command.start.v1", "true", now.Add(time.Minute).UnixMilli()); !errors.Is(err, ErrExecutorClosed) {
		t.Fatalf("IssueGrant after close error = %v, want ErrExecutorClosed", err)
	}
}

func TestGrantRejectsCWDProfileAndRouteDrift(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	otherCWD := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	newExecutor := func() *Executor {
		executor, err := NewExecutor(profile,
			withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeEnvScrub}),
			withClock(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
		return executor
	}

	cwdExecutor := newExecutor()
	cwdToken := issueTestGrant(t, cwdExecutor, now, "exec-cwd", "true", workspace,
		"command.execute", "", "command.start.v1", "true")
	if _, _, err := cwdExecutor.RunCommandWithGrants(context.Background(), "exec-cwd", otherCWD, "true", []string{cwdToken}); !errors.Is(err, ErrGrantWrongWorkingDirectory) {
		t.Fatalf("cwd drift error = %v, want ErrGrantWrongWorkingDirectory", err)
	}

	profileExecutor := newExecutor()
	profileToken := issueTestGrant(t, profileExecutor, now, "exec-profile", "true", workspace,
		"command.execute", "", "command.start.v1", "true")
	profileExecutor.profile.fingerprint = "drifted"
	if _, _, err := profileExecutor.RunCommandWithGrants(context.Background(), "exec-profile", workspace, "true", []string{profileToken}); !errors.Is(err, ErrGrantProfileMismatch) {
		t.Fatalf("profile drift error = %v, want ErrGrantProfileMismatch", err)
	}

	routeExecutor := newExecutor()
	routeToken := issueTestGrant(t, routeExecutor, now, "exec-route", "true", workspace,
		"command.execute", "", "command.start.v1", "true")
	routeExecutor.routeFingerprint = "drifted"
	if _, _, err := routeExecutor.RunCommandWithGrants(context.Background(), "exec-route", workspace, "true", []string{routeToken}); !errors.Is(err, ErrGrantRouteMismatch) {
		t.Fatalf("route drift error = %v, want ErrGrantRouteMismatch", err)
	}
}

func issueTestGrant(t *testing.T, executor *Executor, now time.Time, executionID, command, cwd, kind, scope, class, target string) string {
	t.Helper()
	token, err := executor.IssueGrant(context.Background(), executionID, command, cwd,
		kind, scope, class, target, now.Add(time.Minute).UnixMilli())
	if err != nil {
		t.Fatalf("IssueGrant(%s): %v", class, err)
	}
	return token
}

func mustCanonicalGrantRoot(t *testing.T, path string) string {
	t.Helper()
	canonical, err := canonicalRoot(path)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}
