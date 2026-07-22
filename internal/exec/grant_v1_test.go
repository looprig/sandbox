package exec

import (
	"context"
	"errors"
	"fmt"
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type captureBackend struct {
	mu                  sync.Mutex
	policies            []policy.Effective
	bits                uint64
	compileErr          error
	compileErrAfter     int
	compileErrorRelease func() error
	release             func() error
	releaseForCompile   func(int) func() error
	cleanup             func()
}

type boundaryBackend struct {
	captureBackend
	baseBits uint64
}

func (b *boundaryBackend) Compile(pol policy.Effective) (enforce.Spec, CompileReport, uint8, uint64, error) {
	b.captureBackend.mu.Lock()
	b.captureBackend.policies = append(b.captureBackend.policies, policy.Clone(pol))
	b.captureBackend.mu.Unlock()
	bits := b.baseBits
	if policy.ResolveFS(pol.FS, string(os.PathSeparator))&policy.ReadAccess != 0 {
		bits &^= GuaranteeReadBoundary
	}
	if policy.ResolveFS(pol.FS, string(os.PathSeparator))&policy.WriteAccess != 0 {
		bits &^= GuaranteeWriteBoundary
	}
	spec := enforce.Spec{Wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd) error, func()) { return argv, nil, nil }}
	return spec, CompileReport{}, LevelFull, bits, nil
}

func (b *captureBackend) Compile(pol policy.Effective) (enforce.Spec, CompileReport, uint8, uint64, error) {
	b.mu.Lock()
	b.policies = append(b.policies, policy.Clone(pol))
	compileNumber := len(b.policies)
	b.mu.Unlock()
	if b.compileErr != nil && (b.compileErrAfter == 0 || compileNumber >= b.compileErrAfter) {
		return enforce.Spec{Release: b.compileErrorRelease}, CompileReport{}, LevelNone, 0, b.compileErr
	}
	release := b.release
	if b.releaseForCompile != nil {
		release = b.releaseForCompile(compileNumber)
	}
	spec := enforce.Spec{
		Wrap:    func(_ string, argv []string) ([]string, func(*exec.Cmd) error, func()) { return argv, nil, b.cleanup },
		Release: release,
	}
	return spec, CompileReport{}, LevelNone, b.bits, nil
}

func TestGrantPartialCompileSpecReleasedAndErrorsPreserved(t *testing.T) {
	now := time.Date(2026, 7, 21, 13, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	target := filepath.Join(workspace, "generated.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	compileErr := errors.New("transient compile failed")
	releaseErr := errors.New("transient partial release failed")
	var releases atomic.Int32
	backend := &captureBackend{
		bits:            GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		compileErr:      compileErr,
		compileErrAfter: 2,
		compileErrorRelease: func() error {
			releases.Add(1)
			return releaseErr
		},
	}
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(backend), withClock(func() time.Time { return now })))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = set.Close() })
	executor, err := set.For("partial-compile")
	if err != nil {
		t.Fatal(err)
	}
	token := issueTestGrant(t, executor, now, "exec-partial", "true", workspace,
		"filesystem.write", target, "filesystem.path.write.v1", target)
	_, _, err = executor.RunCommandWithGrants(context.Background(), "exec-partial", workspace, "true", []string{token})
	if !errors.Is(err, compileErr) || !errors.Is(err, releaseErr) {
		t.Fatalf("RunCommandWithGrants error = %v, want compile and release errors", err)
	}
	if got := releases.Load(); got != 1 {
		t.Fatalf("partial grant spec release count = %d, want 1", got)
	}
}

func (b *captureBackend) lastPolicy() policy.Effective {
	b.mu.Lock()
	defer b.mu.Unlock()
	return policy.Clone(b.policies[len(b.policies)-1])
}

func TestGrantCompiledSpecReleasedAfterSpawn(t *testing.T) {
	now := time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	target := filepath.Join(workspace, "generated.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	var releases atomic.Int32
	var spawnCleaned atomic.Bool
	var lifecycle *executorLifecycle
	backend := &captureBackend{
		bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub,
		release: func() error {
			if releases.Add(1) != 1 {
				return nil
			}
			if !spawnCleaned.Load() {
				t.Error("grant spec released before spawn cleanup and process-tree wait completed")
			}
			leaseDone := make(chan struct{})
			go func() {
				lifecycle.wait()
				close(leaseDone)
			}()
			select {
			case <-leaseDone:
			case <-time.After(100 * time.Millisecond):
				t.Error("grant spec released while its execution lease was still active")
			}
			return nil
		},
		cleanup: func() { spawnCleaned.Store(true) },
	}
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1),
		withExecutorSetConfig(withBackend(backend), withClock(func() time.Time { return now })))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := set.For("release")
	if err != nil {
		t.Fatal(err)
	}
	lifecycle = executor.lifecycle
	if got := releases.Load(); got != 0 {
		t.Fatalf("release count after base compile = %d, want 0", got)
	}
	token := issueTestGrant(t, executor, now, "exec-release", "true", workspace,
		"filesystem.write", target, "filesystem.path.write.v1", target)
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-release", workspace, "true", []string{token}); err != nil {
		t.Fatalf("RunCommandWithGrants: %v", err)
	}
	if got := releases.Load(); got != 1 {
		t.Fatalf("release count after grant spawn = %d, want transient spec released once while base spec remains owned", got)
	}
	if err := set.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := releases.Load(); got != 2 {
		t.Fatalf("release count after set close = %d, want transient and base specs released once each", got)
	}
}

func TestGrantVersionAndCommandStart(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	executor, err := newTestExecutor(profile,
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

func TestGrantReplayStateExpiresAndPrunes(t *testing.T) {
	base := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	now := base
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	executor, err := newTestExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
		withClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	expiry := base.Add(time.Minute)
	token, err := executor.IssueGrant(context.Background(), "boundary", "true", workspace,
		"command.execute", "", "command.start.v1", "true", expiry.UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "boundary", workspace, "true", []string{token}); err != nil {
		t.Fatal(err)
	}
	now = expiry
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "boundary", workspace, "true", []string{token}); !errors.Is(err, ErrGrantReplay) {
		t.Fatalf("replay at exact expiry error = %v, want ErrGrantReplay", err)
	}
	now = expiry.Add(time.Millisecond)
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "boundary", workspace, "true", []string{token}); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("token after expiry error = %v, want ErrGrantExpired after replay-state pruning", err)
	}
	if got := len(executor.usedGrants); got != 0 {
		t.Fatalf("expired replay entries = %d, want 0", got)
	}
}

func TestGrantReplayStateRemainsBoundedAfterHighVolumeExpiry(t *testing.T) {
	base := time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC)
	now := base
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	executor, err := newTestExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
		withClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	const volume = 256
	for index := range volume {
		executionID := fmt.Sprintf("volume-%03d", index)
		token, err := executor.IssueGrant(context.Background(), executionID, "true", workspace,
			"command.execute", "", "command.start.v1", "true", base.Add(time.Minute).UnixMilli())
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := executor.RunCommandWithGrants(context.Background(), executionID, workspace, "true", []string{token}); err != nil {
			t.Fatalf("consume grant %d: %v", index, err)
		}
	}
	if got := len(executor.usedGrants); got != volume {
		t.Fatalf("live replay entries = %d, want %d", got, volume)
	}

	now = base.Add(time.Minute + time.Millisecond)
	fresh := issueTestGrant(t, executor, now, "fresh", "true", workspace,
		"command.execute", "", "command.start.v1", "true")
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "fresh", workspace, "true", []string{fresh}); err != nil {
		t.Fatal(err)
	}
	if got := len(executor.usedGrants); got != 1 {
		t.Fatalf("replay entries after expiry and one fresh grant = %d, want 1", got)
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
	executor, err := newTestExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
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
	executor, err := newTestExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
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
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	backend := &captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}
	executor, err := newTestExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	token := issueTestGrant(t, executor, now, "exec-fs", "true", workspace,
		"filesystem.write", target, "filesystem.path.write.v1", target)
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-fs", workspace, "true", []string{token}); err != nil {
		t.Fatalf("RunCommandWithGrants: %v", err)
	}
	if got := policy.ResolveFS(backend.lastPolicy().FS, target); got&policy.WriteAccess == 0 {
		t.Fatalf("verified filesystem grant did not alter compiled policy: access %d", got)
	}
	if got := policy.ResolveFS(backend.lastPolicy().FS, target+"/child"); got&policy.WriteAccess != 0 {
		t.Fatalf("path grant widened recursively to a child: access %d", got)
	}

	tree := issueTestGrant(t, executor, now, "exec-tree", "true", workspace,
		"filesystem.write", "tree:"+workspace, "filesystem.tree.write.v1", workspace)
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-tree", workspace, "true", []string{tree}); err != nil {
		t.Fatalf("RunCommandWithGrants tree: %v", err)
	}
	if got := policy.ResolveFS(backend.lastPolicy().FS, target+"/child"); got&policy.WriteAccess == 0 {
		t.Fatalf("tree grant did not apply recursively: access %d", got)
	}

	drift := issueTestGrant(t, executor, now, "exec-drift", "true", workspace,
		"filesystem.write", target, "filesystem.path.write.v1", target)
	executor.guaranteeBits ^= GuaranteeWriteBoundary
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-drift", workspace, "true", []string{drift}); !errors.Is(err, ErrGrantGuaranteeMismatch) {
		t.Fatalf("guarantee drift error = %v, want ErrGrantGuaranteeMismatch", err)
	}
}

func TestFilesystemGrantRejectsTargetAndAncestorIdentitySwaps(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Gated,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Allow,
	})
	newExecutor := func() *Executor {
		executor, err := newTestExecutor(profile,
			withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
			withClock(func() time.Time { return now }))
		if err != nil {
			t.Fatal(err)
		}
		return executor
	}

	t.Run("target replaced by symlink", func(t *testing.T) {
		target := filepath.Join(workspace, "target")
		outside := filepath.Join(t.TempDir(), "outside")
		for _, path := range []string{target, outside} {
			if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		executor := newExecutor()
		token := issueTestGrant(t, executor, now, "exec-target-swap", "true", workspace,
			"filesystem.write", target, "filesystem.path.write.v1", target)
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, target); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-target-swap", workspace, "true", []string{token}); !errors.Is(err, ErrGrantTargetChanged) {
			t.Fatalf("target swap error = %v, want ErrGrantTargetChanged", err)
		}
	})

	t.Run("existing Ancestor replaced by symlink", func(t *testing.T) {
		Ancestor := filepath.Join(workspace, "generated")
		outside := t.TempDir()
		if err := os.Mkdir(Ancestor, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(Ancestor, "future.txt")
		executor := newExecutor()
		token := issueTestGrant(t, executor, now, "exec-Ancestor-swap", "true", workspace,
			"filesystem.write", target, "filesystem.path.write.v1", target)
		if err := os.Rename(Ancestor, Ancestor+".old"); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, Ancestor); err != nil {
			t.Fatal(err)
		}
		if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-Ancestor-swap", workspace, "true", []string{token}); !errors.Is(err, ErrGrantTargetChanged) {
			t.Fatalf("Ancestor swap error = %v, want ErrGrantTargetChanged", err)
		}
	})
}

func TestBroadHostGrantAppliesRootAuthorityAndExpectedGuaranteeDelta(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Gated, HostWrite: Gated, Network: Deny, Command: Allow,
	})
	backend := &boundaryBackend{baseBits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}
	executor, err := newTestExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	token := issueTestGrant(t, executor, now, "exec-host-read", "true", workspace,
		"filesystem.read", "host:*", "filesystem.host.read.v1", "host:*")
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-host-read", workspace, "true", []string{token}); err != nil {
		t.Fatalf("RunCommandWithGrants host read: %v", err)
	}
	if got := policy.ResolveFS(backend.lastPolicy().FS, string(os.PathSeparator)); got&policy.ReadAccess == 0 {
		t.Fatalf("host read grant did not apply at filesystem root: access %#x", got)
	}

	writeBackend := &boundaryBackend{baseBits: GuaranteeReadBoundary | GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}
	writeExecutor, err := newTestExecutor(profile, withBackend(writeBackend), withClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	writeToken := issueTestGrant(t, writeExecutor, now, "exec-host-write", "true", workspace,
		"filesystem.write", "host:*", "filesystem.host.write.v1", "host:*")
	if _, _, err := writeExecutor.RunCommandWithGrants(context.Background(), "exec-host-write", workspace, "true", []string{writeToken}); err != nil {
		t.Fatalf("RunCommandWithGrants host write: %v", err)
	}
	if got := policy.ResolveFS(writeBackend.lastPolicy().FS, string(os.PathSeparator)); got&policy.WriteAccess == 0 {
		t.Fatalf("host write grant did not apply at filesystem root: access %#x", got)
	}
}

func TestBroadNetworkGrantIncludesDNSForHostnameResolution(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Gated, Command: Allow,
	})
	backend := &captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}
	executor, err := newTestExecutor(profile, withBackend(backend), withClock(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	token := issueTestGrant(t, executor, now, "exec-network-broad", "true", workspace,
		"network", "", "network.broad.v1", "tcp:*:443")
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-network-broad", workspace, "true", []string{token}); err != nil {
		t.Fatalf("RunCommandWithGrants network broad: %v", err)
	}
	pol := backend.lastPolicy()
	if !policy.ContainsPort(pol.Net.Ports, 443) || !pol.Net.DNS {
		t.Fatalf("broad network policy = %+v, want port 443 plus DNS", pol.Net)
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
		withExecutorSetConfig(withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}), withClock(func() time.Time { return now })))
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
		executor, err := newTestExecutor(profile,
			withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
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
	profileExecutor.settings.Fingerprint = "drifted"
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
