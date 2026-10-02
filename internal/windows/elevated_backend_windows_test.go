//go:build windows

package windows

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
	win "golang.org/x/sys/windows"
)

type fakeElevatedVerifier struct{ err error }

func (verifier fakeElevatedVerifier) Verify(string, installedPathExpectation) error {
	return verifier.err
}

type fakeElevatedDependencyInspector struct {
	health elevatedDependencyHealth
	err    error
}

func (inspector fakeElevatedDependencyInspector) Inspect(context.Context, string, setupManifest, policy.Effective) (elevatedDependencyHealth, error) {
	return inspector.health, inspector.err
}

type fakeElevatedLease struct {
	mu                sync.Mutex
	account           brokerAccountKind
	acquires          int
	issues            int
	releases          int
	executionReleases int
	issueErr          error
	releaseError      error
	narrowings        []string
}

type fakeElevatedExecutionLease struct{ factory *fakeElevatedLease }

func (lease *fakeElevatedLease) Acquire(context.Context) (elevatedExecutionLease, error) {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.acquires++
	return &fakeElevatedExecutionLease{factory: lease}, nil
}
func (execution *fakeElevatedExecutionLease) IssueToken(account brokerAccountKind) (brokerIssuedToken, error) {
	lease := execution.factory
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.issues++
	lease.account = account
	return brokerIssuedToken{Handle: 123, Desktop: `Sandbox-123\Default`}, lease.issueErr
}
func (execution *fakeElevatedExecutionLease) Release() error {
	lease := execution.factory
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.executionReleases++
	return lease.releaseError
}
func (lease *fakeElevatedLease) Narrowings() []string {
	return append([]string(nil), lease.narrowings...)
}
func (lease *fakeElevatedLease) Release() error {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	lease.releases++
	return lease.releaseError
}

func readyElevatedSnapshot() elevatedSetupSnapshot {
	return elevatedSetupSnapshot{
		Ready: true, InstallationID: "installation", HostPath: `C:\ProgramData\Looprig\slots\generation\sandbox-host.exe`,
		OwnerSID: "S-1-5-32-544", HostSHA256: "digest", Protocol: brokerProtocolVersion, AccountsReady: true,
		CredentialsReady: true, FirewallReady: true, RuntimeBaselineReady: true,
		RunnerHashVerified: true, PrivateDesktopReady: true, JobReadbackReady: true,
		HandleListReady: true, ProxyPorts: []uint16{39002, 49152},
		PipeName: `\\.\pipe\broker`, OfflineSID: "S-1-5-21-1-2-3-1001",
		OnlineSID: "S-1-5-21-1-2-3-1002",
	}
}

func elevatedInspectionFixture(t *testing.T) (Config, setupManifest) {
	t.Helper()
	programData := t.TempDir()
	t.Setenv("ProgramData", programData)
	root := filepath.Join(programData, "Looprig")
	host := filepath.Join(root, "slots", "generation", "sandbox-host.exe")
	if err := os.MkdirAll(filepath.Dir(host), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(host, []byte("runner"), 0600); err != nil {
		t.Fatal(err)
	}
	digest, err := hashFile(host)
	if err != nil {
		t.Fatal(err)
	}
	user, err := win.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}
	manifest := setupManifest{
		Version: setupManifestVersion, State: setupStateReady,
		InstallationID: "fixture", OwnerSID: user.User.Sid.String(),
		OfflineSID: "S-1-5-21-1-2-3-1001", OnlineSID: "S-1-5-21-1-2-3-1002",
		HostPath: filepath.Clean(host), HostSHA256: digest,
		ProxyPorts: []uint16{49152}, Protocol: brokerProtocolVersion,
	}
	return Config{Mode: Elevated, StateRoot: root}, manifest
}

func writeElevatedManifest(t *testing.T, config Config, manifest setupManifest) {
	t.Helper()
	data, err := encodeSetupManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(config.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.StateRoot, readyManifestName), data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestInspectElevatedSetupDistinguishesAbsentCorruptAndVerified(t *testing.T) {
	config, manifest := elevatedInspectionFixture(t)
	verifier := fakeElevatedVerifier{}
	dependencies := fakeElevatedDependencyInspector{health: elevatedDependencyHealth{
		Accounts: true, Credentials: true, Firewall: true, RuntimeBaseline: true,
		PrivateDesktop: true, JobReadback: true, HandleList: true,
	}}

	if _, err := inspectElevatedSetupWith(config, policy.Effective{}, verifier, dependencies); !errors.Is(err, ErrSetupRequired) {
		t.Fatalf("absent manifest = %v, want setup required", err)
	}
	if err := os.MkdirAll(config.StateRoot, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(config.StateRoot, readyManifestName), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectElevatedSetupWith(config, policy.Effective{}, verifier, dependencies); !errors.Is(err, ErrSetupStale) || errors.Is(err, ErrSetupRequired) {
		t.Fatalf("corrupt manifest = %v, want stale", err)
	}

	writeElevatedManifest(t, config, manifest)
	snapshot, err := inspectElevatedSetupWith(config, policy.Effective{}, verifier, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.PrivateDesktopReady {
		t.Fatal("verified v1 broker installation omitted private desktop readiness")
	}
	if err := validateElevatedSnapshot(snapshot); err != nil {
		t.Fatalf("verified snapshot validation = %v", err)
	}
	if snapshot.HostPath != manifest.HostPath || snapshot.HostSHA256 != manifest.HostSHA256 {
		t.Fatalf("snapshot = %#v, want manifest host identity", snapshot)
	}
}

func TestInspectElevatedSetupFailsClosedOnProtectionHashAndDependencyHealth(t *testing.T) {
	config, manifest := elevatedInspectionFixture(t)
	writeElevatedManifest(t, config, manifest)
	healthy := fakeElevatedDependencyInspector{health: elevatedDependencyHealth{
		Accounts: true, Credentials: true, Firewall: true, RuntimeBaseline: true,
		PrivateDesktop: true, JobReadback: true, HandleList: true,
	}}
	if _, err := inspectElevatedSetupWith(config, policy.Effective{}, fakeElevatedVerifier{err: errors.New("unprotected")}, healthy); !errors.Is(err, ErrSetupStale) {
		t.Fatalf("unprotected installation = %v", err)
	}
	if err := os.WriteFile(manifest.HostPath, []byte("tampered"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := inspectElevatedSetupWith(config, policy.Effective{}, fakeElevatedVerifier{}, healthy); !errors.Is(err, ErrSetupStale) {
		t.Fatalf("tampered runner = %v", err)
	}

	if err := os.WriteFile(manifest.HostPath, []byte("runner"), 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := inspectElevatedSetupWith(config, policy.Effective{}, fakeElevatedVerifier{}, fakeElevatedDependencyInspector{})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.AccountsReady || snapshot.CredentialsReady || snapshot.FirewallReady || snapshot.RuntimeBaselineReady {
		t.Fatalf("unverified dependency reported ready: %#v", snapshot)
	}
	if err := validateElevatedSnapshot(snapshot); err == nil {
		t.Fatal("unverified dependency snapshot passed validation")
	}
}

func TestAcquireElevatedLeaseRejectsIncompleteVerifiedConfiguration(t *testing.T) {
	snapshot := readyElevatedSnapshot()
	snapshot.PipeName = ""
	if _, err := acquireElevatedLease(snapshot, policy.Effective{}); !errors.Is(err, ErrSetupStale) {
		t.Fatalf("incomplete snapshot error = %v", err)
	}
}

func TestElevatedCompileSelectsAccountAndOwnsLease(t *testing.T) {
	for _, test := range []struct {
		name    string
		open    bool
		account brokerAccountKind
	}{
		{"offline", false, brokerAccountOffline},
		{"online", true, brokerAccountOnline},
	} {
		t.Run(test.name, func(t *testing.T) {
			lease := &fakeElevatedLease{}
			backend := &elevatedBackend{deps: elevatedCompileDependencies{
				inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) {
					return readyElevatedSnapshot(), nil
				},
				acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
					return lease, nil
				},
				launch: func(request enforce.LaunchRequest, _ elevatedSetupSnapshot, issued brokerIssuedToken, _ policy.Limits, release func() error) (enforce.Execution, error) {
					if issued.Handle != 123 || issued.Desktop == "" || request.Dir != `C:\work` ||
						!slices.Equal(request.Argv, []string{`C:\tool.exe`, "arg"}) ||
						!slices.Equal(request.Env, []string{"A=B"}) {
						t.Fatalf("launch request = %#v issued=%#v", request, issued)
					}
					_, _ = io.WriteString(request.Stdout, "output")
					if err := release(); err != nil {
						return nil, err
					}
					return fixedExecution{code: 7}, nil
				},
			}}
			p := policy.Effective{
				Net: testNetPolicy(test.open), Env: policy.EnvPolicy{Inherit: false},
				RuntimeBaselines: []string{policy.WindowsRuntimeBaseline},
				Limits:           policy.Limits{MaxPIDs: 16},
				RequiredGuarantees: profile.GuaranteeProcessBoundary |
					profile.GuaranteeReadBoundary | profile.GuaranteeWriteBoundary |
					profile.GuaranteeEnvScrub | profile.GuaranteeResourceLimits,
			}
			spec, report, level, bits, err := backend.Compile(p)
			if err != nil {
				t.Fatal(err)
			}
			if level != profile.LevelFull || bits&p.RequiredGuarantees != p.RequiredGuarantees {
				t.Fatalf("level/bits = %d/%#x, want full and at least %#x", level, bits, p.RequiredGuarantees)
			}
			if len(report.Entries) == 0 || !slices.ContainsFunc(report.Entries, func(entry profile.ReportEntry) bool {
				return entry.Feature == policy.WindowsRuntimeBaseline && entry.Status == "Enforced"
			}) {
				t.Fatalf("runtime baseline absent from report: %#v", report)
			}
			var output strings.Builder
			execution, err := spec.Launch(enforce.LaunchRequest{
				Context: context.Background(), Dir: `C:\work`,
				Argv: []string{`C:\tool.exe`, "arg"}, Env: []string{"A=B"},
				Stdout: &output, Stderr: io.Discard,
			})
			if err != nil {
				t.Fatal(err)
			}
			code, err := execution.Wait(context.Background())
			if err != nil || code != 7 || output.String() != "output" {
				t.Fatalf("launch = code %d output %q err %v", code, output.String(), err)
			}
			if lease.account != test.account {
				t.Fatalf("account = %d, want %d", lease.account, test.account)
			}
			if err := spec.Release(); err != nil {
				t.Fatal(err)
			}
			if err := spec.Release(); err != nil {
				t.Fatal(err)
			}
			if lease.releases != 1 {
				t.Fatalf("lease releases = %d, want 1", lease.releases)
			}
		})
	}
}

func TestElevatedConcurrentExecutionsOwnIndependentLeasesAndSpecReleaseDrains(t *testing.T) {
	lease := &fakeElevatedLease{}
	started := make(chan struct{}, 2)
	finish := [2]chan struct{}{make(chan struct{}), make(chan struct{})}
	var launchMu sync.Mutex
	next := 0
	backend := &elevatedBackend{deps: elevatedCompileDependencies{
		inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) {
			return readyElevatedSnapshot(), nil
		},
		acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
			return lease, nil
		},
		launch: func(_ enforce.LaunchRequest, _ elevatedSetupSnapshot, _ brokerIssuedToken, _ policy.Limits, release func() error) (enforce.Execution, error) {
			launchMu.Lock()
			index := next
			next++
			launchMu.Unlock()
			started <- struct{}{}
			<-finish[index]
			if err := release(); err != nil {
				return nil, err
			}
			return fixedExecution{}, nil
		},
	}}
	spec, _, _, _, err := backend.Compile(policy.Effective{})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(2)
	for range 2 {
		go func() {
			defer wg.Done()
			if _, err := spec.Launch(enforce.LaunchRequest{Context: context.Background()}); err != nil {
				t.Errorf("launch: %v", err)
			}
		}()
	}
	<-started
	<-started
	close(finish[0])
	for {
		lease.mu.Lock()
		released := lease.executionReleases
		factoryReleased := lease.releases
		lease.mu.Unlock()
		if released == 1 {
			if factoryReleased != 0 {
				t.Fatalf("first execution revoked retained factory: %d", factoryReleased)
			}
			break
		}
		time.Sleep(time.Millisecond)
	}
	releaseDone := make(chan error, 1)
	go func() { releaseDone <- spec.Release() }()
	select {
	case err := <-releaseDone:
		t.Fatalf("spec release did not drain sibling execution: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(finish[1])
	wg.Wait()
	if err := <-releaseDone; err != nil {
		t.Fatal(err)
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.releases != 1 || lease.issues != 2 || lease.executionReleases != 2 || lease.acquires != 2 {
		t.Fatalf("lifecycle counts: acquires=%d issues=%d execution releases=%d factory releases=%d",
			lease.acquires, lease.issues, lease.executionReleases, lease.releases)
	}
}

func TestElevatedGrantCompileReportsNoAuthorityBeforeBaseCompile(t *testing.T) {
	backend := &elevatedBackend{}
	spec, report, level, bits, err := backend.CompileWithRetainedPathHandles(nil, policy.Effective{}, policy.Effective{}, []*policy.PathHandle{{}})
	if err == nil {
		t.Fatal("grant compile without proven base authority succeeded")
	}
	for _, entry := range report.Entries {
		if entry.Status == "Enforced" {
			t.Fatalf("unproven grant authority reported enforced feature: %#v", entry)
		}
	}
	if spec.Launch != nil || spec.Release != nil || level != profile.LevelNone || bits != 0 {
		t.Fatalf("unproven grant authority reported posture: level=%d bits=%#x report=%#v spec=%#v", level, bits, report, spec)
	}
}

func TestElevatedSpecGrantAuthorityIsExactAndRetiresAfterBorrows(t *testing.T) {
	base := policy.Effective{
		FS:  []policy.FSEntry{{Path: `C:\executor-one`, Access: policy.AllAccess}},
		Env: policy.EnvPolicy{Set: map[string]string{"HOME": `C:\executor-one\home`}},
	}
	lease := &fakeElevatedLease{}
	authority := newElevatedSpecGrantAuthority(base, lease)
	if _, _, err := authority.borrow(policy.Effective{
		FS:  []policy.FSEntry{{Path: `C:\executor-two`, Access: policy.AllAccess}},
		Env: policy.EnvPolicy{Set: map[string]string{"HOME": `C:\executor-two\home`}},
	}); err == nil {
		t.Fatal("authority from another executor was accepted")
	}
	_, releaseBorrow, err := authority.borrow(policy.Clone(base))
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.retire(); err != nil {
		t.Fatal(err)
	}
	if lease.releases != 0 {
		t.Fatal("base lease released while a transient grant borrowed it")
	}
	if err := releaseBorrow(); err != nil {
		t.Fatal(err)
	}
	if lease.releases != 1 {
		t.Fatalf("base lease releases = %d, want 1 after transient grant release", lease.releases)
	}
	if _, _, err := authority.borrow(policy.Clone(base)); err == nil {
		t.Fatal("retired base authority was reused")
	}
}

func testNetPolicy(open bool) policy.NetPolicy { return policy.NetPolicy{Open: open} }

func TestElevatedCompileRejectsEveryUnverifiedMechanismBeforeAcquire(t *testing.T) {
	fields := []struct {
		name string
		flip func(*elevatedSetupSnapshot)
	}{
		{"manifest", func(s *elevatedSetupSnapshot) { s.Ready = false }},
		{"accounts", func(s *elevatedSetupSnapshot) { s.AccountsReady = false }},
		{"credentials", func(s *elevatedSetupSnapshot) { s.CredentialsReady = false }},
		{"firewall", func(s *elevatedSetupSnapshot) { s.FirewallReady = false }},
		{"baseline", func(s *elevatedSetupSnapshot) { s.RuntimeBaselineReady = false }},
		{"hash", func(s *elevatedSetupSnapshot) { s.RunnerHashVerified = false }},
		{"desktop", func(s *elevatedSetupSnapshot) { s.PrivateDesktopReady = false }},
		{"job", func(s *elevatedSetupSnapshot) { s.JobReadbackReady = false }},
		{"handles", func(s *elevatedSetupSnapshot) { s.HandleListReady = false }},
	}
	for _, test := range fields {
		t.Run(test.name, func(t *testing.T) {
			acquires := 0
			backend := &elevatedBackend{deps: elevatedCompileDependencies{
				inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) {
					snapshot := readyElevatedSnapshot()
					test.flip(&snapshot)
					return snapshot, nil
				},
				acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
					acquires++
					return &fakeElevatedLease{}, nil
				},
			}}
			_, _, level, bits, err := backend.Compile(policy.Effective{})
			if !errors.Is(err, ErrSetupStale) || errors.Is(err, ErrSetupRequired) || level != profile.LevelNone || bits != 0 {
				t.Fatalf("result = level %d bits %#x err %v", level, bits, err)
			}
			if acquires != 0 {
				t.Fatal("invalid setup consumed broker authority")
			}
		})
	}
}

func TestElevatedCompileReleasesPartialAndMissingGuaranteeFailures(t *testing.T) {
	lease := &fakeElevatedLease{releaseError: errors.New("release")}
	backend := &elevatedBackend{deps: elevatedCompileDependencies{
		inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) {
			return readyElevatedSnapshot(), nil
		},
		acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
			return lease, errors.New("acquire")
		},
	}}
	_, _, _, _, err := backend.Compile(policy.Effective{})
	if err == nil || !errors.Is(err, lease.releaseError) || lease.releases != 1 {
		t.Fatalf("partial acquisition was not released: %v releases=%d", err, lease.releases)
	}

	lease = &fakeElevatedLease{}
	backend.deps.acquire = func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) { return lease, nil }
	_, _, _, bits, err := backend.Compile(policy.Effective{RequiredGuarantees: profile.GuaranteeAddressNetwork})
	if !errors.Is(err, enforce.ErrUnavailable) || bits&profile.GuaranteeAddressNetwork != 0 || lease.releases != 1 {
		t.Fatalf("missing network guarantee result = bits %#x err %v releases=%d", bits, err, lease.releases)
	}
}

type fixedCompileBackend struct {
	spec   enforce.Spec
	report profile.CompileReport
	level  uint8
	bits   uint64
	err    error
	calls  int
}

func (backend *fixedCompileBackend) Compile(policy.Effective) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
	backend.calls++
	return backend.spec, backend.report, backend.level, backend.bits, backend.err
}

func TestWindowsAutoPrefersElevatedAndFallsBackOnlyForSetupRequired(t *testing.T) {
	elevated := &fixedCompileBackend{spec: enforce.Spec{Wrap: func(string, []string) ([]string, func(*exec.Cmd) error, func()) {
		return []string{"elevated"}, nil, nil
	}}, level: profile.LevelFull}
	restricted := &fixedCompileBackend{spec: enforce.Spec{Wrap: func(string, []string) ([]string, func(*exec.Cmd) error, func()) {
		return []string{"restricted"}, nil, nil
	}}}
	backend := &autoBackend{elevated: elevated, restricted: restricted}
	spec, _, _, _, err := backend.Compile(policy.Effective{})
	if err != nil || restricted.calls != 0 {
		t.Fatalf("healthy elevated selection fell through: %v calls=%d", err, restricted.calls)
	}
	argv, _, _ := spec.Wrap("", nil)
	if argv[0] != "elevated" {
		t.Fatalf("selected %q", argv[0])
	}

	elevated.err = ErrSetupRequired
	if _, _, _, _, err := backend.Compile(policy.Effective{}); err != nil || restricted.calls != 1 {
		t.Fatalf("setup absence did not select restricted: %v calls=%d", err, restricted.calls)
	}
	elevated.err = errors.New("integrity mismatch")
	if _, _, _, _, err := backend.Compile(policy.Effective{}); err == nil || restricted.calls != 1 {
		t.Fatalf("integrity failure fell back: %v calls=%d", err, restricted.calls)
	}
}

func TestElevatedCompilePreservesInspectionFailureClass(t *testing.T) {
	backend := &elevatedBackend{deps: elevatedCompileDependencies{
		inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) {
			return elevatedSetupSnapshot{}, ErrSetupStale
		},
		acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
			t.Fatal("stale inspection reached lease acquisition")
			return nil, nil
		},
	}}
	_, _, _, _, err := backend.Compile(policy.Effective{})
	if !errors.Is(err, ErrSetupStale) || errors.Is(err, ErrSetupRequired) {
		t.Fatalf("inspection error = %v, want stale without setup-required fallback", err)
	}
}

func TestElevatedGrantClassPreflightIsClosed(t *testing.T) {
	backend := &elevatedBackend{}
	for _, class := range []string{
		"command.start.v1", "filesystem.path.read.v1", "filesystem.path.write.v1",
		"filesystem.tree.read.v1", "filesystem.tree.write.v1", "network.proxy-target.v1",
	} {
		if !backend.SupportsGrantClass(class) {
			t.Errorf("supported class %q rejected", class)
		}
	}
	for _, class := range []string{
		"network.broad.v1", "filesystem.host.read.v1", "filesystem.host.write.v1",
		"filesystem.path.execute.v1", "network.proxy-target.v2", "",
	} {
		if backend.SupportsGrantClass(class) {
			t.Errorf("unsupported class %q accepted", class)
		}
	}
}

func TestWindowsAutoGrantClassPreflightForwardsElevatedAnswer(t *testing.T) {
	backend := &autoBackend{elevated: &elevatedBackend{}, restricted: &fixedCompileBackend{}}
	for _, class := range []string{"command.start.v1", "filesystem.path.write.v1", "network.proxy-target.v1"} {
		if !backend.SupportsGrantClass(class) {
			t.Errorf("elevated-supported class %q rejected by Auto", class)
		}
	}
	for _, class := range []string{"network.broad.v1", "filesystem.host.read.v1", "filesystem.host.write.v1", ""} {
		if backend.SupportsGrantClass(class) {
			t.Errorf("class %q accepted by Auto although the elevated tier rejects it", class)
		}
	}
	// An elevated backend that cannot answer must not fall back to the
	// executor's "absent means supported" default.
	opaque := &autoBackend{elevated: &fixedCompileBackend{}, restricted: &fixedCompileBackend{}}
	if opaque.SupportsGrantClass("command.start.v1") {
		t.Fatal("Auto accepted a grant class without an elevated preflight")
	}
	var nilBackend *autoBackend
	if nilBackend.SupportsGrantClass("command.start.v1") {
		t.Fatal("nil Auto backend accepted a grant class")
	}
}

func TestElevatedCompileRefusesNetworkAllowancesTheFirewallCannotExpress(t *testing.T) {
	for _, test := range []struct {
		name string
		net  policy.NetPolicy
	}{
		{"loopback", policy.NetPolicy{Loopback: true}},
		{"private", policy.NetPolicy{Private: true}},
		{"dns", policy.NetPolicy{DNS: true}},
		{"ports", policy.NetPolicy{Ports: []uint16{443}}},
		{"ports with proxy", policy.NetPolicy{Ports: []uint16{443}, ProxyPort: 49152}},
	} {
		t.Run(test.name, func(t *testing.T) {
			backend := &elevatedBackend{deps: elevatedCompileDependencies{
				inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) { return readyElevatedSnapshot(), nil },
				acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
					t.Fatal("unexpressible network policy reached lease acquisition")
					return nil, nil
				},
			}}
			_, _, level, bits, err := backend.Compile(policy.Effective{Net: test.net})
			if !errors.Is(err, enforce.ErrUnavailable) || errors.Is(err, ErrSetupRequired) || level != profile.LevelNone || bits != 0 {
				t.Fatalf("compile = level %d bits %#x err %v", level, bits, err)
			}
		})
	}
	// An open policy subsumes those allowances; it is not refused for them.
	lease := &fakeElevatedLease{}
	backend := &elevatedBackend{deps: elevatedCompileDependencies{
		inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) { return readyElevatedSnapshot(), nil },
		acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) { return lease, nil },
	}}
	spec, _, _, bits, err := backend.Compile(policy.Effective{Net: policy.NetPolicy{Open: true, Loopback: true, DNS: true, Ports: []uint16{443}}})
	if err != nil || bits&profile.GuaranteeNetworkBoundary != 0 {
		t.Fatalf("open policy compile = bits %#x err %v", bits, err)
	}
	if err := spec.Release(); err != nil {
		t.Fatal(err)
	}
}

// TestElevatedCompileRefusesUnixSocketEscapeHatch pins Task 1 for the elevated
// tier: the broker is never asked for authority for a profile that asks for
// AF_UNIX, the refusal is typed (and not a setup state, so Auto does not fall
// back), and the report names the unmediated feature.
func TestElevatedCompileRefusesUnixSocketEscapeHatch(t *testing.T) {
	for _, unixSockets := range []profile.UnixSocketPolicy{
		{Mode: profile.UnixSocketsLocal},
		{Paths: []string{`C:\agent\ssh.sock`}},
		{Mode: profile.UnixSocketsLocal, Paths: []string{`C:\agent\ssh.sock`}},
	} {
		backend := &elevatedBackend{deps: elevatedCompileDependencies{
			inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) { return readyElevatedSnapshot(), nil },
			acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
				t.Fatal("AF_UNIX profile reached broker lease acquisition")
				return nil, nil
			},
		}}
		spec, report, level, bits, err := backend.Compile(policy.Effective{UnixSockets: unixSockets})
		if !errors.Is(err, enforce.ErrUnavailable) || !errors.Is(err, policy.ErrUnsupportedClass) ||
			errors.Is(err, ErrSetupRequired) || errors.Is(err, ErrSetupStale) {
			t.Fatalf("compile error = %v, want typed AF_UNIX refusal", err)
		}
		if spec.Launch != nil || spec.Release != nil || level != profile.LevelNone || bits != 0 {
			t.Fatalf("partial result spec=%#v level=%d bits=%#x", spec, level, bits)
		}
		if !slices.Contains(report.Entries, profile.ReportEntry{
			Feature: "unix-sockets", Status: "unavailable", Detail: "AF_UNIX endpoints are not mediated on Windows",
		}) {
			t.Fatalf("report omits unix-sockets: %#v", report.Entries)
		}
	}
	// A default-denial profile compiles and carries no unix-sockets entry.
	lease := &fakeElevatedLease{}
	backend := &elevatedBackend{deps: elevatedCompileDependencies{
		inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) { return readyElevatedSnapshot(), nil },
		acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) { return lease, nil },
	}}
	spec, report, _, _, err := backend.Compile(policy.Effective{})
	if err != nil {
		t.Fatal(err)
	}
	if slices.ContainsFunc(report.Entries, func(entry profile.ReportEntry) bool { return entry.Feature == "unix-sockets" }) {
		t.Fatalf("default-denial report names unix-sockets: %#v", report.Entries)
	}
	if err := spec.Release(); err != nil {
		t.Fatal(err)
	}
}

// TestElevatedResourceLimitsOnlyWhenRequested pins L8: ResourceLimits is
// claimed (and required for LevelFull) only when the policy requests a limit
// the launch Job installs and reads back; disabled limits are neither
// installed nor claimed.
func TestElevatedResourceLimitsOnlyWhenRequested(t *testing.T) {
	for _, test := range []struct {
		name   string
		limits policy.Limits
		want   bool
	}{
		{"none requested", policy.Limits{}, false},
		{"process limit", policy.Limits{MaxPIDs: 4}, true},
		{"memory limit", policy.Limits{MaxMemBytes: 64 << 20}, true},
		{"cpu limit", policy.Limits{MaxCPUPct: 50}, true},
		{"disabled", policy.Limits{MaxPIDs: 4, Disabled: true}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := policy.Effective{Limits: test.limits}
			bits := elevatedGuaranteeBits(p)
			if got := bits&profile.GuaranteeResourceLimits != 0; got != test.want {
				t.Fatalf("ResourceLimits claimed = %v, want %v", got, test.want)
			}
			if !elevatedFullLevel(p, bits) {
				t.Fatal("a policy without requested limits cannot reach LevelFull")
			}
			options := elevatedJobOptions(test.limits)
			installs := options.MaxProcesses > 0 || options.MaxMemoryBytes > 0 || options.MaxCPUPct > 0
			if installs != test.want || !options.Sandboxed {
				t.Fatalf("Job options = %#v, want limits installed = %v", options, test.want)
			}
			report := elevatedCompileReport(p, readyElevatedSnapshot())
			index := slices.IndexFunc(report.Entries, func(entry profile.ReportEntry) bool { return entry.Feature == "windows.resource-limits" })
			if index < 0 || (report.Entries[index].Status == "Enforced") != test.want {
				t.Fatalf("resource-limits row = %#v, want enforced = %v", report.Entries, test.want)
			}
		})
	}
}

// TestElevatedReportCarriesFirewallAndDerivedReadiness pins L8: the report
// names windows.firewall from the verified snapshot (and as unenforced for an
// online profile), and the job / private-desktop rows follow the snapshot
// facts instead of being assumed.
func TestElevatedReportCarriesFirewallAndDerivedReadiness(t *testing.T) {
	statusOf := func(report profile.CompileReport, feature string) string {
		index := slices.IndexFunc(report.Entries, func(entry profile.ReportEntry) bool { return entry.Feature == feature })
		if index < 0 {
			t.Fatalf("report has no %s row: %#v", feature, report.Entries)
		}
		return report.Entries[index].Status
	}
	ready := readyElevatedSnapshot()
	if got := statusOf(elevatedCompileReport(policy.Effective{}, ready), "windows.firewall"); got != "Enforced" {
		t.Fatalf("offline firewall row = %q", got)
	}
	if got := statusOf(elevatedCompileReport(policy.Effective{Net: policy.NetPolicy{Open: true}}, ready), "windows.firewall"); got != "unenforced" {
		t.Fatalf("online firewall row = %q", got)
	}
	unverified := ready
	unverified.FirewallReady, unverified.PrivateDesktopReady, unverified.HandleListReady = false, false, false
	report := elevatedCompileReport(policy.Effective{}, unverified)
	for _, feature := range []string{"windows.firewall", "windows.private-desktop", "windows.job"} {
		if got := statusOf(report, feature); got != "Unavailable" {
			t.Fatalf("%s row = %q for an unverified snapshot", feature, got)
		}
	}
}

// TestInspectElevatedSetupDerivesLaunchMechanismReadiness: the three launch
// mechanisms come from inspection facts, never hard-coded, so a host whose
// probes fail is not ready.
func TestInspectElevatedSetupDerivesLaunchMechanismReadiness(t *testing.T) {
	config, manifest := elevatedInspectionFixture(t)
	writeElevatedManifest(t, config, manifest)
	for name, flip := range map[string]func(*elevatedDependencyHealth){
		"private desktop": func(health *elevatedDependencyHealth) { health.PrivateDesktop = false },
		"job read-back":   func(health *elevatedDependencyHealth) { health.JobReadback = false },
		"handle list":     func(health *elevatedDependencyHealth) { health.HandleList = false },
	} {
		t.Run(name, func(t *testing.T) {
			health := elevatedDependencyHealth{Accounts: true, Credentials: true, Firewall: true, RuntimeBaseline: true,
				PrivateDesktop: true, JobReadback: true, HandleList: true}
			flip(&health)
			snapshot, err := inspectElevatedSetupWith(config, policy.Effective{}, fakeElevatedVerifier{}, fakeElevatedDependencyInspector{health: health})
			if err != nil {
				t.Fatal(err)
			}
			if validateElevatedSnapshot(snapshot) == nil {
				t.Fatalf("snapshot with an unverified %s validated", name)
			}
		})
	}
	if err := probeElevatedJobReadback(); err != nil {
		t.Fatalf("this host cannot install and read back a Job: %v", err)
	}
	if err := probeElevatedHandleList(); err != nil {
		t.Fatalf("this host cannot build a handle list: %v", err)
	}
}
