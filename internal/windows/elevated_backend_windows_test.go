//go:build windows

package windows

import (
	"errors"
	"os/exec"
	"slices"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
)

type fakeElevatedLease struct {
	account      brokerAccountKind
	wraps        int
	releases     int
	wrapErr      error
	releaseError error
}

func (lease *fakeElevatedLease) Wrap(_ string, argv []string, account brokerAccountKind) ([]string, func(*exec.Cmd) error, func(), error) {
	lease.wraps++
	lease.account = account
	return append([]string{"host"}, argv...), nil, func() {}, lease.wrapErr
}
func (lease *fakeElevatedLease) Release() error {
	lease.releases++
	return lease.releaseError
}

func readyElevatedSnapshot() elevatedSetupSnapshot {
	return elevatedSetupSnapshot{
		Ready: true, HostPath: `C:\ProgramData\Looprig\slots\generation\sandbox-host.exe`,
		HostSHA256: "digest", Protocol: brokerProtocolVersion, AccountsReady: true,
		CredentialsReady: true, FirewallReady: true, RuntimeBaselineReady: true,
		RunnerHashVerified: true, PrivateDesktopReady: true, JobReadbackReady: true,
		HandleListReady: true,
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
			}}
			p := policy.Effective{
				Net: testNetPolicy(test.open), Env: policy.EnvPolicy{Inherit: false},
				RuntimeBaselines: []string{policy.WindowsRuntimeBaseline},
				RequiredGuarantees: profile.GuaranteeProcessBoundary |
					profile.GuaranteeReadBoundary | profile.GuaranteeWriteBoundary |
					profile.GuaranteeEnvScrub | profile.GuaranteeResourceLimits,
			}
			spec, report, level, bits, err := backend.Compile(p)
			if err != nil {
				t.Fatal(err)
			}
			if level != profile.LevelFull || bits != p.RequiredGuarantees {
				t.Fatalf("level/bits = %d/%#x, want full/%#x", level, bits, p.RequiredGuarantees)
			}
			if len(report.Entries) == 0 || !slices.ContainsFunc(report.Entries, func(entry profile.ReportEntry) bool {
				return entry.Feature == policy.WindowsRuntimeBaseline && entry.Status == "Enforced"
			}) {
				t.Fatalf("runtime baseline absent from report: %#v", report)
			}
			argv, configure, cleanup := spec.Wrap(`C:\work`, []string{`C:\tool.exe`, "arg"})
			if len(argv) != 3 || argv[0] != "host" || configure != nil || cleanup == nil {
				t.Fatalf("invalid wrapped spawn: argv=%#v configure-nil=%t cleanup-nil=%t", argv, configure == nil, cleanup == nil)
			}
			cleanup()
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
	_, _, _, bits, err := backend.Compile(policy.Effective{RequiredGuarantees: profile.GuaranteeNetworkBoundary})
	if !errors.Is(err, enforce.ErrUnavailable) || bits&profile.GuaranteeNetworkBoundary != 0 || lease.releases != 1 {
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
