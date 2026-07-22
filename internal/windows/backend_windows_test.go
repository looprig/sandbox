//go:build windows

package windows

import (
	"errors"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
)

func TestRestrictedCompileClaimsOnlyExecutorEnvironmentScrub(t *testing.T) {
	executor, err := ExecutorSID("installation", "executor")
	if err != nil {
		t.Fatal(err)
	}
	prepareCalls := 0
	configureCalls := 0
	releaseCalls := 0
	backend := &restrictedBackend{config: Config{Mode: RestrictedToken}, deps: restrictedCompileDependencies{
		prepare: func(_ Config, _ string, got policy.Effective) (restrictedPreparedLease, error) {
			prepareCalls++
			got.FS = append(got.FS, policy.FSEntry{Path: `C:\mutated`})
			return restrictedPreparedLease{sid: executor, release: func() error { releaseCalls++; return nil }}, nil
		},
		configure: func(cmd *exec.Cmd, got []SID) (func(), error) {
			configureCalls++
			if cmd == nil || len(got) != 1 || got[0] != executor {
				t.Fatal("configure did not receive this executor SID and command")
			}
			return func() {}, nil
		},
	}}
	p := policy.Effective{
		Env:                policy.EnvPolicy{Inherit: false},
		RuntimeBaselines:   []string{policy.WindowsRuntimeBaseline},
		FS:                 []policy.FSEntry{{Path: `C:\work`, Access: policy.WriteAccess}},
		ProjectionRoots:    []string{`C:\work`},
		RequiredGuarantees: profile.GuaranteeEnvScrub,
	}
	spec, report, level, bits, err := backend.Compile(p)
	if err != nil {
		t.Fatal(err)
	}
	if level != profile.LevelNone || bits != profile.GuaranteeEnvScrub {
		t.Fatalf("level/bits = %d/%#x, want LevelNone/EnvScrub", level, bits)
	}
	if prepareCalls != 1 || len(p.FS) != 1 {
		t.Fatalf("prepare calls/original FS = %d/%d", prepareCalls, len(p.FS))
	}
	for _, forbidden := range []uint64{profile.GuaranteeProcessBoundary, profile.GuaranteeWriteBoundary, profile.GuaranteeReadBoundary,
		profile.GuaranteeNetworkBoundary, profile.GuaranteeResourceLimits, profile.GuaranteeAddressNetwork, profile.GuaranteeTargetNetwork} {
		if bits&forbidden != 0 {
			t.Fatalf("restricted compile claimed forbidden bit %#x", forbidden)
		}
	}
	wantFeatures := []string{"windows.token", "windows.filesystem.write", "windows.job", "windows.private-desktop", "windows.resource-limits", policy.WindowsRuntimeBaseline}
	for _, feature := range wantFeatures {
		index := slices.IndexFunc(report.Entries, func(entry profile.ReportEntry) bool { return entry.Feature == feature })
		if index < 0 || report.Entries[index].Status != "Narrowed" {
			t.Fatalf("report missing narrowed feature %q: %#v", feature, report.Entries)
		}
	}
	for index := 0; index < 2; index++ {
		argv, configure, cleanup := spec.Wrap(`C:\work`, []string{"program", "argument"})
		argv[0] = "mutated"
		if err := configure(&exec.Cmd{}); err != nil {
			t.Fatal(err)
		}
		cleanup()
		cleanup()
	}
	if configureCalls != 2 {
		t.Fatalf("configure calls = %d, want a fresh token path per spawn", configureCalls)
	}
	if err := spec.Release(); err != nil {
		t.Fatal(err)
	}
	if err := spec.Release(); err != nil {
		t.Fatal(err)
	}
	if releaseCalls != 1 {
		t.Fatalf("release calls = %d, want 1", releaseCalls)
	}
}

func TestWindowsAutoFailsWithTypedSetupErrorForExactRequiredBits(t *testing.T) {
	backend := &restrictedBackend{config: Config{Mode: Auto}, deps: restrictedCompileDependencies{
		prepare: func(Config, string, policy.Effective) (restrictedPreparedLease, error) {
			t.Fatal("Auto contacted restricted preparation despite missing guarantees")
			return restrictedPreparedLease{}, nil
		},
		configure: func(*exec.Cmd, []SID) (func(), error) { return nil, nil },
	}}
	wantMissing := uint64(profile.GuaranteeWriteBoundary | profile.GuaranteeNetworkBoundary)
	spec, _, level, bits, err := backend.Compile(policy.Effective{
		Env: policy.EnvPolicy{Inherit: false}, RequiredGuarantees: profile.GuaranteeEnvScrub | wantMissing,
	})
	if !errors.Is(err, ErrSetupRequired) || !errors.Is(err, enforce.ErrUnavailable) {
		t.Fatalf("error = %v, want typed setup-required unavailable error", err)
	}
	if spec.Wrap != nil || level != profile.LevelNone || bits != profile.GuaranteeEnvScrub {
		t.Fatalf("partial result = %#v/%d/%#x", spec, level, bits)
	}
	for _, fragment := range []string{"missing guarantees", "WriteBoundary", "NetworkBoundary"} {
		if !strings.Contains(err.Error(), fragment) {
			t.Fatalf("error %q does not name missing guarantees", err)
		}
	}
}

func TestExplicitRestrictedMissingGuaranteesDoesNotPrepare(t *testing.T) {
	prepareCalls := 0
	backend := &restrictedBackend{config: Config{Mode: RestrictedToken}, deps: restrictedCompileDependencies{
		prepare: func(Config, string, policy.Effective) (restrictedPreparedLease, error) {
			prepareCalls++
			return restrictedPreparedLease{}, nil
		},
		configure: func(*exec.Cmd, []SID) (func(), error) { return nil, nil },
	}}
	_, _, _, _, err := backend.Compile(policy.Effective{RequiredGuarantees: profile.GuaranteeWriteBoundary})
	if !errors.Is(err, enforce.ErrUnavailable) || errors.Is(err, ErrSetupRequired) {
		t.Fatalf("error = %v, want non-setup unavailable error", err)
	}
	if prepareCalls != 0 {
		t.Fatalf("prepare calls = %d, want zero before missing-guarantee rejection", prepareCalls)
	}
}

func TestRestrictedProjectionRootsExcludeHostVolume(t *testing.T) {
	got := writableProjectionRoots([]policy.FSEntry{
		{Path: `C:\`, Access: policy.AllAccess},
		{Path: `C:\work`, Access: policy.WriteAccess},
		{Path: `D:\`, Access: policy.AllAccess},
	}, []string{`C:\work`})
	if len(got) != 1 || got[0].Path != `C:\work` {
		t.Fatalf("projection roots = %#v, want configured workspace only", got)
	}
}

func TestRestrictedCompileReleasesMalformedPreparedLease(t *testing.T) {
	releases := 0
	backend := &restrictedBackend{config: Config{Mode: RestrictedToken}, deps: restrictedCompileDependencies{
		prepare: func(Config, string, policy.Effective) (restrictedPreparedLease, error) {
			return restrictedPreparedLease{release: func() error { releases++; return nil }}, nil
		},
		configure: func(*exec.Cmd, []SID) (func(), error) { return nil, nil },
	}}
	if _, _, _, _, err := backend.Compile(policy.Effective{}); err == nil {
		t.Fatal("malformed prepared lease compiled")
	}
	if releases != 1 {
		t.Fatalf("partial lease releases = %d, want 1", releases)
	}
}

func TestRestrictedGrantCompileReusesBaseLeaseAndTransientReleaseKeepsItActive(t *testing.T) {
	base, err := ExecutorSID("installation", "executor")
	if err != nil {
		t.Fatal(err)
	}
	baseReleases := 0
	var configured []SID
	backend := &restrictedBackend{config: Config{Mode: RestrictedToken}, deps: restrictedCompileDependencies{
		prepare: func(Config, string, policy.Effective) (restrictedPreparedLease, error) {
			return restrictedPreparedLease{sid: base, journal: &RestrictedJournal{}, release: func() error { baseReleases++; return nil }}, nil
		},
		configure: func(_ *exec.Cmd, sids []SID) (func(), error) {
			configured = append([]SID(nil), sids...)
			return func() {}, nil
		},
	}}
	baseSpec, _, _, _, err := backend.Compile(policy.Effective{})
	if err != nil {
		t.Fatal(err)
	}
	grantSpec, _, _, _, err := backend.CompileWithPathHandles(policy.Effective{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, configure, cleanup := grantSpec.Wrap("", []string{"program"})
	if err := configure(&exec.Cmd{}); err != nil {
		t.Fatal(err)
	}
	cleanup()
	if len(configured) != 1 || configured[0] != base {
		t.Fatalf("grant restricting SIDs = %#v, want retained base SID", configured)
	}
	if err := grantSpec.Release(); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	active := backend.baseActive
	backend.mu.Unlock()
	if !active || baseReleases != 0 {
		t.Fatalf("transient release changed base: active=%v releases=%d", active, baseReleases)
	}
	if err := baseSpec.Release(); err != nil {
		t.Fatal(err)
	}
	if baseReleases != 1 {
		t.Fatalf("base releases = %d, want 1", baseReleases)
	}
}
