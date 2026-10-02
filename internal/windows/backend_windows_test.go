//go:build windows

package windows

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
	win "golang.org/x/sys/windows"
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
		prepare: func(_ Config, _ *RestrictedRuntime, got policy.Effective) (restrictedPreparedLease, error) {
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
	wantFeatures := []string{"windows.token", "windows.filesystem.write", "windows.job", "windows.private-desktop", "windows.resource-limits", "windows.env-scrub", policy.WindowsRuntimeBaseline}
	for _, feature := range wantFeatures {
		index := slices.IndexFunc(report.Entries, func(entry profile.ReportEntry) bool { return entry.Feature == feature })
		if index < 0 || report.Entries[index].Status != "Narrowed" {
			t.Fatalf("report missing narrowed feature %q: %#v", feature, report.Entries)
		}
	}
	// The report names the known channels rather than a generic escape, and
	// no longer names the host console as one (H8: the child has its own).
	if index := slices.IndexFunc(report.Entries, func(entry profile.ReportEntry) bool { return entry.Feature == "windows.job" }); strings.Contains(report.Entries[index].Detail, "shares the host console") {
		t.Fatalf("windows.job still reports a shared host console: %q", report.Entries[index].Detail)
	}
	for feature, fragments := range map[string][]string{
		"windows.filesystem.write": {"COM/WMI broker", "DELETE", "WRITE_DAC", "WRITE_OWNER", "No-delete-sharing handles", "carveouts", "one-shot SID"},
		"windows.job":              {"COM/WMI broker", "no console", "DETACHED_PROCESS", "cooperative interrupt is unavailable"},
		"windows.env-scrub":        {"memory", "own environment block"},
	} {
		index := slices.IndexFunc(report.Entries, func(entry profile.ReportEntry) bool { return entry.Feature == feature })
		for _, fragment := range fragments {
			if !strings.Contains(report.Entries[index].Detail, fragment) {
				t.Fatalf("%s detail %q does not name %q", feature, report.Entries[index].Detail, fragment)
			}
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
		prepare: func(Config, *RestrictedRuntime, policy.Effective) (restrictedPreparedLease, error) {
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
		prepare: func(Config, *RestrictedRuntime, policy.Effective) (restrictedPreparedLease, error) {
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
		prepare: func(Config, *RestrictedRuntime, policy.Effective) (restrictedPreparedLease, error) {
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
		prepare: func(Config, *RestrictedRuntime, policy.Effective) (restrictedPreparedLease, error) {
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
	if baseSpec.GrantAuthority == nil {
		t.Fatal("restricted base spec carries no grant authority for its executor")
	}
	grantSpec, _, _, _, err := backend.CompileWithGrantAuthority(baseSpec.GrantAuthority, policy.Effective{}, policy.Effective{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if grantSpec.GrantAuthority != nil {
		t.Fatal("a transient grant spec must not itself be a grant authority")
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
	if baseReleases != 0 {
		t.Fatalf("transient release released the base lease: releases=%d", baseReleases)
	}
	// The probe grant spec borrows the base lease like any other grant, so it
	// must be released before the base: an outstanding borrow keeps the lease
	// alive past the base Release by contract (restricted_authority.go), which
	// is what the second Windows CI run's "base releases = 0, want 1" was
	// observing when this probe was dropped unreleased.
	probe, _, _, _, err := backend.CompileWithGrantAuthority(baseSpec.GrantAuthority, policy.Effective{}, policy.Effective{}, nil)
	if err != nil {
		t.Fatalf("base authority unusable after a transient release: %v", err)
	}
	if err := probe.Release(); err != nil {
		t.Fatal(err)
	}
	if baseReleases != 0 {
		t.Fatalf("probe grant release released the base lease: releases=%d", baseReleases)
	}
	if err := baseSpec.Release(); err != nil {
		t.Fatal(err)
	}
	if baseReleases != 1 {
		t.Fatalf("base releases = %d, want 1", baseReleases)
	}
	if _, _, _, _, err := backend.CompileWithGrantAuthority(baseSpec.GrantAuthority, policy.Effective{}, policy.Effective{}, nil); err == nil {
		t.Fatal("grant compiled against a released base authority")
	}
}

// TestRestrictedBackendLeasesArePerExecutor pins the contract the first
// Windows CI run's facade failure ("restricted backend base lease is already
// active") exposed: an ExecutorSet shares ONE backend across its executors and
// every executor compiles its own base spec, so the backend must hold one
// base lease per Compile, not one per backend. Each executor's grants compile
// against its OWN lease, found through the GrantAuthority on its own spec —
// never through backend-global "current lease" state another executor's
// Compile could have replaced.
func TestRestrictedBackendLeasesArePerExecutor(t *testing.T) {
	first, err := ExecutorSID("installation", "executor-one")
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExecutorSID("installation", "executor-two")
	if err != nil {
		t.Fatal(err)
	}
	sids := []SID{first, second}
	releases := map[SID]int{}
	prepared := 0
	var configured []SID
	backend := &restrictedBackend{config: Config{Mode: RestrictedToken}, deps: restrictedCompileDependencies{
		prepare: func(Config, *RestrictedRuntime, policy.Effective) (restrictedPreparedLease, error) {
			sid := sids[prepared]
			prepared++
			return restrictedPreparedLease{sid: sid, journal: &RestrictedJournal{}, release: func() error { releases[sid]++; return nil }}, nil
		},
		configure: func(_ *exec.Cmd, got []SID) (func(), error) {
			configured = append([]SID(nil), got...)
			return func() {}, nil
		},
	}}
	basePolicy := func(workspace string) policy.Effective {
		return policy.Effective{Workspace: workspace, Env: policy.EnvPolicy{Inherit: false}}
	}
	firstSpec, _, _, _, err := backend.Compile(basePolicy(`C:\one`))
	if err != nil {
		t.Fatal(err)
	}
	secondSpec, _, _, _, err := backend.Compile(basePolicy(`C:\two`))
	if err != nil {
		t.Fatalf("second executor's Compile on the shared backend = %v, want its own lease", err)
	}
	for index, test := range []struct {
		spec enforce.Spec
		base policy.Effective
		want SID
	}{
		{firstSpec, basePolicy(`C:\one`), first},
		{secondSpec, basePolicy(`C:\two`), second},
	} {
		grant, _, _, _, err := backend.CompileWithGrantAuthority(test.spec.GrantAuthority, test.base, test.base, nil)
		if err != nil {
			t.Fatalf("executor %d grant compile: %v", index, err)
		}
		_, configure, cleanup := grant.Wrap("", []string{"program"})
		if err := configure(&exec.Cmd{}); err != nil {
			t.Fatal(err)
		}
		cleanup()
		if len(configured) != 1 || configured[0] != test.want {
			t.Fatalf("executor %d grant restricting SIDs = %#v, want its own base SID %v", index, configured, test.want)
		}
		if err := grant.Release(); err != nil {
			t.Fatal(err)
		}
	}
	// An authority presented with another executor's base policy is refused:
	// a grant must never compile against a lease it was not issued for.
	if _, _, _, _, err := backend.CompileWithGrantAuthority(firstSpec.GrantAuthority, basePolicy(`C:\two`), basePolicy(`C:\two`), nil); err == nil {
		t.Fatal("first executor's authority compiled a grant for the second executor's base policy")
	}
	// Releasing one executor's base leaves the other's untouched.
	if err := firstSpec.Release(); err != nil {
		t.Fatal(err)
	}
	if releases[first] != 1 || releases[second] != 0 {
		t.Fatalf("releases after first executor closed = %v, want only the first lease released", releases)
	}
	// Released before the second base, for the reason given in
	// TestRestrictedGrantCompileReusesBaseLeaseAndTransientReleaseKeepsItActive:
	// an unreleased probe's borrow would (correctly) keep the second lease
	// alive past secondSpec.Release.
	probe, _, _, _, err := backend.CompileWithGrantAuthority(secondSpec.GrantAuthority, basePolicy(`C:\two`), basePolicy(`C:\two`), nil)
	if err != nil {
		t.Fatalf("second executor's authority after the first released: %v", err)
	}
	if err := probe.Release(); err != nil {
		t.Fatal(err)
	}
	if err := secondSpec.Release(); err != nil {
		t.Fatal(err)
	}
	if releases[first] != 1 || releases[second] != 1 {
		t.Fatalf("final releases = %v, want each lease released exactly once", releases)
	}
}

// TestRestrictedBaseReleaseWaitsForOutstandingGrant pins the lease lifetime a
// borrowed authority needs: a transient grant spec's token still names the
// base SID, so the base lease's ACL projections must outlive it even when the
// executor's base spec is released first. The base release is deferred to the
// last borrower and happens exactly once.
func TestRestrictedBaseReleaseWaitsForOutstandingGrant(t *testing.T) {
	base, err := ExecutorSID("installation", "executor")
	if err != nil {
		t.Fatal(err)
	}
	baseReleases := 0
	backend := &restrictedBackend{config: Config{Mode: RestrictedToken}, deps: restrictedCompileDependencies{
		prepare: func(Config, *RestrictedRuntime, policy.Effective) (restrictedPreparedLease, error) {
			return restrictedPreparedLease{sid: base, journal: &RestrictedJournal{}, release: func() error { baseReleases++; return nil }}, nil
		},
		configure: func(*exec.Cmd, []SID) (func(), error) { return func() {}, nil },
	}}
	baseSpec, _, _, _, err := backend.Compile(policy.Effective{})
	if err != nil {
		t.Fatal(err)
	}
	grant, _, _, _, err := backend.CompileWithGrantAuthority(baseSpec.GrantAuthority, policy.Effective{}, policy.Effective{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := baseSpec.Release(); err != nil {
		t.Fatal(err)
	}
	if baseReleases != 0 {
		t.Fatal("base lease released while a grant spec still borrows it")
	}
	if _, _, _, _, err := backend.CompileWithGrantAuthority(baseSpec.GrantAuthority, policy.Effective{}, policy.Effective{}, nil); err == nil {
		t.Fatal("new grant compiled against a base authority that is retiring")
	}
	if err := grant.Release(); err != nil {
		t.Fatal(err)
	}
	if err := grant.Release(); err != nil {
		t.Fatal(err)
	}
	if baseReleases != 1 {
		t.Fatalf("base releases = %d, want exactly 1 once the last borrower released", baseReleases)
	}
}

func TestRestrictedGrantCollisionFailsBeforeProjectionAndRetainsRetirement(t *testing.T) {
	base, err := ExecutorSID("collision-installation", "collision-executor")
	if err != nil {
		t.Fatal(err)
	}
	for index, collision := range []string{"TokenUser", "TokenGroups"} {
		t.Run(collision, func(t *testing.T) {
			entropy := bytes.Repeat([]byte{byte(0x71 + index)}, sidEntropyBytes)
			store := newMemorySIDRetirementStore()
			generator, err := NewOneShotSIDGenerator(bytes.NewReader(entropy), store)
			if err != nil {
				t.Fatal(err)
			}

			target := filepath.Join(t.TempDir(), "grant.txt")
			if err := os.WriteFile(target, []byte("grant"), 0o600); err != nil {
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
			defer handle.Close()
			handle.SetAccess(policy.WriteAccess)

			projectCalls := 0
			authority := newRestrictedGrantAuthority(policy.Effective{}, restrictedPreparedLease{
				sid: base, journal: &RestrictedJournal{}, release: func() error { return nil },
			})
			backend := &restrictedBackend{
				config: Config{Mode: RestrictedToken},
				deps: restrictedCompileDependencies{
					configure: func(*exec.Cmd, []SID) (func(), error) { return nil, nil },
					newGrantSIDGenerator: func(*RestrictedJournal) (*OneShotSIDGenerator, error) {
						return generator, nil
					},
					validateTrustees: func(sids []SID) error {
						parsed := mustTestSID(t, sids[0].String())
						if collision == "TokenUser" {
							return ensureRestrictingSIDsAreNew(parsed, nil, []*win.SID{parsed})
						}
						return ensureRestrictingSIDsAreNew(nil, []win.SIDAndAttributes{{Sid: parsed}}, []*win.SID{parsed})
					},
					projectGrant: func(*policy.PathHandle, []policy.FSEntry, SID, *RestrictedJournal, io.Reader) (*ACLProjection, error) {
						projectCalls++
						return nil, nil
					},
				},
			}
			if _, _, _, _, err := backend.CompileWithGrantAuthority(authority, policy.Effective{}, policy.Effective{}, []*policy.PathHandle{handle}); err == nil {
				t.Fatal("colliding one-shot trustee compiled")
			}
			if projectCalls != 0 {
				t.Fatalf("grant projection calls = %d, want zero", projectCalls)
			}

			replay, err := NewOneShotSIDGenerator(bytes.NewReader(entropy), store)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := replay.Next(); !errors.Is(err, ErrSIDReuse) {
				t.Fatalf("rejected one-shot SID retirement = %v, want ErrSIDReuse", err)
			}
		})
	}
}

// TestRestrictedCompileRefusesUnixSocketEscapeHatch pins Task 1 for the
// restricted tier: any non-default profile.UnixSocketPolicy is refused, typed,
// before a lease, SID or journal record exists, on both the base compile and
// the grant compile, and the report names the unmediated feature.
func TestRestrictedCompileRefusesUnixSocketEscapeHatch(t *testing.T) {
	for _, unixSockets := range []profile.UnixSocketPolicy{
		{Mode: profile.UnixSocketsLocal},
		{Paths: []string{`C:\agent\ssh.sock`}},
	} {
		prepareCalls := 0
		backend := &restrictedBackend{config: Config{Mode: RestrictedToken}, deps: restrictedCompileDependencies{
			prepare: func(Config, *RestrictedRuntime, policy.Effective) (restrictedPreparedLease, error) {
				prepareCalls++
				return restrictedPreparedLease{}, nil
			},
			configure: func(*exec.Cmd, []SID) (func(), error) { return nil, nil },
		}}
		p := policy.Effective{Env: policy.EnvPolicy{Inherit: false}, UnixSockets: unixSockets}
		for name, compile := range map[string]func() (enforce.Spec, profile.CompileReport, uint8, uint64, error){
			"base": func() (enforce.Spec, profile.CompileReport, uint8, uint64, error) { return backend.Compile(p) },
			"grant": func() (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
				return backend.CompileWithGrantAuthority(nil, p, p, nil)
			},
		} {
			spec, report, level, _, err := compile()
			if !errors.Is(err, enforce.ErrUnavailable) || !errors.Is(err, policy.ErrUnsupportedClass) || errors.Is(err, ErrSetupRequired) {
				t.Fatalf("%s compile error = %v, want typed AF_UNIX refusal", name, err)
			}
			if spec.Wrap != nil || spec.Release != nil || level != profile.LevelNone {
				t.Fatalf("%s compile returned a partial spec %#v level %d", name, spec, level)
			}
			if !slices.Contains(report.Entries, profile.ReportEntry{
				Feature: "unix-sockets", Status: "unavailable", Detail: "AF_UNIX endpoints are not mediated on Windows",
			}) {
				t.Fatalf("%s report omits unix-sockets: %#v", name, report.Entries)
			}
		}
		if prepareCalls != 0 {
			t.Fatalf("AF_UNIX profile reached lease preparation %d times", prepareCalls)
		}
	}
}
