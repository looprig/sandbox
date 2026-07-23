//go:build windows

package windows

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
)

// This file is the Task 19 compile/filesystem matrix.  The planning rows are
// deliberately hermetic: they assert the identity-bound authority sent to the
// broker, rather than treating a path-string simulation as filesystem
// enforcement.  The live row below remains an explicit disposable-worker gate.

func TestElevatedFilesystemPlanMatrix(t *testing.T) {
	sid, err := ExecutorSID("matrix-installation", "executor")
	if err != nil {
		t.Fatal(err)
	}
	root := testIdentity(1, ACLObjectDirectory, 1)
	ordinary := testIdentity(2, ACLObjectFile, 1)
	protected := testIdentity(3, ACLObjectDirectory, 1)

	tests := []struct {
		name        string
		scope       ACLScope
		access      ACLAccess
		root        ACLObjectIdentity
		entries     []ACLPlanEntry
		wantAllows  []ACLAccess
		wantDenies  []ACLAccess
		wantSkipped int
	}{
		{
			name: "exact read", scope: ACLScopeExact, access: ACLRead,
			root: testIdentity(4, ACLObjectFile, 1), wantAllows: []ACLAccess{ACLRead},
		},
		{
			name: "exact read-write", scope: ACLScopeExact, access: ACLRead | ACLWrite,
			root: testIdentity(5, ACLObjectFile, 1), wantAllows: []ACLAccess{ACLRead, ACLWrite},
		},
		{
			name: "tree read", scope: ACLScopeTree, access: ACLRead, root: root,
			entries: []ACLPlanEntry{{Object: ordinary}}, wantAllows: []ACLAccess{ACLRead},
		},
		{
			name: "tree protected write carveout", scope: ACLScopeTree,
			access: ACLRead | ACLWrite, root: root,
			entries: []ACLPlanEntry{
				{Object: ordinary},
				{Object: protected, Deny: ACLWrite},
			},
			wantAllows: []ACLAccess{ACLRead, ACLWrite}, wantDenies: []ACLAccess{ACLWrite},
		},
		{
			name: "tree protected read-write carveout", scope: ACLScopeTree,
			access: ACLRead | ACLWrite, root: root,
			entries:    []ACLPlanEntry{{Object: protected, Deny: ACLRead | ACLWrite}},
			wantAllows: []ACLAccess{ACLRead, ACLWrite}, wantDenies: []ACLAccess{ACLRead, ACLWrite},
		},
		{
			name: "tree skips junction and symlink identities", scope: ACLScopeTree,
			access: ACLRead, root: root,
			entries: []ACLPlanEntry{
				{Object: reparseMatrixIdentity(6, 0xa0000003)}, // mount point/junction
				{Object: reparseMatrixIdentity(7, 0xa000000c)}, // symbolic link
			},
			wantAllows: []ACLAccess{ACLRead}, wantSkipped: 2,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			plan, err := BuildACLPlan(ACLPlanRequest{
				LeaseID: testLeaseID(), SID: sid, Scope: test.scope,
				Access: test.access, Root: test.root, Entries: test.entries,
			})
			if err != nil {
				t.Fatal(err)
			}
			var allows, denies []ACLAccess
			for _, mutation := range plan.Mutations() {
				ace := mutation.ACE()
				switch ace.Type {
				case ACEAllow:
					allows = append(allows, ace.Access)
					if mutation.Object() != test.root {
						t.Fatalf("allow attached to descendant identity: %+v", mutation.Object())
					}
				case ACEDeny:
					denies = append(denies, ace.Access)
					if mutation.Object() == test.root {
						t.Fatal("protected carveout deny attached to root")
					}
				}
			}
			if !slices.Equal(allows, test.wantAllows) || !slices.Equal(denies, test.wantDenies) {
				t.Fatalf("allows/denies = %v/%v, want %v/%v", allows, denies, test.wantAllows, test.wantDenies)
			}
			if got := len(plan.SkippedReparsePoints()); got != test.wantSkipped {
				t.Fatalf("skipped reparses = %d, want %d", got, test.wantSkipped)
			}
		})
	}
}

func TestElevatedFilesystemAdversarialIdentityMatrix(t *testing.T) {
	sid, err := ExecutorSID("matrix-installation", "executor")
	if err != nil {
		t.Fatal(err)
	}
	root := testIdentity(1, ACLObjectDirectory, 1)
	file := testIdentity(2, ACLObjectFile, 1)

	tests := []struct {
		name    string
		request ACLPlanRequest
	}{
		{
			name: "reparse root",
			request: ACLPlanRequest{LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree,
				Access: ACLRead, Root: reparseMatrixIdentity(1, 0xa000000c)},
		},
		{
			name: "root identity swapped after capture",
			request: ACLPlanRequest{LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree,
				Access: ACLRead, Root: ACLObjectIdentity{VolumeSerial: root.VolumeSerial, FileID: [16]byte{99}, Kind: ACLObjectDirectory}},
		},
		{
			name: "duplicate identity race",
			request: ACLPlanRequest{LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree,
				Access: ACLRead, Root: root, Entries: []ACLPlanEntry{{Object: file}, {Object: file}}},
		},
		{
			name: "inconsistent reparse metadata",
			request: ACLPlanRequest{LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree,
				Access: ACLRead, Root: root, Entries: []ACLPlanEntry{{Object: ACLObjectIdentity{
					VolumeSerial: 7, FileID: [16]byte{3}, Kind: ACLObjectFile, ReparseTag: 0xa000000c, LinkCount: 1,
				}}}},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := BuildACLPlan(test.request); err == nil {
				t.Fatal("adversarial identity was accepted")
			}
		})
	}
}

func TestElevatedFilesystemHardlinkAndVolumeMatrix(t *testing.T) {
	sid, err := ExecutorSID("matrix-installation", "executor")
	if err != nil {
		t.Fatal(err)
	}
	exactHardlink := testIdentity(1, ACLObjectFile, 2)
	if _, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeExact, Access: ACLRead,
		Root: exactHardlink,
	}); !errors.Is(err, policy.ErrUnsupportedClass) {
		t.Fatalf("exact multi-link error = %v, want unsupported class", err)
	}

	root := testIdentity(2, ACLObjectDirectory, 1)
	treeHardlink := testIdentity(3, ACLObjectFile, 2)
	treeHardlink.VolumeSerial = 8 // another volume identity is never conflated.
	plan, err := BuildACLPlan(ACLPlanRequest{
		LeaseID: testLeaseID(), SID: sid, Scope: ACLScopeTree, Access: ACLRead | ACLWrite,
		Root: root, Entries: []ACLPlanEntry{{Object: treeHardlink}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(plan.Narrowings(), []string{"windows.filesystem.hardlink"}) {
		t.Fatalf("tree hard-link narrowing = %v", plan.Narrowings())
	}
	var denied int
	for _, mutation := range plan.Mutations() {
		if mutation.Object() == treeHardlink && mutation.ACE().Type == ACEDeny {
			denied++
		}
	}
	if denied != 2 {
		t.Fatalf("other-volume multi-link deny count = %d, want read and write", denied)
	}
}

func TestElevatedBrokerPathClassMatrix(t *testing.T) {
	for _, test := range []struct {
		name string
		path string
		ok   bool
	}{
		{"canonical mixed case", `C:\Work\MiXeD.txt`, true},
		{"other drive", `D:\work\file.txt`, true},
		{"extended DOS path", `\\?\C:\work\file.txt`, false},
		{"ADS", `C:\work\file.txt:stream`, false},
		{"UNC", `\\server\share\file.txt`, false},
		{"device", `\\.\PhysicalDrive0`, false},
		{"NT device", `\Device\HarddiskVolume1\file.txt`, false},
		{"relative", `work\file.txt`, false},
		{"parent traversal", `C:\work\..\outside.txt`, false},
		{"forward slash", `C:/work/file.txt`, false},
		{"lowercase drive", `c:\work\file.txt`, false},
		{"trailing dot", `C:\work\file.`, false},
		{"trailing space", `C:\work\file `, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := canonicalBrokerPath(test.path); got != test.ok {
				t.Fatalf("canonicalBrokerPath(%q) = %t, want %t", test.path, got, test.ok)
			}
		})
	}
}

func TestElevatedCompileGuaranteeAndReportMatrix(t *testing.T) {
	requiredCore := uint64(profile.GuaranteeProcessBoundary | profile.GuaranteeReadBoundary |
		profile.GuaranteeWriteBoundary | profile.GuaranteeResourceLimits)
	for _, test := range []struct {
		name        string
		policy      policy.Effective
		wantAccount brokerAccountKind
		wantBits    uint64
		wantLevel   uint8
	}{
		{
			name: "offline complete",
			policy: policy.Effective{
				FS:                 []policy.FSEntry{{Path: `C:\work`, Access: policy.ReadAccess | policy.WriteAccess}},
				RuntimeBaselines:   []string{policy.WindowsRuntimeBaseline},
				RequiredGuarantees: requiredCore | profile.GuaranteeNetworkBoundary,
			},
			wantAccount: brokerAccountOffline,
			wantBits:    requiredCore | profile.GuaranteeNetworkBoundary,
			wantLevel:   profile.LevelFull,
		},
		{
			name: "online claims no network boundary",
			policy: policy.Effective{
				FS:  []policy.FSEntry{{Path: `C:\work`, Access: policy.ReadAccess}},
				Net: policy.NetPolicy{Open: true}, RuntimeBaselines: []string{policy.WindowsRuntimeBaseline},
				RequiredGuarantees: requiredCore,
			},
			wantAccount: brokerAccountOnline, wantBits: requiredCore, wantLevel: profile.LevelFull,
		},
		{
			name: "offline target proxy",
			policy: policy.Effective{
				FS:  []policy.FSEntry{{Path: `C:\work`, Access: policy.ReadAccess}},
				Net: policy.NetPolicy{ProxyPort: 49152}, RuntimeBaselines: []string{policy.WindowsRuntimeBaseline},
				RequiredGuarantees: requiredCore | profile.GuaranteeNetworkBoundary | profile.GuaranteeTargetNetwork,
			},
			wantAccount: brokerAccountOffline,
			wantBits:    requiredCore | profile.GuaranteeNetworkBoundary | profile.GuaranteeTargetNetwork,
			wantLevel:   profile.LevelFull,
		},
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
			spec, report, level, bits, err := backend.Compile(test.policy)
			if err != nil {
				t.Fatal(err)
			}
			if bits&test.wantBits != test.wantBits || level != test.wantLevel {
				t.Fatalf("bits/level = %#x/%d, want at least %#x/%d", bits, level, test.wantBits, test.wantLevel)
			}
			if test.policy.Net.Open && bits&profile.GuaranteeNetworkBoundary != 0 {
				t.Fatal("online account claimed a network boundary")
			}
			for _, feature := range []string{
				"windows.installed-host", "windows.token", "windows.filesystem.read",
				"windows.filesystem.write", "windows.job", "windows.private-desktop",
				"windows.resource-limits", policy.WindowsRuntimeBaseline,
			} {
				if !slices.ContainsFunc(report.Entries, func(entry profile.ReportEntry) bool {
					return entry.Feature == feature && entry.Status == "Enforced"
				}) {
					t.Errorf("missing enforced report row %q: %#v", feature, report)
				}
			}
			_, configure, cleanup := spec.Wrap(`C:\work`, []string{`C:\tool.exe`})
			if configure != nil || cleanup == nil || lease.account != test.wantAccount {
				t.Fatalf("spawn account/configure/cleanup = %d/%t/%t", lease.account, configure != nil, cleanup == nil)
			}
			cleanup()
			if err := spec.Release(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestElevatedCompileFailsBeforeLeaseForEveryProcessClaim(t *testing.T) {
	for _, test := range []struct {
		name string
		flip func(*elevatedSetupSnapshot)
	}{
		{"runtime baseline", func(snapshot *elevatedSetupSnapshot) { snapshot.RuntimeBaselineReady = false }},
		{"runner hash", func(snapshot *elevatedSetupSnapshot) { snapshot.RunnerHashVerified = false }},
		{"private desktop", func(snapshot *elevatedSetupSnapshot) { snapshot.PrivateDesktopReady = false }},
		{"job and resources", func(snapshot *elevatedSetupSnapshot) { snapshot.JobReadbackReady = false }},
		{"stdio-only handle list", func(snapshot *elevatedSetupSnapshot) { snapshot.HandleListReady = false }},
		{"restricted account", func(snapshot *elevatedSetupSnapshot) { snapshot.AccountsReady = false }},
		{"protected credential", func(snapshot *elevatedSetupSnapshot) { snapshot.CredentialsReady = false }},
	} {
		t.Run(test.name, func(t *testing.T) {
			acquired := false
			backend := &elevatedBackend{deps: elevatedCompileDependencies{
				inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) {
					snapshot := readyElevatedSnapshot()
					test.flip(&snapshot)
					return snapshot, nil
				},
				acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
					acquired = true
					return &fakeElevatedLease{}, nil
				},
			}}
			_, _, level, bits, err := backend.Compile(policy.Effective{
				RequiredGuarantees: profile.GuaranteeProcessBoundary |
					profile.GuaranteeReadBoundary | profile.GuaranteeWriteBoundary |
					profile.GuaranteeResourceLimits,
			})
			if !errors.Is(err, ErrSetupStale) || level != profile.LevelNone || bits != 0 || acquired {
				t.Fatalf("level/bits/acquired/error = %d/%#x/%t/%v", level, bits, acquired, err)
			}
		})
	}

	lease := &fakeElevatedLease{}
	backend := &elevatedBackend{deps: elevatedCompileDependencies{
		inspect: func(Config, policy.Effective) (elevatedSetupSnapshot, error) {
			return readyElevatedSnapshot(), nil
		},
		acquire: func(elevatedSetupSnapshot, policy.Effective) (elevatedLease, error) {
			return lease, nil
		},
	}}
	_, _, level, bits, err := backend.Compile(policy.Effective{
		RequiredGuarantees: profile.GuaranteeAddressNetwork,
	})
	if !errors.Is(err, enforce.ErrUnavailable) || level != profile.LevelNone ||
		bits&profile.GuaranteeAddressNetwork != 0 || lease.releases != 1 {
		t.Fatalf("unsupported address claim = level %d bits %#x releases %d err %v", level, bits, lease.releases, err)
	}
}

func TestElevatedFilesystemDisposableWorkerMatrix(t *testing.T) {
	if os.Getenv("SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST") != "1" {
		t.Skip("SANDBOX_WINDOWS_DISPOSABLE_ACL_TEST=1 is required; Task 19 filesystem matrix remains an outstanding live phase gate")
	}
	requireACLDisposableStandardSourceToken(t)

	root := t.TempDir()
	mixed := filepath.Join(root, "MiXeD.txt")
	if err := os.WriteFile(mixed, []byte("positive control"), 0o600); err != nil {
		t.Fatalf("positive control cannot create mixed-case fixture: %v", err)
	}
	binding, err := policy.CapturePathBinding(strings.ToUpper(mixed))
	if err != nil {
		t.Fatalf("case-insensitive binding failed on disposable worker: %v", err)
	}
	handle, err := policy.AcquirePathHandle(&binding, binding.CanonicalPath, true)
	if err != nil {
		t.Fatalf("retain exact mixed-case fixture: %v", err)
	}
	defer handle.Close()

	// These namespace classes may never be smuggled through the authenticated
	// broker as ordinary local DOS paths.
	for name, path := range map[string]string{
		"ADS":      mixed + ":stream",
		"extended": `\\?\` + mixed,
		"UNC":      `\\localhost\C$\Windows`,
		"device":   `\\.\PhysicalDrive0`,
	} {
		t.Run(name, func(t *testing.T) {
			if canonicalBrokerPath(path) {
				t.Fatalf("unsupported namespace %q accepted", path)
			}
		})
	}
}

func reparseMatrixIdentity(id byte, tag uint32) ACLObjectIdentity {
	identity := testIdentity(id, ACLObjectReparsePoint, 1)
	identity.ReparseTag = tag
	return identity
}
