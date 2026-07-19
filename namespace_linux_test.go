//go:build linux

package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// requireRung1Caps skips a rung-1 ENFORCEMENT test when the host cannot create
// the unprivileged user+mount+net namespaces the mechanism needs, recording the
// exact reason (SPEC §7.2 rung 1). The authoring host has
// apparmor_restrict_unprivileged_userns=1, so every enforcement test skips HERE
// and is validated only in CI. Compilation/enumeration unit tests do NOT gate on
// this — they walk the filesystem and build plans without any namespace.
func requireRung1Caps(t *testing.T) {
	t.Helper()
	c := probeLinuxCaps()
	if !c.userns || !c.mountns || !c.netns {
		t.Skip("rung-1 backend requires unprivileged userns+mountns+netns; blocked on this host by apparmor_restrict_unprivileged_userns=1 — CI-verified")
	}
}

// TestCompileMountView asserts the pure policy -> mount-view plan compilation:
// writable roots become rw binds, read roots + carveouts become ro binds, literal
// secret denies become masks, glob denies are carried for the spawn scan, and a
// deny that is an ancestor-or-equal of an allow drops that allow (deny is a hard
// override). This runs on THIS host — no namespaces.
func TestCompileMountView(t *testing.T) {
	t.Parallel()
	ws := "/work/repo"

	tests := []struct {
		name         string
		policy       effectivePolicy
		wantRW       []string // must be present in rwBinds
		wantRO       []string // must be present in roBinds
		wantNotBound []string // must NOT appear in rw or ro binds
		wantGlob     []string // must be present in globDenies
		wantMaskAny  bool     // denyMasks must be non-empty
	}{
		{
			name:        "write mode: workspace+tmp rw, / ro, carveouts ro, secrets masked",
			policy:      PolicyFor(Write, ws),
			wantRW:      []string{ws, writableTmpRoot},
			wantRO:      []string{"/", filepath.Join(ws, ".git"), filepath.Join(ws, ".looprig")},
			wantGlob:    []string{"**/.env*"},
			wantMaskAny: true,
		},
		{
			name:   "zerotrust: workspace read-only bind, no rw roots",
			policy: PolicyFor(ZeroTrust, ws),
			wantRO: []string{ws},
			// zerotrust grants no writable root at all.
			wantNotBound: []string{writableTmpRoot},
			wantGlob:     []string{"**/.env*"},
			wantMaskAny:  true,
		},
		{
			name: "deny hard-override: an allow at-or-under a deny is dropped",
			policy: effectivePolicy{
				Workspace: ws,
				FS: []fsEntry{
					{Path: ws, Access: readFSAccess | writeFSAccess | execFSAccess},
					{Path: filepath.Join(ws, "secret"), Access: readFSAccess}, // under the deny below
					{Path: filepath.Join(ws, "secret"), Access: denyFSAccess},
				},
			},
			wantRW:       []string{ws},
			wantNotBound: []string{filepath.Join(ws, "secret")},
			wantMaskAny:  true,
		},
		{
			name:   "open/full policy: single rw bind, no denies",
			policy: effectivePolicy{Workspace: ws, FS: []fsEntry{{Path: "/", Access: readFSAccess | writeFSAccess | execFSAccess}}},
			wantRW: []string{"/"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			plan := compileMountView(tt.policy)
			for _, w := range tt.wantRW {
				if !containsStr(plan.rwBinds, w) {
					t.Errorf("rwBinds %v missing %q", plan.rwBinds, w)
				}
			}
			for _, w := range tt.wantRO {
				if !containsStr(plan.roBinds, w) {
					t.Errorf("roBinds %v missing %q", plan.roBinds, w)
				}
			}
			for _, w := range tt.wantNotBound {
				if containsStr(plan.rwBinds, w) || containsStr(plan.roBinds, w) {
					t.Errorf("path %q should not be bound; rw=%v ro=%v", w, plan.rwBinds, plan.roBinds)
				}
			}
			for _, g := range tt.wantGlob {
				if !containsStr(plan.globDenies, g) {
					t.Errorf("globDenies %v missing %q", plan.globDenies, g)
				}
			}
			if tt.wantMaskAny && len(plan.denyMasks) == 0 {
				t.Errorf("denyMasks empty, want at least one literal secret deny")
			}
		})
	}
}

// TestEnumerateMountView asserts the spawn-time enumeration against a real
// filesystem: binds are classified dir/file, nonexistent roots are dropped (fail
// secure), binds are sorted parents-first, and existing deny targets become masks
// while missing ones are skipped. Runs on THIS host (no namespaces).
func TestEnumerateMountView(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatalf("mkdir sub: %v", err)
	}
	file := filepath.Join(root, "f.txt")
	if err := os.WriteFile(file, []byte("x"), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	missing := filepath.Join(root, "does-not-exist")

	plan := mountViewPlan{
		rwBinds:   []string{root, missing}, // missing must be dropped
		roBinds:   []string{sub},
		denyMasks: []string{file, missing}, // missing deny must be skipped
	}
	spec := enumerateMountView(plan)

	// Binds: root (rw, dir) and sub (ro, dir); missing dropped; sorted parents-first.
	if len(spec.Binds) != 2 {
		t.Fatalf("Binds = %+v, want 2 (root, sub; missing dropped)", spec.Binds)
	}
	if spec.Binds[0].Target != root || spec.Binds[1].Target != sub {
		t.Errorf("Binds not sorted parents-first: %q then %q", spec.Binds[0].Target, spec.Binds[1].Target)
	}
	if spec.Binds[0].ReadOnly {
		t.Errorf("root bind should be rw")
	}
	if !spec.Binds[1].ReadOnly {
		t.Errorf("sub bind should be ro")
	}
	if !spec.Binds[0].IsDir || !spec.Binds[1].IsDir {
		t.Errorf("binds should be dirs: %+v", spec.Binds)
	}
	// Masks: only the existing file; the missing deny is skipped.
	if len(spec.Masks) != 1 || spec.Masks[0].Target != file || spec.Masks[0].IsDir {
		t.Errorf("Masks = %+v, want single file mask for %q", spec.Masks, file)
	}
}

// TestScanGlobDenies asserts the bounded glob-deny scan: nested .env* matches are
// found, non-matching files are ignored, symlinks are not followed, and the depth
// bound is honored. Runs on THIS host.
func TestScanGlobDenies(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	topEnv := filepath.Join(root, ".env")
	if err := os.WriteFile(topEnv, []byte("SECRET=1"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	deep := filepath.Join(root, "a", "b")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatalf("mkdir deep: %v", err)
	}
	deepEnv := filepath.Join(deep, ".env.local")
	if err := os.WriteFile(deepEnv, []byte("SECRET=2"), 0o600); err != nil {
		t.Fatalf("write deep .env: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "normal.txt"), []byte("ok"), 0o644); err != nil {
		t.Fatalf("write normal: %v", err)
	}
	// A symlink whose name matches the pattern must NOT be masked (never followed).
	link := filepath.Join(root, ".envlink")
	if err := os.Symlink(topEnv, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	masks := scanGlobDenies([]string{root}, []string{"**/.env*"}, globScanMaxDepth)
	got := make(map[string]bool)
	for _, m := range masks {
		got[m.Target] = true
	}
	if !got[topEnv] {
		t.Errorf("top-level .env not masked; masks=%v", masks)
	}
	if !got[deepEnv] {
		t.Errorf("nested .env.local not masked; masks=%v", masks)
	}
	if got[filepath.Join(root, "normal.txt")] {
		t.Errorf("non-matching normal.txt was masked")
	}
	if got[link] {
		t.Errorf("symlink .envlink was masked (must not follow symlinks)")
	}

	// Depth bound: with maxDepth 0 only the top level is scanned.
	shallow := scanGlobDenies([]string{root}, []string{"**/.env*"}, 0)
	for _, m := range shallow {
		if m.Target == deepEnv {
			t.Errorf("depth-0 scan reached %q; depth bound not honored", deepEnv)
		}
	}
}

// TestConfigureRung1SysProcAttr asserts the namespace cloneflags + uid/gid maps
// (SPEC §7.2 rung 1): user+mount+pid always, net only when egress is confined,
// and the caller mapped to root-in-userns. Pure logic — runs on THIS host.
func TestConfigureRung1SysProcAttr(t *testing.T) {
	t.Parallel()
	base := uintptr(syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWPID)
	tests := []struct {
		name        string
		netConfined bool
		wantFlags   uintptr
	}{
		{"confined egress adds a net namespace", true, base | syscall.CLONE_NEWNET},
		{"open egress keeps host networking (no net ns)", false, base},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			attr := &syscall.SysProcAttr{}
			configureRung1SysProcAttr(attr, tt.netConfined)
			if attr.Cloneflags != tt.wantFlags {
				t.Errorf("Cloneflags = %#x, want %#x", attr.Cloneflags, tt.wantFlags)
			}
			if len(attr.UidMappings) != 1 || attr.UidMappings[0].ContainerID != 0 || attr.UidMappings[0].HostID != os.Getuid() {
				t.Errorf("UidMappings = %+v, want caller->root", attr.UidMappings)
			}
			if len(attr.GidMappings) != 1 || attr.GidMappings[0].ContainerID != 0 || attr.GidMappings[0].HostID != os.Getgid() {
				t.Errorf("GidMappings = %+v, want caller->root", attr.GidMappings)
			}
		})
	}
}

// TestSelectLinuxBackendRung1 asserts the selector returns a backend compiled for
// rung 1 when the probe yields rungOne, and rung 2 for rungTwo — the wiring proof
// that platformBackend now selects the full tier. Pure logic — runs on THIS host.
func TestSelectLinuxBackendRung1(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		rung     rung
		wantRung rung
	}{
		{"rungOne selects the rung-1 backend", rungOne, rungOne},
		{"rungTwo selects the rung-2 backend", rungTwo, rungTwo},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b, err := selectLinuxBackend(tt.rung, true)
			if err != nil {
				t.Fatalf("selectLinuxBackend: %v", err)
			}
			lb, ok := b.(*linuxBackend)
			if !ok {
				t.Fatalf("backend = %T, want *linuxBackend", b)
			}
			if lb.rung != tt.wantRung {
				t.Errorf("backend rung = %d, want %d", lb.rung, tt.wantRung)
			}
		})
	}
}

// TestCompileRung1LevelAndGuarantees asserts the rung-1 compile reports LevelFull
// and the full guarantee posture (SPEC §7.2 rung 1, §7.5): process boundary,
// write boundary, read denies (mount masks enforce fixed + glob), env scrub, and
// the address-scoped network boundary. This exercises compile ONLY (no spawn), so
// it runs on THIS host even though the enforcement path cannot.
func TestCompileRung1LevelAndGuarantees(t *testing.T) {
	t.Parallel()
	ws := t.TempDir()
	tests := []struct {
		name     string
		policy   effectivePolicy
		wantBits uint64 // bits that MUST be set
	}{
		{
			name:     "write mode: full posture incl. address network (egress confined-empty)",
			policy:   PolicyFor(Write, ws),
			wantBits: GuaranteeProcessBoundary | GuaranteeWriteBoundary | GuaranteeReadBoundary | GuaranteeEnvScrub | GuaranteeNetworkBoundary | GuaranteeAddressNetwork,
		},
		{
			name:     "trusted mode: full posture with ports/loopback/private/dns",
			policy:   PolicyFor(Trusted, ws),
			wantBits: GuaranteeProcessBoundary | GuaranteeWriteBoundary | GuaranteeReadBoundary | GuaranteeEnvScrub | GuaranteeNetworkBoundary | GuaranteeAddressNetwork,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			b := newLinuxBackendRung1()
			_, report, level, bits, err := b.compile(tt.policy)
			if err != nil {
				t.Fatalf("compile: %v", err)
			}
			if level != LevelFull {
				t.Errorf("level = %d, want LevelFull (%d)", level, LevelFull)
			}
			if bits&tt.wantBits != tt.wantBits {
				t.Errorf("guarantee bits = %#x, missing %#x", bits, tt.wantBits&^bits)
			}
			// The report must record restricted-read and metadata-deny as enforced —
			// the two rung-2 cannot claim.
			if !reportHas(report, "restricted-read", "enforced") {
				t.Errorf("report missing enforced restricted-read: %+v", report.Entries)
			}
			if !reportHas(report, "metadata-deny", "enforced") {
				t.Errorf("report missing enforced metadata-deny: %+v", report.Entries)
			}
			if !reportHas(report, "glob-deny", "enforced") {
				t.Errorf("report missing enforced glob-deny: %+v", report.Entries)
			}
		})
	}
}

// TestMountViewSpecGobRoundTrip asserts the rung-1 mount-view and nftables specs
// survive the gob re-exec codec unchanged (they cross the pipe to the stage-2
// child). Runs on THIS host.
func TestMountViewSpecGobRoundTrip(t *testing.T) {
	t.Parallel()
	spec := stage2Spec{
		Dir:  "/work",
		Argv: []string{"/bin/true"},
		Env:  []string{"PATH=/usr/bin"},
		Rung: stage2RungOne,
		MountView: MountViewSpec{
			Binds: []BindSpec{
				{Source: "/work", Target: "/work", ReadOnly: false, IsDir: true},
				{Source: "/work/.git", Target: "/work/.git", ReadOnly: true, IsDir: true},
			},
			Masks: []MaskSpec{{Target: "/work/.env", IsDir: false}},
		},
		NftRules: NftSpec{
			Confined:      true,
			TCPPorts:      []uint16{443},
			Loopback:      true,
			Private:       true,
			DNS:           true,
			MetadataCIDRs: metadataDenyCIDRs(),
		},
	}
	var buf bytes.Buffer
	if err := encodeStage2Spec(&buf, spec); err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, err := decodeStage2Spec(fileFromBuf(t, &buf))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Rung != stage2RungOne {
		t.Errorf("Rung = %d, want %d", got.Rung, stage2RungOne)
	}
	if len(got.MountView.Binds) != 2 || got.MountView.Binds[1].Target != "/work/.git" || !got.MountView.Binds[1].ReadOnly {
		t.Errorf("MountView.Binds round-trip mismatch: %+v", got.MountView.Binds)
	}
	if len(got.MountView.Masks) != 1 || got.MountView.Masks[0].Target != "/work/.env" {
		t.Errorf("MountView.Masks round-trip mismatch: %+v", got.MountView.Masks)
	}
	if !got.NftRules.Confined || len(got.NftRules.TCPPorts) != 1 || got.NftRules.TCPPorts[0] != 443 {
		t.Errorf("NftRules round-trip mismatch: %+v", got.NftRules)
	}
	if len(got.NftRules.MetadataCIDRs) != len(metadataDenyCIDRs()) {
		t.Errorf("NftRules.MetadataCIDRs round-trip mismatch: %+v", got.NftRules.MetadataCIDRs)
	}
}

// TestRung1MountViewEnforcement is the CI-verified enforcement proof for the
// bind-mount view (SPEC §7.2 rung 1, §7.5). Anti-fail-open: it asserts BOTH the
// positive (the workspace is visible and writable) AND the negative (a host path
// NOT in the policy is INVISIBLE — restricted-read, not merely unreadable — and a
// glob-masked .env reads empty). It SKIPS on the authoring host (userns blocked)
// with a recorded reason and runs for real only in CI.
func TestRung1MountViewEnforcement(t *testing.T) {
	requireRung1Caps(t)

	ws := t.TempDir()
	if err := os.WriteFile(filepath.Join(ws, "hello.txt"), []byte("hi"), 0o644); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ws, ".env"), []byte("SECRET=leak"), 0o600); err != nil {
		t.Fatalf("write .env: %v", err)
	}
	// A sibling temp dir NOT granted by the policy: it must be invisible after the
	// pivot_root (zerotrust binds only the workspace + minimal system reads).
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("TOPSECRET"), 0o600); err != nil {
		t.Fatalf("write outside: %v", err)
	}

	// Write mode (workspace rw, glob deny on .env). The workspace is visible/writable
	// and the .env is masked empty; use Write so the write assertion is meaningful.
	e, err := newExecutorForEffectivePolicy(PolicyFor(Write, ws), withBackend(newLinuxBackendRung1()))
	if err != nil {
		t.Fatalf("NewExecutor: %v", err)
	}
	script := strings.Join([]string{
		`cat hello.txt`, // POSITIVE: workspace read
		`echo written > newfile.txt && echo WROTE`,           // POSITIVE: workspace write
		`printf 'ENV=[%s]\n' "$(cat .env 2>/dev/null)"`,      // .env masked -> empty
		`cat ` + outsideFile + ` 2>/dev/null || echo HIDDEN`, // NEGATIVE: invisible host path
	}, "; ")
	out, code, err := e.RunCommand(context.Background(), ws, script)
	if err != nil || code != 0 {
		t.Fatalf("RunCommand: err=%v code=%d out=%q", err, code, out)
	}
	s := string(out)
	if !strings.Contains(s, "hi") {
		t.Errorf("workspace file not visible; out=%q", s)
	}
	if !strings.Contains(s, "WROTE") {
		t.Errorf("workspace not writable; out=%q", s)
	}
	if strings.Contains(s, "SECRET=leak") || !strings.Contains(s, "ENV=[]") {
		t.Errorf("glob-masked .env leaked (want ENV=[]); out=%q", s)
	}
	if strings.Contains(s, "TOPSECRET") || !strings.Contains(s, "HIDDEN") {
		t.Errorf("out-of-policy host path was visible; out=%q", s)
	}
}
