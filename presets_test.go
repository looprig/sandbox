package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

// fsAccess returns the access granted to an exact path by the first matching
// entry, and whether any entry named that path.
func fsAccess(fs []FSEntry, path string) (FSAccess, bool) {
	for _, e := range fs {
		if e.Path == path {
			return e.Access, true
		}
	}
	return 0, false
}

// fsHasDeny reports whether some entry denies (DenyAccess) the exact path.
func fsHasDeny(fs []FSEntry, path string) bool {
	for _, e := range fs {
		if e.Path == path && e.Access == DenyAccess {
			return true
		}
	}
	return false
}

const testWS = "/work/repo"

// TestPolicyForModes is the per-mode expansion table (SPEC §4, §5.1–§5.5).
func TestPolicyForModes(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}
	sshDeny := filepath.Join(home, ".ssh")

	tests := []struct {
		name string
		mode Mode
		// FS expectations
		wsAccess       FSAccess // access on the workspace root itself
		wantBroadRead  bool     // {"/" : Read|Exec}
		wantFullAccess bool     // {"/" : Read|Write|Exec}
		wantSystemRead bool     // MinimalSystemReadPaths present (e.g. /usr)
		wantTmpWrite   bool     // {"/tmp" : Read|Write|Exec}
		wantCarveouts  bool     // ws/.git re-masked read-only
		wantSecrets    bool     // DefaultSecretDenials applied
		// Net / Env expectations
		wantNet     NetPolicy
		wantInherit bool
		wantTMPDIR  bool
	}{
		{
			name:           "zerotrust",
			mode:           ZeroTrust,
			wsAccess:       ReadAccess,
			wantSystemRead: true,
			wantSecrets:    true,
			wantNet:        NetPolicy{},
			wantInherit:    false,
			wantTMPDIR:     true,
		},
		{
			name:          "readonly",
			mode:          ReadOnly,
			wsAccess:      0, // no dedicated ws entry; covered by broad read
			wantBroadRead: true,
			wantSecrets:   true,
			wantNet:       NetPolicy{},
			wantInherit:   false,
			wantTMPDIR:    true,
		},
		{
			name:          "write",
			mode:          Write,
			wsAccess:      ReadAccess | WriteAccess | ExecAccess,
			wantBroadRead: true,
			wantTmpWrite:  true,
			wantCarveouts: true,
			wantSecrets:   true,
			wantNet:       NetPolicy{},
			wantInherit:   false,
			wantTMPDIR:    true,
		},
		{
			name:          "trusted",
			mode:          Trusted,
			wsAccess:      ReadAccess | WriteAccess | ExecAccess,
			wantBroadRead: true,
			wantTmpWrite:  true,
			wantCarveouts: true,
			wantSecrets:   true,
			wantNet:       NetPolicy{Loopback: true, Private: true, Ports: []uint16{443}, DNS: true},
			wantInherit:   false,
			wantTMPDIR:    true,
		},
		{
			name:           "unconfined",
			mode:           Unconfined,
			wantFullAccess: true,
			wantSecrets:    false,
			wantNet:        NetPolicy{Open: true},
			wantInherit:    true,
			wantTMPDIR:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := PolicyFor(tt.mode, testWS)

			if p.Workspace != testWS {
				t.Errorf("Workspace = %q, want %q", p.Workspace, testWS)
			}

			// /dev/null is process plumbing, not persistent storage. Every mode
			// must permit programs such as Git to open it read-write during startup.
			nullAccess := Resolve(p.FS, "/dev/null")
			if want := ReadAccess | WriteAccess; nullAccess&want != want {
				t.Errorf("/dev/null access = %d, want at least Read|Write", nullAccess)
			}

			// Workspace root access.
			if tt.wsAccess != 0 {
				got, ok := fsAccess(p.FS, testWS)
				if !ok {
					t.Errorf("no FS entry for workspace %q", testWS)
				} else if got != tt.wsAccess {
					t.Errorf("workspace access = %d, want %d", got, tt.wsAccess)
				}
			}

			// Broad host read.
			if acc, ok := fsAccess(p.FS, "/"); tt.wantBroadRead {
				if !ok || acc != ReadAccess|ExecAccess {
					t.Errorf("broad read: got (%d,%v), want / => Read|Exec", acc, ok)
				}
			} else if !tt.wantFullAccess && ok {
				t.Errorf("unexpected root entry %d for mode %s", acc, tt.name)
			}

			// Full access (unconfined).
			if tt.wantFullAccess {
				if acc, ok := fsAccess(p.FS, "/"); !ok || acc != ReadAccess|WriteAccess|ExecAccess {
					t.Errorf("full access: got (%d,%v), want / => Read|Write|Exec", acc, ok)
				}
			}

			// Minimal system reads (zerotrust only).
			if acc, ok := fsAccess(p.FS, "/usr"); tt.wantSystemRead {
				if !ok || acc != ReadAccess|ExecAccess {
					t.Errorf("/usr: got (%d,%v), want Read|Exec", acc, ok)
				}
			} else if ok {
				t.Errorf("mode %s should not carry a dedicated /usr read entry", tt.name)
			}

			// /tmp writable.
			if acc, ok := fsAccess(p.FS, "/tmp"); tt.wantTmpWrite {
				if !ok || acc != ReadAccess|WriteAccess|ExecAccess {
					t.Errorf("/tmp: got (%d,%v), want Read|Write|Exec", acc, ok)
				}
			} else if ok && acc&WriteAccess != 0 {
				t.Errorf("mode %s should not have writable /tmp", tt.name)
			}

			// Carveouts: ws/.git re-masked read-only.
			gitCarve := filepath.Join(testWS, ".git")
			looprigCarve := filepath.Join(testWS, ".looprig")
			if tt.wantCarveouts {
				if acc, ok := fsAccess(p.FS, gitCarve); !ok || acc != ReadAccess {
					t.Errorf("%s: got (%d,%v), want ReadAccess carveout", gitCarve, acc, ok)
				}
				if acc, ok := fsAccess(p.FS, looprigCarve); !ok || acc != ReadAccess {
					t.Errorf("%s: got (%d,%v), want ReadAccess carveout", looprigCarve, acc, ok)
				}
			} else if _, ok := fsAccess(p.FS, gitCarve); ok {
				t.Errorf("mode %s should not carve %s", tt.name, gitCarve)
			}

			// Secret denials.
			if fsHasDeny(p.FS, sshDeny) != tt.wantSecrets {
				t.Errorf("secret deny %s present = %v, want %v", sshDeny, fsHasDeny(p.FS, sshDeny), tt.wantSecrets)
			}
			if fsHasDeny(p.FS, "**/.env*") != tt.wantSecrets {
				t.Errorf("glob deny **/.env* present = %v, want %v", fsHasDeny(p.FS, "**/.env*"), tt.wantSecrets)
			}

			// Network.
			if !netEqual(p.Net, tt.wantNet) {
				t.Errorf("Net = %+v, want %+v", p.Net, tt.wantNet)
			}

			// Environment.
			if p.Env.Inherit != tt.wantInherit {
				t.Errorf("Env.Inherit = %v, want %v", p.Env.Inherit, tt.wantInherit)
			}
			if got := p.Env.Set["TMPDIR"]; tt.wantTMPDIR && got != "/tmp" {
				t.Errorf("Env.Set[TMPDIR] = %q, want /tmp", got)
			} else if !tt.wantTMPDIR && got != "" {
				t.Errorf("Env.Set[TMPDIR] = %q, want unset", got)
			}

			// AckUnconfined is never set by mode expansion alone.
			if p.AckUnconfined {
				t.Errorf("mode %s: AckUnconfined set without WithAckUnconfined", tt.name)
			}
		})
	}
}

func netEqual(a, b NetPolicy) bool {
	if a.Loopback != b.Loopback || a.Private != b.Private || a.DNS != b.DNS || a.Open != b.Open {
		return false
	}
	if len(a.Ports) != len(b.Ports) {
		return false
	}
	for i := range a.Ports {
		if a.Ports[i] != b.Ports[i] {
			return false
		}
	}
	return true
}

// TestEnvGlobEverywhere asserts the **/.env* glob is a real glob applied
// regardless of the workspace being writable (SPEC §5.3): it is present in
// Write mode, where the workspace root is writable, and is kept as a glob
// (not anchored/expanded).
func TestEnvGlobEverywhere(t *testing.T) {
	p := PolicyFor(Write, testWS)
	if !fsHasDeny(p.FS, "**/.env*") {
		t.Fatal("Write mode is missing the **/.env* deny glob")
	}
	// It must remain a glob, not be rewritten under the workspace.
	if fsHasDeny(p.FS, filepath.Join(testWS, "**/.env*")) {
		t.Error("**/.env* was anchored to the workspace; it must stay a bare glob")
	}
}

// TestDefaultSecretDenials asserts the §5.3 preset expands ~ to the caller's
// home and keeps **/.env* as a glob.
func TestDefaultSecretDenials(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}
	got := DefaultSecretDenials()
	if len(got) == 0 {
		t.Fatal("DefaultSecretDenials is empty")
	}
	set := map[string]bool{}
	for _, p := range got {
		set[p] = true
	}
	for _, rel := range []string{".ssh", ".aws", ".gnupg", ".kube", ".config/gh", ".netrc", ".docker/config.json"} {
		want := filepath.Join(home, rel)
		if !set[want] {
			t.Errorf("DefaultSecretDenials missing %s", want)
		}
	}
	if !set["**/.env*"] {
		t.Error("DefaultSecretDenials missing **/.env* glob")
	}
	// The glob must not have been home-expanded.
	if set[filepath.Join(home, "**/.env*")] {
		t.Error("**/.env* was home-expanded; it must stay a bare glob")
	}
}

// TestMetadataDenyCIDRs documents that metadata deny is a backend invariant, not
// a NetPolicy field: the preset is exported and non-empty, and PolicyFor never
// encodes it into NetPolicy (enforcement is asserted in the backend tasks).
func TestMetadataDenyCIDRs(t *testing.T) {
	cidrs := MetadataDenyCIDRs()
	if len(cidrs) == 0 {
		t.Fatal("MetadataDenyCIDRs is empty")
	}
	set := map[string]bool{}
	for _, c := range cidrs {
		set[c] = true
	}
	if !set["169.254.0.0/16"] {
		t.Error("MetadataDenyCIDRs missing 169.254.0.0/16")
	}
	if !set["fd00:ec2::254"] {
		t.Error("MetadataDenyCIDRs missing fd00:ec2::254")
	}
}

// TestMinimalSystemReadPaths asserts the documented minimal set is present.
func TestMinimalSystemReadPaths(t *testing.T) {
	paths := MinimalSystemReadPaths()
	if len(paths) == 0 {
		t.Fatal("MinimalSystemReadPaths is empty")
	}
	set := map[string]bool{}
	for _, p := range paths {
		set[p] = true
	}
	for _, want := range []string{"/usr", "/bin", "/etc", "/dev/null"} {
		if !set[want] {
			t.Errorf("MinimalSystemReadPaths missing %s", want)
		}
	}
}

// TestBaselineEnvAllowlist asserts the §5.5 baseline names are present. This is
// the implicit baseline; it is NOT copied into EnvPolicy.Allow (env assembly is
// a later task).
func TestBaselineEnvAllowlist(t *testing.T) {
	names := BaselineEnvAllowlist()
	set := map[string]bool{}
	for _, n := range names {
		set[n] = true
	}
	for _, want := range []string{"PATH", "HOME", "TERM", "LANG", "LC_*", "USER", "LOGNAME", "SHELL", "TZ"} {
		if !set[want] {
			t.Errorf("BaselineEnvAllowlist missing %s", want)
		}
	}
	// The baseline is not leaked into the expanded policy's EnvPolicy.Allow.
	p := PolicyFor(Write, testWS)
	if len(p.Env.Allow) != 0 {
		t.Errorf("EnvPolicy.Allow = %v, want empty (baseline is implicit, not copied)", p.Env.Allow)
	}
}

// TestPolicyForCanonicalPaths asserts writable roots and their carveouts share
// one canonical path form, so a trailing slash cannot produce divergent keys for
// the (later) Path-keyed FS resolver.
func TestPolicyForCanonicalPaths(t *testing.T) {
	p := PolicyFor(Write, "/work/repo/", WithWritable("/data/"))
	if p.Workspace != "/work/repo" {
		t.Errorf("Workspace = %q, want cleaned /work/repo", p.Workspace)
	}
	// Workspace: canonical writable entry, no trailing-slash variant.
	if acc, ok := fsAccess(p.FS, "/work/repo"); !ok || acc != ReadAccess|WriteAccess|ExecAccess {
		t.Errorf("/work/repo: got (%d,%v), want cleaned writable entry", acc, ok)
	}
	if _, ok := fsAccess(p.FS, "/work/repo/"); ok {
		t.Error("found trailing-slash writable entry /work/repo/; paths must be canonical")
	}
	if acc, ok := fsAccess(p.FS, "/work/repo/.git"); !ok || acc != ReadAccess {
		t.Errorf("/work/repo/.git: got (%d,%v), want ReadAccess carveout", acc, ok)
	}
	// WithWritable root: same canonicalization.
	if _, ok := fsAccess(p.FS, "/data/"); ok {
		t.Error("found trailing-slash writable entry /data/; paths must be canonical")
	}
	if acc, ok := fsAccess(p.FS, "/data"); !ok || acc != ReadAccess|WriteAccess|ExecAccess {
		t.Errorf("/data: got (%d,%v), want cleaned writable entry", acc, ok)
	}
	if acc, ok := fsAccess(p.FS, "/data/.git"); !ok || acc != ReadAccess {
		t.Errorf("/data/.git: got (%d,%v), want ReadAccess carveout", acc, ok)
	}
}

// TestPolicyForOutOfRangeMode asserts an out-of-range Mode fails closed to
// ZeroTrust rather than an all-denied policy with a zero (no-baseline) env.
func TestPolicyForOutOfRangeMode(t *testing.T) {
	bogus := Mode(200)
	got := PolicyFor(bogus, testWS)
	want := PolicyFor(ZeroTrust, testWS)
	if !fsSetEqual(got.FS, want.FS) {
		t.Error("out-of-range mode FS differs from ZeroTrust")
	}
	if got.Env.Set["TMPDIR"] != "/tmp" {
		t.Errorf("out-of-range mode Env.Set[TMPDIR] = %q, want /tmp (baseline env)", got.Env.Set["TMPDIR"])
	}
	if got.Env.Inherit {
		t.Error("out-of-range mode Env.Inherit = true, want false (fail-closed)")
	}
}

// TestPolicyForOptions asserts the functional options compose.
func TestPolicyForOptions(t *testing.T) {
	t.Run("WithWritable", func(t *testing.T) {
		p := PolicyFor(Write, testWS, WithWritable("/data"))
		if acc, ok := fsAccess(p.FS, "/data"); !ok || acc != ReadAccess|WriteAccess|ExecAccess {
			t.Errorf("/data: got (%d,%v), want Read|Write|Exec", acc, ok)
		}
		// A WithWritable root also gets the read-only carveouts.
		if acc, ok := fsAccess(p.FS, "/data/.git"); !ok || acc != ReadAccess {
			t.Errorf("/data/.git: got (%d,%v), want ReadAccess carveout", acc, ok)
		}
		if acc, ok := fsAccess(p.FS, "/data/.looprig"); !ok || acc != ReadAccess {
			t.Errorf("/data/.looprig: got (%d,%v), want ReadAccess carveout", acc, ok)
		}
	})

	t.Run("WithDenyRead", func(t *testing.T) {
		p := PolicyFor(Write, testWS, WithDenyRead("**/*.pem"))
		if !fsHasDeny(p.FS, "**/*.pem") {
			t.Error("WithDenyRead(**/*.pem) not applied")
		}
	})

	t.Run("WithNet", func(t *testing.T) {
		want := NetPolicy{Ports: []uint16{8080}, DNS: true}
		p := PolicyFor(Write, testWS, WithNet(want))
		if !netEqual(p.Net, want) {
			t.Errorf("Net = %+v, want %+v", p.Net, want)
		}
	})

	t.Run("WithNetReplacesWholesale", func(t *testing.T) {
		// Replace, not merge: a zero NetPolicy over Trusted clears everything.
		p := PolicyFor(Trusted, testWS, WithNet(NetPolicy{}))
		if p.Net.Loopback || p.Net.Private || p.Net.DNS || p.Net.Open {
			t.Errorf("Net = %+v, want zero value (replace, not merge)", p.Net)
		}
		if len(p.Net.Ports) != 0 {
			t.Errorf("Net.Ports = %v, want empty (replace, not merge)", p.Net.Ports)
		}
	})

	t.Run("WithEnv", func(t *testing.T) {
		p := PolicyFor(Write, testWS, WithEnv(EnvPolicy{Allow: []string{"GOFLAGS"}, Set: map[string]string{"FOO": "bar"}}))
		found := false
		for _, a := range p.Env.Allow {
			if a == "GOFLAGS" {
				found = true
			}
		}
		if !found {
			t.Error("WithEnv did not merge Allow")
		}
		if p.Env.Set["FOO"] != "bar" {
			t.Error("WithEnv did not merge Set")
		}
		// The mode's TMPDIR must survive the merge.
		if p.Env.Set["TMPDIR"] != "/tmp" {
			t.Errorf("WithEnv clobbered TMPDIR: %q", p.Env.Set["TMPDIR"])
		}
	})

	t.Run("WithEnvTMPDIROverrideWins", func(t *testing.T) {
		// A caller-supplied TMPDIR overrides the mode default.
		p := PolicyFor(Write, testWS, WithEnv(EnvPolicy{Set: map[string]string{"TMPDIR": "/custom"}}))
		if p.Env.Set["TMPDIR"] != "/custom" {
			t.Errorf("Env.Set[TMPDIR] = %q, want /custom (caller override wins)", p.Env.Set["TMPDIR"])
		}
	})

	t.Run("WithLimits", func(t *testing.T) {
		l := Limits{MaxPIDs: 128, MaxMemBytes: 1 << 30}
		p := PolicyFor(Write, testWS, WithLimits(l))
		if p.Limits != l {
			t.Errorf("Limits = %+v, want %+v", p.Limits, l)
		}
	})

	t.Run("WithCarveouts", func(t *testing.T) {
		p := PolicyFor(Write, testWS, WithCarveouts("node_modules"))
		carve := filepath.Join(testWS, "node_modules")
		if acc, ok := fsAccess(p.FS, carve); !ok || acc != ReadAccess {
			t.Errorf("%s: got (%d,%v), want ReadAccess carveout", carve, acc, ok)
		}
	})

	t.Run("WithoutSecretDenials", func(t *testing.T) {
		home, _ := os.UserHomeDir()
		p := PolicyFor(Write, testWS, WithoutSecretDenials())
		if fsHasDeny(p.FS, filepath.Join(home, ".ssh")) {
			t.Error("WithoutSecretDenials left ~/.ssh deny in place")
		}
		if fsHasDeny(p.FS, "**/.env*") {
			t.Error("WithoutSecretDenials left **/.env* deny in place")
		}
	})

	t.Run("WithAckUnconfined", func(t *testing.T) {
		if p := PolicyFor(Unconfined, testWS); p.AckUnconfined {
			t.Error("Unconfined without WithAckUnconfined set AckUnconfined")
		}
		if p := PolicyFor(Unconfined, testWS, WithAckUnconfined()); !p.AckUnconfined {
			t.Error("WithAckUnconfined did not set AckUnconfined")
		}
	})

	t.Run("OrderIndependent", func(t *testing.T) {
		// The relative order of accumulating options must not change the result.
		a := PolicyFor(Write, testWS, WithWritable("/data"), WithCarveouts("node_modules"))
		b := PolicyFor(Write, testWS, WithCarveouts("node_modules"), WithWritable("/data"))
		if !fsSetEqual(a.FS, b.FS) {
			t.Errorf("FS set differs by option order:\n a=%v\n b=%v", a.FS, b.FS)
		}
	})
}

// fsSetEqual compares two FS lists as multisets (order-independent). FSEntry is
// comparable, so it can key a count map directly.
func fsSetEqual(a, b []FSEntry) bool {
	if len(a) != len(b) {
		return false
	}
	counts := map[FSEntry]int{}
	for _, e := range a {
		counts[e]++
	}
	for _, e := range b {
		counts[e]--
		if counts[e] < 0 {
			return false
		}
	}
	return true
}
