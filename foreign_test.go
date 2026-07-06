package sandbox

import (
	"os"
	"path/filepath"
	"testing"
)

// containsStr reports whether xs contains s (exact match).
func containsStr(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// countPort returns how many times p appears in ps (used to assert no dupes).
func countPort(ps []uint16, p uint16) int {
	n := 0
	for _, x := range ps {
		if x == p {
			n++
		}
	}
	return n
}

// testForeignDecl is a representative foreign-agent declaration: the agent's LLM
// API host, its own credential env var (which must survive scrubbing), and the
// env marker telling it it is externally sandboxed.
func testForeignDecl() ForeignDecl {
	return ForeignDecl{
		LLMAPIHost:        "api.anthropic.com",
		CredEnvVars:       []string{"ANTHROPIC_API_KEY"},
		ExternalMarkerEnv: "CLAUDE_CODE_EXTERNAL_SANDBOX",
	}
}

// TestForeignAgentPolicyWrite is the core §10.6 table: over a Write base, the
// foreign preset must add LLM egress (443 + DNS), admit the agent's own creds to
// the env allowlist while leaving harness tokens scrubbed, set the external
// marker, and inherit the base FS/write-boundary and secret denials untouched.
func TestForeignAgentPolicyWrite(t *testing.T) {
	t.Parallel()

	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatalf("os.UserHomeDir: %v", err)
	}
	sshDeny := filepath.Join(home, ".ssh")

	decl := testForeignDecl()
	p := ForeignAgentPolicy(Write, decl, testWS)

	// --- Inherited base (Write) FS + write boundary ---
	if p.Workspace != testWS {
		t.Errorf("Workspace = %q, want %q", p.Workspace, testWS)
	}
	if acc, ok := fsAccess(p.FS, "/"); !ok || acc != ReadAccess|ExecAccess {
		t.Errorf("broad read: got (%d,%v), want / => Read|Exec (inherited from Write)", acc, ok)
	}
	if acc, ok := fsAccess(p.FS, testWS); !ok || acc != ReadAccess|WriteAccess|ExecAccess {
		t.Errorf("workspace access = (%d,%v), want Read|Write|Exec (Write write-boundary)", acc, ok)
	}
	if acc, ok := fsAccess(p.FS, "/tmp"); !ok || acc != ReadAccess|WriteAccess|ExecAccess {
		t.Errorf("/tmp access = (%d,%v), want Read|Write|Exec (inherited from Write)", acc, ok)
	}
	// Carveout inherited: ws/.git re-masked read-only.
	if acc, ok := fsAccess(p.FS, filepath.Join(testWS, ".git")); !ok || acc != ReadAccess {
		t.Errorf("ws/.git carveout = (%d,%v), want ReadAccess (inherited)", acc, ok)
	}

	// --- §5.3 secret denials still present ---
	if !fsHasDeny(p.FS, sshDeny) {
		t.Errorf("secret deny %s missing; §5.3 denials must be inherited", sshDeny)
	}

	// --- LLM egress: HTTPS + DNS, merged into base net ---
	if !p.Net.DNS {
		t.Error("Net.DNS = false, want true (hostname LLM APIs need resolution, §5.2)")
	}
	if !containsPort(p.Net.Ports, 443) {
		t.Errorf("Net.Ports = %v, want to contain 443 (LLM API HTTPS)", p.Net.Ports)
	}
	// Write base has an empty net, so the ONLY port granted must be 443 — no
	// accidental widening beyond the LLM API.
	if len(p.Net.Ports) != 1 {
		t.Errorf("Net.Ports = %v, want exactly {443} over a Write base", p.Net.Ports)
	}

	// --- Env allowlist: agent creds pass through, harness tokens do not ---
	for _, cred := range decl.CredEnvVars {
		if !containsStr(p.Env.Allow, cred) {
			t.Errorf("Env.Allow = %v, want to contain agent cred %q", p.Env.Allow, cred)
		}
	}
	if containsStr(p.Env.Allow, "GITHUB_TOKEN") {
		t.Error("GITHUB_TOKEN must NOT be in Env.Allow (a harness token stays scrubbed)")
	}
	if containsStr(BaselineEnvAllowlist(), "GITHUB_TOKEN") {
		t.Error("precondition: GITHUB_TOKEN must not be in the baseline allowlist either")
	}

	// --- External-isolation marker set on the child env ---
	if got, ok := p.Env.Set[decl.ExternalMarkerEnv]; !ok || got == "" {
		t.Errorf("Env.Set[%q] = (%q,%v), want a truthy value (external-sandbox marker)", decl.ExternalMarkerEnv, got, ok)
	}
	// TMPDIR from the base env survives the merge.
	if p.Env.Set["TMPDIR"] != "/tmp" {
		t.Errorf("Env.Set[TMPDIR] = %q, want /tmp (base env preserved)", p.Env.Set["TMPDIR"])
	}
	if p.Env.Inherit {
		t.Error("Env.Inherit = true, want false (foreign preset must not inherit the harness env)")
	}
}

// TestForeignAgentPolicyNetMerge asserts the net extension merges with — never
// clobbers — a broader base. Over a Trusted base (Loopback+Private+443+DNS), the
// address-scoped grants survive and 443 is not duplicated.
func TestForeignAgentPolicyNetMerge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		base         Mode
		wantLoopback bool
		wantPrivate  bool
	}{
		{name: "write base has no address grants", base: Write},
		{name: "trusted base keeps address grants", base: Trusted, wantLoopback: true, wantPrivate: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := ForeignAgentPolicy(tt.base, testForeignDecl(), testWS)

			if !p.Net.DNS {
				t.Error("Net.DNS = false, want true")
			}
			if !containsPort(p.Net.Ports, 443) {
				t.Errorf("Net.Ports = %v, want to contain 443", p.Net.Ports)
			}
			if n := countPort(p.Net.Ports, 443); n != 1 {
				t.Errorf("Net.Ports contains 443 %d times, want exactly 1 (no dupe over a base that already grants it)", n)
			}
			if p.Net.Loopback != tt.wantLoopback {
				t.Errorf("Net.Loopback = %v, want %v (base must not be clobbered)", p.Net.Loopback, tt.wantLoopback)
			}
			if p.Net.Private != tt.wantPrivate {
				t.Errorf("Net.Private = %v, want %v (base must not be clobbered)", p.Net.Private, tt.wantPrivate)
			}
		})
	}
}

// TestForeignAgentPolicyEdgeDecls covers empty declaration fields: an empty
// marker must not inject a Set[""] entry, and empty creds must leave the
// allowlist as just the base (no phantom empty allow entry).
func TestForeignAgentPolicyEdgeDecls(t *testing.T) {
	t.Parallel()

	t.Run("empty marker does not inject a blank Set key", func(t *testing.T) {
		t.Parallel()
		decl := ForeignDecl{CredEnvVars: []string{"ANTHROPIC_API_KEY"}}
		p := ForeignAgentPolicy(Write, decl, testWS)
		if _, ok := p.Env.Set[""]; ok {
			t.Error(`Env.Set[""] set; an empty ExternalMarkerEnv must inject nothing`)
		}
	})

	t.Run("empty creds leave no blank allow entry", func(t *testing.T) {
		t.Parallel()
		decl := ForeignDecl{ExternalMarkerEnv: "MARK"}
		p := ForeignAgentPolicy(Write, decl, testWS)
		if containsStr(p.Env.Allow, "") {
			t.Error(`Env.Allow contains ""; empty CredEnvVars must add nothing`)
		}
		if got, ok := p.Env.Set["MARK"]; !ok || got == "" {
			t.Errorf("Env.Set[MARK] = (%q,%v), want truthy", got, ok)
		}
	})
}

// TestForeignAgentPolicyThreadsOptions confirms PolicyOptions still flow through
// (ForeignAgentPolicy == PolicyFor + foreign deltas): a WithWritable root lands
// in the FS, and the foreign deltas apply on top.
func TestForeignAgentPolicyThreadsOptions(t *testing.T) {
	t.Parallel()

	extra := "/work/extra"
	p := ForeignAgentPolicy(Write, testForeignDecl(), testWS, WithWritable(extra))

	if acc, ok := fsAccess(p.FS, extra); !ok || acc != ReadAccess|WriteAccess|ExecAccess {
		t.Errorf("extra writable = (%d,%v), want Read|Write|Exec (option threaded through)", acc, ok)
	}
	if !containsPort(p.Net.Ports, 443) || !p.Net.DNS {
		t.Errorf("foreign net deltas missing with options present: Ports=%v DNS=%v", p.Net.Ports, p.Net.DNS)
	}
}
