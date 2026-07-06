package sandbox

// This file defines the foreign-agent confinement preset (SPEC §10.6).
//
// A foreign agent (e.g. Claude Code) is an OS process the harness foreignloop
// launcher execs as a subprocess. Seatbelt profiles and Linux namespaces are
// inherited by every descendant, so wrapping the foreign process confines
// EVERYTHING it and its own spawned commands do — the honest trust boundary,
// since a foreign agent's internal gates cannot be audited. ForeignAgentPolicy
// is the preset that shapes that confinement: a base mode plus the three deltas
// a foreign agent needs (reach its own LLM API, keep its own credentials, and
// know it is already sandboxed so it does not try to nest one).

// foreignHTTPSPort is the outbound TCP port opened to the foreign agent's LLM
// API. Hostname LLM APIs speak HTTPS, so 443 plus DNS is the minimum egress
// (SPEC §5.2, §10.6).
const foreignHTTPSPort uint16 = 443

// foreignExternalMarkerValue is the truthy value written to
// ForeignDecl.ExternalMarkerEnv. Its presence — not its exact value — is the
// signal; "1" is the conventional truthy marker.
const foreignExternalMarkerValue = "1"

// ForeignDecl declares the facts about a foreign agent that shape its sandbox
// (SPEC §10.6). It carries no policy of its own; ForeignAgentPolicy folds it
// into a base mode.
type ForeignDecl struct {
	// LLMAPIHost is the hostname of the agent's LLM API, e.g. "api.anthropic.com".
	// v1 NetPolicy is port-scoped only (domain allowlists are v2, §5.2), so this
	// is an audit/forward-looking field: the port+DNS egress it justifies is
	// granted by ForeignAgentPolicy, but the host itself is not yet an
	// enforcement input.
	LLMAPIHost string
	// CredEnvVars names the env vars carrying the foreign agent's OWN credentials
	// (e.g. its API key). They are added to the env allowlist so they survive
	// scrubbing — the agent's API key is ITS secret to keep, whereas harness's
	// other tokens stay scrubbed by the baseline allowlist (SPEC §5.5, §10.6).
	CredEnvVars []string
	// ExternalMarkerEnv is the env var name set (to a truthy value) telling the
	// foreign agent it is already externally sandboxed, so it does NOT erect its
	// own nested sandbox: sandbox-exec will not initialize inside an existing
	// Seatbelt profile and userns-in-userns is frequently blocked, so a nested
	// attempt fails (SPEC §10.6). Empty means no marker is set.
	ExternalMarkerEnv string
}

// ForeignAgentPolicy expands a foreign-agent confinement policy: PolicyFor(base,
// workspace, opts...) plus the three §10.6 deltas applied on top, so they hold
// regardless of the base mode or any option:
//
//   - Net gains egress to the agent's LLM API — port 443 and DNS — MERGED into
//     the base net (a broader base's Loopback/Private/other ports survive; 443 is
//     not duplicated).
//   - Env.Allow gains decl.CredEnvVars, so the agent's own credentials pass
//     through while harness's other tokens stay scrubbed by the baseline.
//   - Env.Set gains decl.ExternalMarkerEnv=<truthy>, the external-isolation
//     marker, so the agent does not nest a (failing) sandbox of its own.
//
// Everything else — the base FS + write boundary, the §5.3 secret deny-reads,
// carveouts, env baseline — is inherited unchanged from the base preset.
func ForeignAgentPolicy(base Mode, decl ForeignDecl, workspace string, opts ...PolicyOption) Policy {
	p := PolicyFor(base, workspace, opts...)

	// LLM egress: HTTPS + name resolution, merged (not clobbered) into the base.
	p.Net.DNS = true
	if !containsPort(p.Net.Ports, foreignHTTPSPort) {
		p.Net.Ports = append(p.Net.Ports, foreignHTTPSPort)
	}

	// The agent's own credentials survive scrubbing; harness tokens do not.
	p.Env.Allow = append(p.Env.Allow, decl.CredEnvVars...)

	// Tell the agent it is already sandboxed so it does not nest its own.
	if decl.ExternalMarkerEnv != "" {
		if p.Env.Set == nil {
			p.Env.Set = make(map[string]string, 1)
		}
		p.Env.Set[decl.ExternalMarkerEnv] = foreignExternalMarkerValue
	}

	return p
}
