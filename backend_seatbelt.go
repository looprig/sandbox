//go:build darwin

package sandbox

import (
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// This file is the darwin Seatbelt backend (SPEC §7.1): it compiles a policy.Effective
// into an SBPL profile string and wraps every spawn with
// `/usr/bin/sandbox-exec -p <profile> -- ...`. The network syntax is taken
// verbatim from the Task M1 spike (docs/spikes/seatbelt-net.md), which
// empirically verified what SBPL can and cannot express. This backend is selected
// on darwin by platformBackend() (platform_darwin.go); its file-rule enforcement
// is verified end-to-end against a real sandbox-exec (backend_seatbelt_test.go).

// baseSandboxPreamble is the minimal tested startup closure for every generated
// profile. It grants no file writes, remote network, or unfiltered execution.
// Native regression tests prove that dyld needs file-read-data on the literal
// root directory even when every runtime tree is readable; this permits only
// that directory object, not arbitrary descendants. /private/var/select is the
// system shell-selector read used when sandbox-exec launches /bin/sh. Executable
// and remaining readable paths are emitted per effective-policy entry below.
const baseSandboxPreamble = `(version 1)
(deny default)
(allow process-fork)
(allow process-info*)
(allow sysctl-read)
(allow mach-lookup)
(allow file-read-data (literal "/"))
(allow file-read* (subpath "/private/var/select"))
`

// mDNSResponderSocket is the unix-domain socket macOS getaddrinfo hands DNS
// queries to (the unsandboxed mDNSResponder daemon does the actual :53 traffic).
// M1 verified this — not outbound :53 — is the load-bearing DNS rule (§5.2).
const mDNSResponderSocket = "/private/var/run/mDNSResponder"

// compileSBPL generates the SBPL profile for a policy and returns it alongside
// the compilation report, the achieved isolation level, and the guarantee
// bitmask. It resolves ordinary configured paths so rules match the kernel's
// canonical view, but never re-follows identity-bound grant paths. The
// filesystem section uses SBPL's last-match-wins behavior: rules are emitted
// broad-to-narrow, allows before denies at a true tie, exact paths after trees
// at the same spelling, and fail-closed glob denies last.
//
// Verification scope: the M1 spike (docs/spikes/seatbelt-net.md) verified the
// NETWORK section and the base preamble against a real sandbox-exec; the file-rule
// syntax — (subpath "…"), (regex #"…"), and file-rule deny-override under
// last-match-wins — is verified end-to-end by the real-sandbox-exec enforcement
// tests in backend_seatbelt_test.go (the goldens alone only prove byte-equality to
// the Go/RE2 glob translation, not that SBPL's engine enforces it identically).
func compileSBPL(p policy.Effective) (sbpl string, report CompileReport, level uint8, guaranteeBits uint64) {
	var b strings.Builder
	b.WriteString(baseSandboxPreamble)

	compileFS(&b, &report, p.FS)
	compileNet(&b, &report, p.Net)

	level = LevelFull

	if p.Net.Private {
		// Private requests address-scoped egress, which SBPL cannot express
		// (§5.2, M1): its AddressNetwork guarantee can never be satisfied, so the
		// policy tops out at Degraded even though everything else is enforced.
		level = LevelDegraded
	}

	guaranteeBits = compileGuarantees(p)
	return b.String(), report, level, guaranteeBits
}

// compileFS writes the filesystem section (SPEC §5.1, §7.5) into b, appending any
// narrowing to report. See compileSBPL for the broad-to-narrow last-match-wins order.
func compileFS(b *strings.Builder, report *CompileReport, fs []policy.FSEntry) {
	b.WriteString("; --- filesystem ---\n")
	compileAncestorMetadata(b, fs)

	// Seatbelt is last-match-wins. Emit broad rules before narrow rules and, at
	// one specificity, allows before denies. This realizes the same independent
	// per-axis longest-match model as policy.ResolveFS.
	rules := mergeSeatbeltRules(fs)
	for _, rule := range rules {
		if strings.ContainsAny(rule.Path, policy.GlobMeta) {
			compileSeatbeltGlobRule(b, report, rule)
			continue
		}
		for _, candidate := range seatbeltPathAliases(rule.Path, rule.Canonical) {
			writeSeatbeltPathRule(b, "allow", rule.Access, candidate, rule.Exact)
			writeSeatbeltPathRule(b, "deny", rule.Denied, candidate, rule.Exact)
		}
	}
}

func mergeSeatbeltRules(entries []policy.FSEntry) []policy.FSEntry {
	type ruleKey struct {
		path      string
		exact     bool
		canonical bool
	}
	byPath := make(map[ruleKey]policy.FSEntry, len(entries))
	for _, entry := range entries {
		key := ruleKey{path: entry.Path, exact: entry.Exact, canonical: entry.Canonical}
		merged := byPath[key]
		merged.Path = entry.Path
		merged.Exact = entry.Exact
		merged.Canonical = entry.Canonical
		merged.Access |= entry.Access
		merged.Denied |= policy.NormalizedDenied(entry)
		byPath[key] = merged
	}
	rules := make([]policy.FSEntry, 0, len(byPath))
	for _, rule := range byPath {
		rules = append(rules, rule)
	}
	sort.Slice(rules, func(i, j int) bool {
		leftGlob := strings.ContainsAny(rules[i].Path, policy.GlobMeta) && rules[i].Denied != 0
		rightGlob := strings.ContainsAny(rules[j].Path, policy.GlobMeta) && rules[j].Denied != 0
		if leftGlob != rightGlob {
			return !leftGlob
		}
		left, right := policy.EntryPrecedence(rules[i]), policy.EntryPrecedence(rules[j])
		if left != right {
			return left < right
		}
		return rules[i].Path < rules[j].Path
	})
	return rules
}

func writeSeatbeltPathRule(b *strings.Builder, action string, access policy.FSAccess, path string, exact bool) {
	path = sbplString(path)
	selector := "subpath"
	if exact {
		selector = "literal"
	}
	if access&policy.ReadAccess != 0 {
		b.WriteString(`(` + action + ` file-read* (` + selector + ` "` + path + `"))` + "\n")
	}
	if access&policy.ExecAccess != 0 {
		b.WriteString(`(` + action + ` process-exec (` + selector + ` "` + path + `"))` + "\n")
	}
	if access&policy.WriteAccess != 0 {
		b.WriteString(`(` + action + ` file-write* (` + selector + ` "` + path + `"))` + "\n")
	}
}

func compileSeatbeltGlobRule(b *strings.Builder, report *CompileReport, rule policy.FSEntry) {
	// Glob allows are not part of the effective profile vocabulary; dropping one
	// under-grants. Denies fail closed to a conservative fixed subtree if SBPL
	// cannot represent the translated expression.
	denied := rule.Denied
	if denied == 0 {
		return
	}
	reSrc := policy.GlobToRegexp(rule.Path)
	representable := policy.GlobRegexp(rule.Path) != nil
	if representable && !strings.Contains(reSrc, `"`) {
		if denied&policy.ReadAccess != 0 {
			b.WriteString(`(deny file-read* (regex #"` + reSrc + `"))` + "\n")
		}
		if denied&policy.ExecAccess != 0 {
			b.WriteString(`(deny process-exec (regex #"` + reSrc + `"))` + "\n")
		}
		if denied&policy.WriteAccess != 0 {
			b.WriteString(`(deny file-write* (regex #"` + reSrc + `"))` + "\n")
		}
		return
	}
	broad := conservativeDenyRoot(rule.Path)
	for _, candidate := range seatbeltPathAliases(broad, false) {
		writeSeatbeltPathRule(b, "deny", denied, candidate, false)
	}
	detail := "unrepresentable deny glob widened to a conservative subtree deny"
	if representable && strings.Contains(reSrc, `"`) {
		detail = "deny glob contains a quote and was widened to a conservative subtree deny"
	}
	report.Entries = append(report.Entries, ReportEntry{
		Feature: "glob-deny", Status: "narrowed",
		Detail: detail,
	})
}

// compileAncestorMetadata permits only metadata lookup on each configured
// allow-root's ancestor chain. Seatbelt requires these lookups to traverse to a
// nested writable/readable root; granting the root itself does not implicitly
// grant lookup on its parents. This deliberately does not allow file data or
// directory enumeration outside configured roots.
func compileAncestorMetadata(b *strings.Builder, fs []policy.FSEntry) {
	seen := map[string]struct{}{string(filepath.Separator): {}}
	for _, entry := range fs {
		if entry.Access == policy.DenyAccess {
			continue
		}
		for _, candidate := range seatbeltPathAliases(entry.Path, entry.Canonical) {
			for parent := filepath.Dir(candidate); parent != string(filepath.Separator); parent = filepath.Dir(parent) {
				if _, ok := seen[parent]; ok {
					continue
				}
				seen[parent] = struct{}{}
				b.WriteString(`(allow file-read-metadata (literal "` + sbplString(parent) + `"))` + "\n")
			}
		}
	}
}

// compileNet writes the network section (SPEC §5.2, §7.1) into b using the
// M1-verified syntax, appending unenforced/narrowed features to report. The base
// preamble does not allow network, so default-deny holds unless rules are added.
func compileNet(b *strings.Builder, report *CompileReport, net policy.NetPolicy) {
	b.WriteString("; --- network ---\n")

	if net.Open {
		// Unconfined only. Everything else stays default-deny.
		b.WriteString("(allow network*)\n")
		return
	}
	if net.ProxyPort != 0 {
		b.WriteString(`(allow network-outbound (remote tcp "localhost:` + strconv.Itoa(int(net.ProxyPort)) + `"))` + "\n")
	}

	for _, port := range net.Ports {
		b.WriteString(`(allow network-outbound (remote tcp "*:` + strconv.Itoa(int(port)) + `"))` + "\n")
	}
	if net.Loopback {
		b.WriteString(`(allow network-outbound (remote ip "localhost:*"))` + "\n")
		report.Entries = append(report.Entries, ReportEntry{
			Feature: "loopback",
			Status:  "narrowed",
			Detail:  "SBPL 'localhost' matches all of this host's own addresses (loopback plus its own interface IPs) — wider than 127.0.0.0/8 — but never reaches a remote host",
		})
	}
	if net.DNS {
		b.WriteString(`(allow network-outbound (remote unix-socket (path-literal "` + sbplString(mDNSResponderSocket) + `")))` + "\n")
	}
	if net.Private {
		// Not expressible in SBPL (host token is * or localhost only); compile to
		// blocked and record it (§5.2, M1).
		report.Entries = append(report.Entries, ReportEntry{
			Feature: "address-network",
			Status:  "unenforced",
			Detail:  "SBPL cannot address-scope; Private compiled to blocked",
		})
	}
	// The metadata note is scoped to actual IP egress: metadata is only reachable
	// over an outbound IP port, so a loopback- or DNS-socket-only policy grants no
	// path to it and needs no note. Only Ports opens that path.
	if len(net.Ports) > 0 {
		// The §5.4 metadata hard-deny cannot be expressed as a positive IP deny;
		// it holds only vacuously when :80 is not in the allowed port set.
		entry := ReportEntry{
			Feature: "metadata-deny",
			Status:  "vacuous",
			Detail:  "SBPL cannot express an IP deny; metadata endpoints are blocked only vacuously because :80 is not in the allowed port set",
		}
		if policy.ContainsPort(net.Ports, 80) {
			entry.Status = "unenforced"
			entry.Detail = "SBPL cannot express an IP deny and :80 IS in the allowed port set; cloud metadata is reachable and cannot be carved out"
		}
		report.Entries = append(report.Entries, entry)
	}
}

// compileGuarantees derives the seam-facing guarantee bitmask from what the
// Seatbelt profile actually enforces for this policy. Each bit is fail-closed:
// set only when genuinely enforced.
func compileGuarantees(p policy.Effective) uint64 {
	var bits uint64

	// sandbox-exec always wraps the spawn in an isolating boundary.
	bits |= GuaranteeProcessBoundary

	// Writes are confined to policy-writable roots unless the policy itself grants
	// write at "/" (unconfined full access), in which case nothing is confined and
	// the claim would be dishonest. Probed with the SAME resolver the level
	// demotion uses (one consistent probe), which also catches a "/"-matching
	// write glob that a literal-"/" scan would miss.
	if policy.IsAccessRestricted(p.FS, policy.WriteAccess) {
		bits |= GuaranteeWriteBoundary
	}

	// Reads are confined whenever the effective policy does not grant broad root
	// read. All process-exec and file-read allows are emitted per configured root.
	if policy.IsAccessRestricted(p.FS, policy.ReadAccess|policy.ExecAccess) {
		bits |= GuaranteeReadBoundary
	}

	// The executor scrubs the child environment unless the policy inherits it
	// (mirrors the null backend's honesty fix).
	if !p.Env.Inherit {
		bits |= GuaranteeEnvScrub
	}

	// Egress is default-deny + port/loopback/DNS allows, i.e. at least
	// port-restricted, unless the policy opens the network entirely.
	if !p.Net.Open {
		bits |= GuaranteeNetworkBoundary
	}
	if p.Net.ProxyPort != 0 && !p.Net.Open {
		bits |= GuaranteeTargetNetwork
	}

	// AddressNetwork is FALSE always on macOS: SBPL cannot address-scope (§5.2,
	// M1). ResourceLimits is false: the darwin ulimit approximation is a later
	// task. Neither bit is ever set here.
	return bits
}

// conservativeDenyRoot returns the broadest safe subpath to deny for an
// untranslatable glob: its literal prefix (the substring before the first glob
// metacharacter), or "/" when there is no usable absolute prefix. Denying a
// too-broad path is the fail-closed direction — it over-denies rather than
// leaking the secret the glob was meant to hide.
func conservativeDenyRoot(glob string) string {
	prefix := glob
	if i := strings.IndexAny(glob, policy.GlobMeta); i >= 0 {
		prefix = glob[:i]
	}
	prefix = filepath.Clean(prefix)
	if prefix == "" || prefix == "." || !filepath.IsAbs(prefix) {
		return "/"
	}
	return prefix
}

// canonPath resolves p through any symlinks so the emitted SBPL rule matches the
// path the kernel presents to the sandbox. Seatbelt evaluates (subpath …) rules
// against the FULLY symlink-resolved access path, and macOS symlinks the very roots
// a policy names — /tmp→/private/tmp, /etc→/private/etc, /var→/private/var (so a
// workspace or temp dir under /var/folders resolves into /private). A rule emitted
// from the raw path would therefore match NOTHING and silently deny in-policy access
// (a raw "/tmp" write grant never fires; a /var-form workspace grant never fires).
//
// EvalSymlinks only resolves an EXISTING path. For a non-existent leaf (a fixed
// test path like /ws or /lrsbx-home/tester, or a not-yet-created carveout/secret target),
// canonPath recurses on the parent — resolving the longest EXISTING ancestor and
// re-attaching the remainder — so a symlinked PREFIX is always resolved even when
// the leaf does not exist yet.
//
// This is critical for DENY rules: the .git/.looprig carveouts and the §5.3 secret
// denies are emitted whether or not those paths exist on disk, and on an ephemeral
// /var/folders workspace they typically do NOT exist at compile time. Leaving such a
// deny raw while its enclosing writable-root ALLOW resolves would let the resolved
// write match the allow but not the raw deny — fail-OPEN — silently defeating the
// carveout/secret protection. (An ALLOW under a symlinked prefix fails CLOSED, which
// is merely annoying; a DENY fails OPEN, which is a security hole — hence the
// asymmetry this resolution closes.)
//
// Residual (TOCTOU): the resolved path is baked into the profile once at compile and
// reused for the executor's whole lifetime, so a path-component symlink swapped
// externally after construction leaves a stale rule — fail-closed for allows,
// fail-open for denies. Inherent to the compile-once, stateless-per-spawn design.
func canonPath(p string) string {
	if p == "" {
		return p // absolute paths only in practice; avoid Clean("") == "."
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		return r
	}
	dir := filepath.Dir(p)
	if dir == p { // reached the root; nothing more to resolve
		return filepath.Clean(p)
	}
	return filepath.Join(canonPath(dir), filepath.Base(p))
}

// seatbeltPathAliases returns the canonical path first and, when macOS exposes
// the caller's symlink spelling to a Seatbelt operation, the cleaned configured
// path second. Current macOS reports some /var/folders operations through the
// raw /var alias even though other operations use /private/var. Emitting both
// spellings confines access to the same configured filesystem object. Deny
// callers use this helper too, so a writable alias cannot bypass a carveout.
func seatbeltPathAliases(p string, alreadyCanonical bool) []string {
	canonical := filepath.Clean(p)
	if !alreadyCanonical {
		canonical = filepath.Clean(canonPath(p))
	}
	raw := filepath.Clean(p)
	aliases := []string{canonical}
	for _, pair := range [][2]string{
		{"/private/var", "/var"},
		{"/private/tmp", "/tmp"},
		{"/private/etc", "/etc"},
	} {
		if canonical == pair[0] || strings.HasPrefix(canonical, pair[0]+string(filepath.Separator)) {
			aliases = append(aliases, pair[1]+strings.TrimPrefix(canonical, pair[0]))
		}
	}
	if raw != canonical {
		aliases = append(aliases, raw)
	}
	return uniqueStrings(aliases)
}

func uniqueStrings(values []string) []string {
	unique := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		unique = append(unique, value)
	}
	return unique
}

// sbplString escapes a Go string for inclusion inside an SBPL (subpath "…") /
// path-literal double-quoted literal: backslash and double-quote are the only
// characters that need escaping, and absolute paths with spaces are valid inside
// the quotes unescaped. It does NOT make a string safe for the (regex #"…")
// branch, which has different needs — its backslashes are meaningful regex
// syntax and a contained double-quote is unrepresentable there (that case falls
// back to a conservative subpath deny in compileFS phase 3, not to sbplString).
func sbplString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// seatbeltBackend is the darwin OS enforcement backend (SPEC §7.1). It is
// stateless: compile builds a fixed SBPL profile per policy and captures it in
// the enforce.Spec closures.
type seatbeltBackend struct{}

// newSeatbeltBackend returns the stateless Seatbelt backend.
func newSeatbeltBackend() enforce.Backend { return seatbeltBackend{} }

// compile generates the SBPL profile for the policy and returns a enforce.Spec that
// wraps every command/argv with `sandbox-exec -p <profile> -- ...`, plus the
// achieved level, guarantee bits, and compilation report.
//
// The profile is passed inline via -p, which is M1-verified and fine for the
// profiles this generator produces. A very large profile could exceed ARG_MAX;
// the future fallback is the temp-file `-f <path>` form of sandbox-exec, but the
// inline form keeps the transform stateless (no temp file to create or clean up)
// and is sufficient here.
func (seatbeltBackend) Compile(p policy.Effective) (enforce.Spec, CompileReport, uint8, uint64, error) {
	sbpl, report, level, bits := compileSBPL(p)
	spec := enforce.Spec{
		// Prepend the sandbox-exec launcher to the inner argv. The executor has
		// already shell-normalized a RunCommand to innerArgv == /bin/sh -c command,
		// so a shell command becomes `sandbox-exec -p <profile> -- /bin/sh -c cmd`
		// and a RunArgv becomes `sandbox-exec -p <profile> -- <argv...>`, identical
		// to the pre-reshape wrapShell/wrapArgv. dir needs no special handling and
		// there are no per-spawn resources, so configure and cleanup are nil.
		Wrap: func(_ string, innerArgv []string) ([]string, func(*exec.Cmd) error, func()) {
			wrapped := make([]string, 0, 4+len(innerArgv))
			wrapped = append(wrapped, "/usr/bin/sandbox-exec", "-p", sbpl, "--")
			wrapped = append(wrapped, innerArgv...)
			return wrapped, nil, nil
		},
	}
	return spec, report, level, bits, nil
}
