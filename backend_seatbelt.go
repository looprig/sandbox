//go:build darwin

package sandbox

import (
	"path/filepath"
	"strconv"
	"strings"
)

// This file is the darwin Seatbelt backend (SPEC §7.1): it compiles a Policy
// into an SBPL profile string and wraps every spawn with
// `/usr/bin/sandbox-exec -p <profile> -- ...`. The network syntax is taken
// verbatim from the Task M1 spike (docs/spikes/seatbelt-net.md), which
// empirically verified what SBPL can and cannot express. This backend is selected
// on darwin by platformBackend() (platform_darwin.go); its file-rule enforcement
// is verified end-to-end against a real sandbox-exec (backend_seatbelt_test.go).

// baseSandboxPreamble is the minimal always-on base of every generated profile
// (SPEC §7.1). A bare `(deny default)` is fail-closed to the point of blocking
// even execvp, the dyld loader, and mach bootstrap, so nothing runs at all — the
// Task M1 spike (docs/spikes/seatbelt-net.md) confirmed `/usr/bin/true` fails
// under a bare deny-default and runs only once these allows are present. The set
// lets the target process fork, exec, load its dynamic libraries/dyld, read the
// system page size (sysctl), and reach the mach bootstrap namespace.
//
// It grants NO file writes and NO network, so it does not weaken the write or
// network boundaries; and because SBPL is last-match-wins, the §5.3 secret
// deny-reads emitted at the end of the filesystem section still override the
// broad `(allow file-read*)` here.
//
// HONEST LIMITATION (to be tightened by the real-exec follow-up): the
// file-read*/process-exec* allows here are intentionally BROAD. M1 verified this
// broad set works (including reaching the Apple-Silicon dyld shared cache, whose
// exact path — e.g. under /System/Volumes/Preboot/Cryptexes/OS — is awkward to
// enumerate); a tighter dyld/dylib read set could not be verified without a real
// exec, and the task's guidance is to err toward the M1-proven set. The
// consequence is that zerotrust restricted-read and per-entry exec-scoping are
// not enforced by this preamble — but the write boundary, network boundary, and
// secret deny-reads all remain intact (they never depend on withholding these
// broad reads/execs). None of these are guarantee bits this backend claims.
const baseSandboxPreamble = `(version 1)
(deny default)
(allow process-fork)
(allow process-exec*)
(allow file-read*)
(allow sysctl-read)
(allow mach-lookup)
`

// mDNSResponderSocket is the unix-domain socket macOS getaddrinfo hands DNS
// queries to (the unsandboxed mDNSResponder daemon does the actual :53 traffic).
// M1 verified this — not outbound :53 — is the load-bearing DNS rule (§5.2).
const mDNSResponderSocket = "/private/var/run/mDNSResponder"

// compileSBPL generates the SBPL profile for a policy and returns it alongside
// the compilation report, the achieved isolation level, and the guarantee
// bitmask. It performs symlink resolution on emitted filesystem paths (canonPath,
// an OS read) so rules match the kernel's resolved view (§7.1); output is
// deterministic given a fixed workspace and HOME on a host where the named
// non-/private roots (/ws, /lrsbx-home/tester) do not exist while /tmp,/etc resolve
// macOS-invariantly.
//
// The filesystem section relies on SBPL's last-match-wins precedence to realize
// the resolver's deny>write>read + carveout semantics (§5.1, fsresolve.go). It
// emits, in order: (1) the per-entry read/exec/write ALLOWS; (2) carveout write
// DENIES for read-only entries nested in a writable root (e.g. .git under the
// workspace), placed after the write allow so the deny wins; (3) the §5.3 secret
// DENIES last so they override everything above.
//
// Verification scope: the M1 spike (docs/spikes/seatbelt-net.md) verified the
// NETWORK section and the base preamble against a real sandbox-exec; the file-rule
// syntax — (subpath "…"), (regex #"…"), and file-rule deny-override under
// last-match-wins — is verified end-to-end by the real-sandbox-exec enforcement
// tests in backend_seatbelt_test.go (the goldens alone only prove byte-equality to
// the Go/RE2 glob translation, not that SBPL's engine enforces it identically).
func compileSBPL(p Policy) (profile string, report CompileReport, level uint8, guaranteeBits uint64) {
	var b strings.Builder
	b.WriteString(baseSandboxPreamble)

	compileFS(&b, &report, p.FS)
	compileNet(&b, &report, p.Net)

	level = LevelFull

	// Soundness (§7.5): the base preamble unconditionally broad-allows
	// file-read*/process-exec* so the target can even start (dyld, exec, and the
	// mach bootstrap need broad reads on macOS). For a policy that itself grants
	// broad root read/exec (write/readonly/trusted/unconfined all carry
	// {"/":Read|Exec}) the preamble matches intent — nothing is wider than policy.
	// But a restricted-read policy (zerotrust grants read/exec only to
	// MinimalSystemReadPaths + workspace, with no "/" entry) is compiled STRICTLY
	// WIDER than intended: the command can read/exec almost the whole disk. §7.5
	// forbids that from passing silently — it must be recorded AND demote Level(),
	// so such a policy cannot clear a default LevelFull auto-approve gate. Detect
	// it by asking the resolver what the policy actually grants at "/".
	//
	// This point-samples access AT "/" — sound for every current preset because a
	// literal "/" read entry grants recursively, so root access implies the whole
	// tree. A future non-recursive root-read option (e.g. a "/*" glob that reads
	// as Full at "/" yet grants only the top level) would leave the preamble
	// wider than a "/"-only sample can detect; revisit this probe if such an
	// option is added.
	rootAccess := Resolve(p.FS, "/")
	if rootAccess&ReadAccess == 0 {
		report.Entries = append(report.Entries, ReportEntry{
			Feature: "restricted-read",
			Status:  "unenforced",
			Detail:  "base preamble broad-allows file-read* (dyld/exec needs broad reads on macOS); per-policy read restriction not enforced — tighten via scoped system-lib reads in a later iteration",
		})
		level = LevelDegraded
	}
	if rootAccess&ExecAccess == 0 {
		report.Entries = append(report.Entries, ReportEntry{
			Feature: "exec-scoping",
			Status:  "unenforced",
			Detail:  "base preamble broad-allows process-exec* (dyld/exec needs broad reads on macOS); per-policy exec restriction not enforced — tighten via scoped system-lib reads in a later iteration",
		})
		level = LevelDegraded
	}

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
// narrowing to report. See compileSBPL for the three-phase last-match-wins order.
func compileFS(b *strings.Builder, report *CompileReport, fs []FSEntry) {
	b.WriteString("; --- filesystem ---\n")

	// Writable roots: the entries that grant write, used to detect which
	// read-only entries are carveouts nested inside them.
	var writableRoots []FSEntry
	for _, e := range fs {
		if e.Access != DenyAccess && e.Access&WriteAccess != 0 {
			writableRoots = append(writableRoots, e)
		}
	}

	// Phase 1: per-entry allows (read, exec, write) for every allow entry. Paths are
	// canonicalized (canonPath) so a rule matches the symlink-resolved path Seatbelt
	// evaluates against — on macOS /tmp→/private/tmp, /var/folders→/private/... etc.
	for _, e := range fs {
		if e.Access == DenyAccess {
			continue
		}
		path := sbplString(canonPath(e.Path))
		if e.Access&ReadAccess != 0 {
			b.WriteString(`(allow file-read* (subpath "` + path + `"))` + "\n")
		}
		if e.Access&ExecAccess != 0 {
			b.WriteString(`(allow process-exec* (subpath "` + path + `"))` + "\n")
		}
		if e.Access&WriteAccess != 0 {
			b.WriteString(`(allow file-write* (subpath "` + path + `"))` + "\n")
		}
	}

	// Phase 2: carveout write-denies. A read-only entry nested inside a writable
	// root would otherwise inherit that root's write allow; emitting the deny
	// AFTER the allow removes write under last-match-wins (§5.1 carveout).
	for _, e := range fs {
		if e.Access == DenyAccess || e.Access&WriteAccess != 0 {
			continue
		}
		if underWritableRoot(e.Path, writableRoots) {
			b.WriteString(`(deny file-write* (subpath "` + sbplString(canonPath(e.Path)) + `"))` + "\n")
		}
	}

	// Phase 3: secret / deny-entry denies LAST so they win over every allow
	// above. Fixed paths use (subpath ...); globs are translated to a regex. Two
	// fail-closed fallbacks widen to a conservative subpath deny rather than emit
	// a bad rule: (a) an untranslatable glob (does not compile), and (b) a glob
	// whose translated regex would contain a double-quote — which an SBPL #"..."
	// literal cannot represent (it would unbalance the delimiters), reachable via
	// a consumer WithDenyRead of a quote-bearing path. Both over-deny, never skip.
	//
	// NOTE: unlike the network rules, the (regex #"...") and (subpath "...") FILE
	// forms and file-rule deny-override are NOT part of the M1 spike — only
	// byte-equality to Go's RE2 translation is proven here. SBPL's (older,
	// different) regex engine matching identically is pending real-exec
	// verification (Task 8b).
	for _, e := range fs {
		if e.Access != DenyAccess {
			continue
		}
		if strings.ContainsAny(e.Path, globMeta) {
			// The regex form legitimately needs its backslashes (e.g. \.env), so
			// it must NOT go through sbplString; only the un-representable quote
			// case falls back. NOTE (canonPath limitation): a glob's literal prefix
			// is NOT symlink-resolved here, so a WithDenyRead glob whose fixed prefix
			// sits under a symlinked root would under-match. DefaultSecretDenials'
			// only glob (**/.env*) is suffix-anchored (no literal prefix), so this
			// does not affect the secure defaults.
			reSrc := globToRegexp(e.Path)
			reCompiles := globRegexp(e.Path) != nil
			if reCompiles && !strings.Contains(reSrc, `"`) {
				b.WriteString(`(deny file-read* file-write* (regex #"` + reSrc + `"))` + "\n")
				continue
			}
			broad := conservativeDenyRoot(e.Path)
			b.WriteString(`(deny file-read* file-write* (subpath "` + sbplString(canonPath(broad)) + `"))` + "\n")
			detail := "untranslatable deny glob " + e.Path + " compiled to a broad conservative deny of " + broad + " (fail closed, over-deny)"
			if reCompiles { // translated fine, but the regex would contain a quote
				detail = `deny glob contains a quote unrepresentable in an SBPL #"..." regex; widened to a conservative subpath deny`
			}
			report.Entries = append(report.Entries, ReportEntry{
				Feature: "glob-deny",
				Status:  "narrowed",
				Detail:  detail,
			})
		} else {
			b.WriteString(`(deny file-read* file-write* (subpath "` + sbplString(canonPath(e.Path)) + `"))` + "\n")
		}
	}
}

// compileNet writes the network section (SPEC §5.2, §7.1) into b using the
// M1-verified syntax, appending unenforced/narrowed features to report. The base
// preamble does not allow network, so default-deny holds unless rules are added.
func compileNet(b *strings.Builder, report *CompileReport, net NetPolicy) {
	b.WriteString("; --- network ---\n")

	if net.Open {
		// Unconfined only. Everything else stays default-deny.
		b.WriteString("(allow network*)\n")
		return
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
		if containsPort(net.Ports, 80) {
			entry.Status = "unenforced"
			entry.Detail = "SBPL cannot express an IP deny and :80 IS in the allowed port set; cloud metadata is reachable and cannot be carved out"
		}
		report.Entries = append(report.Entries, entry)
	}
}

// compileGuarantees derives the seam-facing guarantee bitmask from what the
// Seatbelt profile actually enforces for this policy. Each bit is fail-closed:
// set only when genuinely enforced (SPEC §6, §10.3, §7.5 soundness).
func compileGuarantees(p Policy) uint64 {
	var bits uint64

	// sandbox-exec always wraps the spawn in an isolating boundary.
	bits |= GuaranteeProcessBoundary

	// Writes are confined to policy-writable roots unless the policy itself grants
	// write at "/" (unconfined full access), in which case nothing is confined and
	// the claim would be dishonest. Probed with the SAME resolver the level
	// demotion uses (one consistent probe), which also catches a "/"-matching
	// write glob that a literal-"/" scan would miss.
	if Resolve(p.FS, "/")&WriteAccess == 0 {
		bits |= GuaranteeWriteBoundary
	}

	// SBPL expresses the §5.3 secret deny-reads natively (emitted last, so they
	// win over the broad base read). Enforced whenever the policy carries deny
	// entries; a policy with none (unconfined) enforces nothing to claim.
	if hasDenyEntry(p.FS) {
		bits |= GuaranteeReadDenies
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

	// AddressNetwork is FALSE always on macOS: SBPL cannot address-scope (§5.2,
	// M1). ResourceLimits is false: the darwin ulimit approximation is a later
	// task. Neither bit is ever set here.
	return bits
}

// underWritableRoot reports whether path is nested strictly inside one of the
// writable-root entries, i.e. it is a carveout that must have write removed.
func underWritableRoot(path string, writableRoots []FSEntry) bool {
	for _, w := range writableRoots {
		if w.Path != path && literalMatches(w.Path, path) {
			return true
		}
	}
	return false
}

// hasDenyEntry reports whether the policy carries any deny entry.
func hasDenyEntry(fs []FSEntry) bool {
	for _, e := range fs {
		if e.Access == DenyAccess {
			return true
		}
	}
	return false
}

// conservativeDenyRoot returns the broadest safe subpath to deny for an
// untranslatable glob: its literal prefix (the substring before the first glob
// metacharacter), or "/" when there is no usable absolute prefix. Denying a
// too-broad path is the fail-closed direction — it over-denies rather than
// leaking the secret the glob was meant to hide.
func conservativeDenyRoot(glob string) string {
	prefix := glob
	if i := strings.IndexAny(glob, globMeta); i >= 0 {
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
// the spawnSpec closures.
type seatbeltBackend struct{}

// newSeatbeltBackend returns the stateless Seatbelt backend.
func newSeatbeltBackend() backend { return seatbeltBackend{} }

// compile generates the SBPL profile for the policy and returns a spawnSpec that
// wraps every command/argv with `sandbox-exec -p <profile> -- ...`, plus the
// achieved level, guarantee bits, and compilation report.
//
// The profile is passed inline via -p, which is M1-verified and fine for the
// profiles this generator produces. A very large profile could exceed ARG_MAX;
// the future fallback is the temp-file `-f <path>` form of sandbox-exec, but the
// inline form keeps the transform stateless (no temp file to create or clean up)
// and is sufficient here.
func (seatbeltBackend) compile(p Policy) (spawnSpec, CompileReport, uint8, uint64, error) {
	profile, report, level, bits := compileSBPL(p)
	spec := spawnSpec{
		wrapShell: func(command string) []string {
			return []string{"/usr/bin/sandbox-exec", "-p", profile, "--", "/bin/sh", "-c", command}
		},
		wrapArgv: func(argv []string) []string {
			wrapped := make([]string, 0, 4+len(argv))
			wrapped = append(wrapped, "/usr/bin/sandbox-exec", "-p", profile, "--")
			return append(wrapped, argv...)
		},
		configure: nil,
	}
	return spec, report, level, bits, nil
}
