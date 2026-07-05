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
// empirically verified what SBPL can and cannot express. This file only
// GENERATES and wraps; it does not select the backend — platformBackend() still
// returns the null backend, and wiring the darwin selection (plus real
// sandbox-exec enforcement tests) is a separate follow-up.

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
// bitmask. It is pure: it reasons only over the policy and emits text, making no
// OS calls, so its output is deterministic given a fixed workspace and HOME.
//
// The filesystem section relies on SBPL's last-match-wins precedence to realize
// the resolver's deny>write>read + carveout semantics (§5.1, fsresolve.go). It
// emits, in order: (1) the per-entry read/exec/write ALLOWS; (2) carveout write
// DENIES for read-only entries nested in a writable root (e.g. .git under the
// workspace), placed after the write allow so the deny wins; (3) the §5.3 secret
// DENIES last so they override everything above.
func compileSBPL(p Policy) (profile string, report CompileReport, level uint8, guaranteeBits uint64) {
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

	// Phase 1: per-entry allows (read, exec, write) for every allow entry.
	for _, e := range fs {
		if e.Access == DenyAccess {
			continue
		}
		path := sbplString(e.Path)
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
			b.WriteString(`(deny file-write* (subpath "` + sbplString(e.Path) + `"))` + "\n")
		}
	}

	// Phase 3: secret / deny-entry denies LAST so they win over every allow
	// above. Fixed paths use (subpath ...); globs are translated to an SBPL
	// regex; an untranslatable glob fails closed to a broad conservative deny.
	for _, e := range fs {
		if e.Access != DenyAccess {
			continue
		}
		if strings.ContainsAny(e.Path, globMeta) {
			if globRegexp(e.Path) != nil {
				b.WriteString(`(deny file-read* file-write* (regex #"` + globToRegexp(e.Path) + `"))` + "\n")
			} else {
				// Untranslatable glob: over-deny rather than skip (fail closed).
				broad := conservativeDenyRoot(e.Path)
				b.WriteString(`(deny file-read* file-write* (subpath "` + sbplString(broad) + `"))` + "\n")
				report.Entries = append(report.Entries, ReportEntry{
					Feature: "glob-deny",
					Status:  "narrowed",
					Detail:  "untranslatable deny glob " + e.Path + " compiled to a broad conservative deny of " + broad + " (fail closed, over-deny)",
				})
			}
		} else {
			b.WriteString(`(deny file-read* file-write* (subpath "` + sbplString(e.Path) + `"))` + "\n")
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

	grantedEgress := false
	for _, port := range net.Ports {
		b.WriteString(`(allow network-outbound (remote tcp "*:` + strconv.Itoa(int(port)) + `"))` + "\n")
		grantedEgress = true
	}
	if net.Loopback {
		b.WriteString(`(allow network-outbound (remote ip "localhost:*"))` + "\n")
		grantedEgress = true
		report.Entries = append(report.Entries, ReportEntry{
			Feature: "loopback",
			Status:  "narrowed",
			Detail:  "SBPL 'localhost' matches all of this host's own addresses (loopback plus its own interface IPs) — wider than 127.0.0.0/8 — but never reaches a remote host",
		})
	}
	if net.DNS {
		b.WriteString(`(allow network-outbound (remote unix-socket (path-literal "` + sbplString(mDNSResponderSocket) + `")))` + "\n")
		grantedEgress = true
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
	if grantedEgress {
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

	// Writes are confined to policy-writable roots unless the policy itself
	// grants write to "/" (unconfined full access), in which case nothing is
	// confined and the claim would be dishonest.
	if !grantsRootWrite(p.FS) {
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

// grantsRootWrite reports whether any allow entry grants write to "/", meaning
// writes are not confined at all (unconfined full access).
func grantsRootWrite(fs []FSEntry) bool {
	for _, e := range fs {
		if e.Access != DenyAccess && e.Access&WriteAccess != 0 && filepath.Clean(e.Path) == "/" {
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

// containsPort reports whether ports contains p.
func containsPort(ports []uint16, p uint16) bool {
	for _, x := range ports {
		if x == p {
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

// sbplString escapes a Go string for inclusion inside an SBPL double-quoted
// literal: backslash and double-quote are the only characters that need
// escaping. Absolute paths with spaces are valid inside the quotes unescaped.
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
