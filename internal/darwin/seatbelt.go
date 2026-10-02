//go:build darwin

package darwin

import (
	"github.com/looprig/sandbox/internal/enforce"
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
	"os"
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
//
// mach-lookup is an allowlist of global service names (review H7), not the
// former unfiltered (allow mach-lookup). Bootstrap lookup is how a process
// reaches every launchd-hosted daemon of its user session, and several of
// those act OUTSIDE the sandbox on the caller's behalf: LaunchServices
// (com.apple.coreservices.launchservicesd, com.apple.lsd.*,
// com.apple.CoreServices.coreservicesd) is what `open https://…` uses to
// launch the unsandboxed default browser — defeating Network: Deny — and
// `open -a`/AppleEvents start or drive any application; cfprefsd writes any
// application's preferences; securityd (com.apple.SecurityServer) fronts the
// login keychain; FSEvents reports file activity in trees the profile cannot
// read; distributed notifications reach every app. Each name below was kept
// only because a measured leave-one-out run broke something without it (see
// darwinMachLookupAllowlist), and the reachable-daemon surface is now those
// two identity services plus, on a network-granting profile only, trustd.
//
// process-info* and sysctl-read stay unfiltered, and that is NOT a choice
// that narrowing could fix (review H6), measured with a raw
// sysctl({CTL_KERN, KERN_PROCARGS2, pid}) probe (C and perl) against a
// same-user, non-platform-binary process holding a planted secret in its
// environment: the secret was recovered under (deny default) with NO
// process-info and NO sysctl-read rule at all, under (allow process-info*
// (target self)), under process-info-pidinfo/-listpids-only variants, under
// (deny sysctl-read (sysctl-name "kern.procargs2")) and
// (sysctl-name-regex #"^kern\.procargs") placed after the allow, and under a
// name-prefix allowlist of only hw./vm./machdep. — Seatbelt does not mediate
// KERN_PROCARGS2 at all. (Platform binaries such as /bin/sleep or
// /usr/bin/perl returned argv only, never their environment; an ordinary
// signed-adhoc binary, a Go program for instance, returned all of it.) So a
// confined child CAN read the initial environment of any same-user process
// that is not a platform binary — including the process that embeds this
// module — and compileGuarantees' EnvScrub bit therefore only ever describes
// the child's OWN environment; compileSBPL reports that limit as
// env-scrub/narrowed.
var baseSandboxPreamble = `(version 1)
(deny default)
(allow process-fork)
(allow process-info*)
(allow sysctl-read)
` + darwinMachLookupRule + `(allow file-read-data (literal "/"))
(allow file-read* (subpath "/private/var/select"))
`

// darwinMachLookupAllowlist is the complete set of bootstrap service names
// every profile may look up. It was derived by measurement, not copied: the
// module's whole darwin test corpus (internal/darwin, internal/exec — unit
// and -tags integration — pkg/..., the root facade) was run under
// (allow mach-lookup (with report)) with the sandbox log streamed, which
// observed only libinfo, membership, notification_center, logd and
// diagnosticd; a tool matrix (sh, perl, whoami, ls -l, git init/add/commit,
// git ls-remote https, /usr/bin/python3 with pwd and urllib https, make,
// clang, ssh -V, id -Gn, date, getconf DARWIN_USER_TEMP_DIR, curl http/https,
// a Go net/http HTTPS client) was then run with each candidate removed in
// turn. Kept:
//
//   - com.apple.system.opendirectoryd.libinfo: getpwuid/getgrgid and
//     friends. Without it whoami and ls -l print numeric ids, `id -Gn` loses
//     group names and Python's pwd module raises (breaking expanduser).
//   - com.apple.system.opendirectoryd.membership: uid<->UUID membership.
//     Without it confstr(_CS_DARWIN_USER_TEMP_DIR/_CACHE_DIR) fails, so
//     xcrun-backed /usr/bin shims (git, python3, make, clang) lose their
//     per-user cache directory (compileXcrunCachePlumbing) and every group
//     membership check falls back.
//
// Measured unnecessary and left out: com.apple.system.notification_center,
// com.apple.logd and com.apple.diagnosticd (no tool changed behaviour; a
// confined process's os_log messages are dropped and libinfo answers are not
// cached across calls). Deliberately excluded although a tool may want them,
// each a known compatibility consequence: com.apple.cfprefsd.* (Foundation
// tools read preference plists straight from disk, subject to file rules, and
// cannot write defaults), com.apple.SecurityServer (no keychain access:
// `security find-*` fails), com.apple.SystemConfiguration.configd (no system
// proxy/network-reachability settings; environment-variable proxies, which
// this module sets, are unaffected), com.apple.FSEvents (file watchers fall
// back to polling or fail), com.apple.CoreServices.coreservicesd /
// LaunchServices (`open`, AppleScript `tell application`, and anything
// resolving an app or URL handler fails), com.apple.bsd.dirhelper,
// com.apple.distributed_notifications@Uv3, com.apple.mDNSResponder (DNS uses
// the mDNSResponder unix socket, see compileNet, not this service) and every
// window-server/pasteboard service (pbcopy/pbpaste fail).
//
// com.apple.trustd.agent is NOT here: it is added per profile by
// compileNetMach, only when the profile grants network egress. Certificate
// evaluation through Security.framework needs it — Go's crypto/x509 on
// darwin, URLSession and Swift tooling fail TLS verification without it
// (curl, git-remote-https and Python's ssl verify with their own bundles and
// do not) — but trustd fetches AIA intermediates and revocation data over
// the network itself, unsandboxed, from URLs a crafted certificate names, so
// a network-denied profile must not be able to ask it to.
var darwinMachLookupAllowlist = []string{
	"com.apple.system.opendirectoryd.libinfo",
	"com.apple.system.opendirectoryd.membership",
}

// darwinMachLookupRule renders darwinMachLookupAllowlist as one SBPL rule.
var darwinMachLookupRule = machLookupRule(darwinMachLookupAllowlist)

// darwinNetworkMachLookupAllowlist is added by compileNetMach for a profile
// that grants any network egress; see darwinMachLookupAllowlist.
var darwinNetworkMachLookupAllowlist = []string{"com.apple.trustd.agent"}

func machLookupRule(names []string) string {
	var b strings.Builder
	b.WriteString("(allow mach-lookup")
	for _, name := range names {
		b.WriteString(` (global-name "` + sbplString(name) + `")`)
	}
	b.WriteString(")\n")
	return b.String()
}

// xcrunCacheRegex matches Xcode's `xcrun`/`git` cache file inside the real
// per-user Darwin temp directory (both the canonical /private/var/folders
// spelling and the /var/folders alias a caller's own environment reports).
// Anchored to the "<user-token>/<session-token>/T/" shape so it never widens
// beyond one specific per-user directory tree, and to the "xcrun_db" filename
// prefix so it never widens beyond that one cache file family.
const xcrunCacheRegex = `/var/folders/[^/]+/[^/]+/T/xcrun_db[^/]*$`

// compileXcrunCachePlumbing allow-lists Xcode's per-user xcrun/git tool-path
// cache file. That cache is written to the real, OS-assigned Darwin user temp
// directory resolved via confstr(_CS_DARWIN_USER_TEMP_DIR) -- independent of
// the TMPDIR env var this package sets for the child process (see
// exec.ExecutorSet.For's scratch TMPDIR grant) -- so without this rule every
// git/xcrun-backed command denies that one cache write with a non-fatal but
// noisy "Operation not permitted", even though the command itself still
// succeeds. This is deliberately scoped platform runtime plumbing, not a
// policy.FS entry: glob ALLOWs are not part of the effective-profile
// vocabulary (compileSeatbeltGlobRule handles only glob DENYs), and widening
// this through pol.FS would corrupt the GuaranteeWriteBoundary/ReadBoundary
// accounting for every profile. Other users' per-user temp directories remain
// unreadable (OS-enforced 0700 on the parent), and the filename anchor limits
// exposure to this one tool-path cache, never arbitrary files a caller might
// place in their own temp directory.
func compileXcrunCachePlumbing(b *strings.Builder, report *profile.CompileReport) {
	b.WriteString(`(allow file-read* file-write* (regex #"^/private` + xcrunCacheRegex + `"))` + "\n")
	b.WriteString(`(allow file-read* file-write* (regex #"^` + xcrunCacheRegex + `"))` + "\n")
	report.Entries = append(report.Entries, profile.ReportEntry{
		Feature: "xcrun-cache", Status: "widened",
		Detail: "allow-listed Xcode's per-user xcrun/git tool-path cache file (xcrun_db*) in the real Darwin user temp directory, independent of the profile's own read/write grants",
	})
}

// compileRuntimePlumbingAfterFS re-asserts the preamble's fixed runtime FILE
// allows — the root directory object, the /private/var/select shell selector
// and the xcrun cache file (compileXcrunCachePlumbing) — after the
// filesystem section. A profile with HostRead or HostWrite Deny compiles its
// host root to (deny file-read*/file-write* (subpath "/")), and under SBPL's
// last-match-wins that broad deny silently shadowed every allow the preamble
// made before it: /bin/sh then printed "Error opening /private/var/select/sh:
// Operation not permitted" into every command's output, and the xcrun cache
// rule never took effect for the production default shape. Re-emitting them
// here keeps them exactly as narrow as before (one directory object, one
// system directory, one cache-file pattern); the cost is that a caller's own
// deny of those exact objects cannot remove them either, which is the
// backend-controlled plumbing contract compileXcrunCachePlumbing already
// documents. The preamble keeps its copies so that nothing earlier in the
// profile observes a different closure.
func compileRuntimePlumbingAfterFS(b *strings.Builder) {
	b.WriteString("; --- runtime plumbing (re-asserted after host-root denies) ---\n")
	b.WriteString(`(allow file-read-data (literal "/"))` + "\n")
	b.WriteString(`(allow file-read* (subpath "/private/var/select"))` + "\n")
	b.WriteString(`(allow file-read* file-write* (regex #"^/private` + xcrunCacheRegex + `"))` + "\n")
	b.WriteString(`(allow file-read* file-write* (regex #"^` + xcrunCacheRegex + `"))` + "\n")
}

// mDNSResponderSocket is the unix-domain socket macOS getaddrinfo hands DNS
// queries to (the unsandboxed mDNSResponder daemon does the actual :53 traffic).
// M1 verified this — not outbound :53 — is the load-bearing DNS rule (§5.2).
const mDNSResponderSocket = "/private/var/run/mDNSResponder"

// ptySlaveIoctlRegex matches macOS's PTY slave device family, /dev/ttysNNN
// (devfs — never a /private alias like /tmp, /var, /etc, so no
// seatbeltPathAliases handling is needed here). Anchored to the fixed
// "/dev/ttys" prefix plus one-or-more digits so it never widens beyond that
// one device family — not /dev/ptmx (the PTY *master*, see
// compilePTYSlaveIoctl's own doc comment for why that side needs no rule at
// all), and not any other /dev entry (disks, audio, etc.).
const ptySlaveIoctlRegex = `^/dev/ttys[0-9]+$`

// compilePTYSlaveIoctl allow-lists the ioctl(2) operations a confined
// process needs on its own already-open PTY slave (its controlling
// terminal). Deliberate, user-approved 2026-08-07 scope extension: the
// Darwin best-effort supervised-lifetime plan's own architecture note
// ("access confinement is untouched") predates this — real end-to-end
// exercise of a Seatbelt-confined TTY-backed spawn (only possible once
// PrepareProcess/Start stopped rejecting every Darwin Supervised spawn
// outright) surfaced that `stty size` — and by extension any tool that
// queries/configures its controlling terminal, not just this one command —
// failed inside the sandbox with "TIOCGETD: Operation not permitted", even
// though the identical command already worked unconfined and even though
// plain PTY read/write and isatty()-style checks already worked *confined*.
// That asymmetry is exactly what motivates this rule rather than a broader
// one: this codebase's own child never itself *opens* a device path for its
// stdio — openProcessTerminal (internal/exec/terminal_unix.go) opens both
// halves of the PTY from the UNSANDBOXED parent process (via
// github.com/creack/pty, i.e. /dev/ptmx) and attaches the already-open slave
// fd directly to the child's stdin/stdout/stderr before sandbox-exec ever
// wraps it — so the child's plain read/write (and apparently isatty, which
// this profile already permitted with no rule at all) ride the already-open
// fd and are never subject to Seatbelt's open-time file-read*/file-write*
// checks at all. ioctl(2) is different: Seatbelt intercepts it per-call,
// keyed by the fd's underlying path, regardless of when the fd was opened —
// hence a real, previously-undiscovered gap once a TTY-backed spawn actually
// ran under real confinement for the first time (Task 6 of the darwin
// best-effort-lifetime plan; darwin's PTY path failed closed, pre-spawn,
// before that).
//
// This is unconditional (called for every compiled profile, not gated
// behind any policy.Effective flag) for the same structural reason
// compileXcrunCachePlumbing is: compileSBPL runs exactly once, at executor
// construction (see (*Executor) construction in internal/exec/executor.go),
// strictly before any later PrepareProcess call ever requests TTY: true and
// therefore strictly before any PTY device — let alone its concrete
// /dev/ttysNNN path — exists to name literally. A profile that never spawns
// a TTY-backed process simply never exercises this rule.
//
// The regex, not the (extension "com.apple.sandbox.pty") predicate Apple's
// own shipped application.sb pairs with an equivalent (regex
// "^/dev/ttys[0-9]*") file-read*/file-write* rule (grep
// /System/Library/Sandbox/Profiles/application.sb): that extension token is
// privately issued (com.apple.sandbox.pty is an Apple-internal sandbox
// extension class) and unavailable to an unsigned, unentitled sandbox-exec
// process like this one — this codebase cannot request or hold it. Empirical
// verification (throwaway sandbox-exec probes against a real PTY slave and
// this package's own real Compile output, not committed — mirroring the M1
// spike's own empirical-SBPL-verification method): a plain, un-extension-
// gated (allow file-ioctl (regex ...)) is syntactically valid under
// unentitled sandbox-exec and is BOTH necessary (the denial reproduces
// without it) AND sufficient (stty size succeeds end-to-end, including
// reporting a real resized "30 120" through a genuinely resized PTY, with
// it) — matching this file's own file-ioctl idiom elsewhere on this host
// (e.g. /System/Library/Sandbox/Profiles/com.apple.diskimagesiod.sb's
// (allow file-ioctl (regex #"/dev/r?disk.*")), also path-scoped with no
// per-ioctl-command predicate).
//
// What this explicitly does NOT widen: no file-read*/file-write* grant
// beyond what already worked (a disjoint SBPL operation category from
// file-ioctl); no ioctl grant on /dev/ptmx or any device other than the
// /dev/ttysNNN family (the child never opens ptmx itself, see above); no
// change to any non-PTY spawn (dead rule for a profile whose executor is
// never asked for TTY: true); no change to compileGuarantees' bitmask
// (ReadBoundary/WriteBoundary accounting inspects policy.FS access only,
// never this operation category).
func compilePTYSlaveIoctl(b *strings.Builder, report *profile.CompileReport) {
	b.WriteString(`(allow file-ioctl (regex #"` + ptySlaveIoctlRegex + `"))` + "\n")
	report.Entries = append(report.Entries, profile.ReportEntry{
		Feature: "pty-slave-ioctl", Status: "widened",
		Detail: "allow-listed ioctl(2) on the /dev/ttysNNN PTY-slave device family so a confined TTY-backed spawn's controlling-terminal tools (e.g. stty) work; scoped to that one device family, no broader file-read/write grant, no non-PTY-spawn effect",
	})
}

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
func compileSBPL(p policy.Effective) (sbpl string, report profile.CompileReport, level uint8, guaranteeBits uint64) {
	var b strings.Builder
	b.WriteString(baseSandboxPreamble)
	compileXcrunCachePlumbing(&b, &report)
	compilePTYSlaveIoctl(&b, &report)

	compileFS(&b, &report, p.FS)
	compileRuntimePlumbingAfterFS(&b)
	compileNet(&b, &report, p.Net)
	unixSocketsDangerous := compileUnixSockets(&b, &report, p)

	level = profile.LevelFull

	if p.Net.Private {
		// Private requests address-scoped egress, which SBPL cannot express
		// (§5.2, M1): its AddressNetwork guarantee can never be satisfied, so the
		// policy tops out at Degraded even though everything else is enforced.
		level = profile.LevelDegraded
	}
	if unixSocketsDangerous {
		// A granted same-user broker socket makes the process boundary a
		// statement about that daemon, not about Seatbelt (see
		// compileUnixSockets): ProcessBoundary is withheld below, so the
		// policy cannot be Full.
		level = profile.LevelDegraded
	}

	guaranteeBits = compileGuarantees(p, unixSocketsDangerous)
	if guaranteeBits&profile.GuaranteeEnvScrub != 0 {
		// Review H6, measured (see baseSandboxPreamble): Seatbelt does not
		// mediate sysctl KERN_PROCARGS2, so the scrub is real for the child's
		// own environment but does not stop it READING another same-user
		// process's initial environment.
		report.Entries = append(report.Entries, profile.ReportEntry{
			Feature: "env-scrub",
			Status:  "narrowed",
			Detail:  "the child's own environment is scrubbed, but Seatbelt cannot mediate sysctl(KERN_PROCARGS2): a confined process can read the initial environment (and argv) of any same-user process that is not a platform binary, including the process embedding this sandbox; keep secrets out of that process's environment",
		})
	}
	return b.String(), report, level, guaranteeBits
}

// compileFS writes the filesystem section (SPEC §5.1, §7.5) into b, appending any
// narrowing to report. See compileSBPL for the broad-to-narrow last-match-wins order.
func compileFS(b *strings.Builder, report *profile.CompileReport, fs []policy.FSEntry) {
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

func compileSeatbeltGlobRule(b *strings.Builder, report *profile.CompileReport, rule policy.FSEntry) {
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
	report.Entries = append(report.Entries, profile.ReportEntry{
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
func compileNet(b *strings.Builder, report *profile.CompileReport, net policy.NetPolicy) {
	b.WriteString("; --- network ---\n")
	compileNetMach(b, net)

	if net.Open {
		// Network: Allow with no egress route (and profile.Unconfined, which
		// never reaches Seatbelt in production). Everything else stays
		// default-deny; compileUnixSockets re-denies AF_UNIX after this.
		b.WriteString("(allow network*)\n")
		return
	}
	if net.ProxyPort != 0 {
		// Review L2: SBPL refuses an address literal here ("host must be * or
		// localhost in network address", measured for 127.0.0.1, [::1] and
		// the ip/tcp forms alike), so the egress proxy's listener cannot be
		// named exactly. tcp4 is the narrowest expressible form — the proxy
		// listens on 127.0.0.1 only (network.NewProxy), and tcp4 measurably
		// refuses ::1 at the same port where tcp admits it — but "localhost"
		// still matches every IPv4 address of this host's own interfaces at
		// that port, which is reported rather than claimed.
		b.WriteString(`(allow network-outbound (remote tcp4 "localhost:` + strconv.Itoa(int(net.ProxyPort)) + `"))` + "\n")
		report.Entries = append(report.Entries, profile.ReportEntry{
			Feature: "proxy-listener",
			Status:  "narrowed",
			Detail:  "SBPL cannot name 127.0.0.1 exactly: the egress-proxy rule admits IPv4 TCP to the proxy's port on any of this host's own addresses (loopback plus its interface IPs), never a remote host; the proxy itself listens on 127.0.0.1 only",
		})
	}

	for _, port := range net.Ports {
		b.WriteString(`(allow network-outbound (remote tcp "*:` + strconv.Itoa(int(port)) + `"))` + "\n")
	}
	if net.Loopback {
		b.WriteString(`(allow network-outbound (remote ip "localhost:*"))` + "\n")
		report.Entries = append(report.Entries, profile.ReportEntry{
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
		report.Entries = append(report.Entries, profile.ReportEntry{
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
		entry := profile.ReportEntry{
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

// compileNetMach admits the network-only bootstrap services
// (darwinNetworkMachLookupAllowlist: certificate evaluation) for a profile
// that grants any egress — the blanket allow, the egress proxy port, an
// allowed port, or loopback. A DNS-only or fully denied profile gets none:
// trustd performs its own unsandboxed fetches (AIA, OCSP, CRL) from URLs a
// presented certificate names, which would otherwise be a way to make a
// network-denied process's data leave the host.
func compileNetMach(b *strings.Builder, net policy.NetPolicy) {
	if net.Open || net.ProxyPort != 0 || len(net.Ports) > 0 || net.Loopback {
		b.WriteString(machLookupRule(darwinNetworkMachLookupAllowlist))
	}
}

// compileUnixSockets writes the AF_UNIX section (profile.UnixSocketPolicy)
// into b and reports whether the profile admits a same-user broker socket, in
// which case compileSBPL withholds GuaranteeProcessBoundary and lowers the
// level. Report feature names ("unix-sockets", "unix-sockets.dangerous") are
// shared with the Linux and Windows backends.
//
// What Seatbelt mediates, measured with /usr/bin/sandbox-exec on macOS 26
// against perl client/server probes (a pathname server outside every root,
// one inside a writable root, and a bind probe):
//
//   - socket(AF_UNIX) and socketpair() are NOT mediated: both succeed under
//     (deny default). Anonymous pairs are therefore always available, which
//     matches the contract (pipe-style IPC built on socketpair is unaffected
//     by the default denial).
//   - connect(2) to a pathname socket needs network-outbound with a
//     (remote unix-socket ...) filter; without one it fails EPERM. That is the
//     default denial: the base (deny default) already provides it, and the
//     only unix-socket rule a zero policy carries is compileNet's DNS
//     exception for mDNSResponder.
//   - bind(2) needs network-bind with a (local unix-socket ...) filter AND
//     file-write-create on the socket file: with the network-bind rule but no
//     file write, or under a carveout's write deny (.git), bind still fails.
//     So the filesystem section keeps deciding where a socket file can be
//     created, and these rules only add the socket operation on top.
//   - listen(2)/accept(2) need nothing further: a server bound under Local
//     mode accepted a connection from its own sandboxed child.
//   - every unix-socket path filter (subpath, path-literal, literal) matches
//     only the FULLY symlink-resolved path: a rule spelled /tmp/... matched
//     nothing when the socket was reached as /tmp/..., because the kernel
//     resolves it to /private/tmp/... first. Rules are emitted in the
//     canonical spelling, and in the public alias too for symmetry with the
//     file rules (harmless, never matching more than the canonical rule).
//   - (allow network*) — Net.Open — admits connect and bind to EVERY pathname
//     socket on the host. A sandboxed profile with Network: Allow therefore
//     re-denies both operations immediately after it (unfiltered
//     (remote unix-socket)/(local unix-socket) filters parse and match every
//     path), re-admits the DNS socket (getaddrinfo fails without it), and
//     then admits this policy's own grants, all under last-match-wins.
//
// Local mode admits connect and bind beneath every writable, non-exact
// filesystem root of the policy — the workspace when writable, additional
// writable roots, an executor-owned HOME and the executor's TMPDIR are all
// such entries in p.FS — in every spelling the file rules use. A writable
// root of "/" (HostWrite: Allow) would admit every broker socket on the
// machine, so that is flagged dangerous like a named broker path.
//
// Paths mode admits connect (never bind: the endpoint is someone else's) to
// each named socket exactly, via path-literal. The existing prefix is
// canonicalized with policy.CanonicalPath (symlinks resolved and, on APFS,
// each existing component re-spelled with its on-disk case, matching how
// configured roots are spelled), so a path under /var, /tmp or a symlinked
// directory still matches the kernel's resolved view. The LEAF is never
// followed: profile.UnixSocketPolicy promises that a symlinked socket path
// fails closed, and Seatbelt matching the resolved endpoint means a rule
// naming the link itself never matches a connect through it. A leaf that is
// a symlink at compile time is reported so the caller can name the target.
func compileUnixSockets(b *strings.Builder, report *profile.CompileReport, p policy.Effective) (dangerous bool) {
	sockets := p.UnixSockets
	open := p.Net.Open && p.Isolation != profile.Unconfined
	if p.Isolation == profile.Unconfined {
		// Unconfined never reaches Seatbelt in production; (allow network*)
		// stands and no AF_UNIX posture is claimed.
		return false
	}
	if sockets.Mode == profile.UnixSocketsDenied && len(sockets.Paths) == 0 && !open {
		return false
	}
	b.WriteString("; --- unix sockets ---\n")
	if open {
		b.WriteString("(deny network-outbound (remote unix-socket))\n")
		b.WriteString("(deny network-bind (local unix-socket))\n")
		b.WriteString(`(allow network-outbound (remote unix-socket (path-literal "` + sbplString(mDNSResponderSocket) + `")))` + "\n")
		if sockets.Mode == profile.UnixSocketsDenied && len(sockets.Paths) == 0 {
			report.Entries = append(report.Entries, profile.ReportEntry{
				Feature: "unix-sockets", Status: "enforced",
				Detail: "denied: network allow does not admit AF_UNIX endpoints (only the mDNSResponder DNS socket)",
			})
		}
	}

	if sockets.Mode == profile.UnixSocketsLocal {
		roots, wholeHost := unixSocketLocalRoots(p.FS)
		for _, root := range roots {
			quoted := sbplString(root)
			b.WriteString(`(allow network-outbound (remote unix-socket (subpath "` + quoted + `")))` + "\n")
			b.WriteString(`(allow network-bind (local unix-socket (subpath "` + quoted + `")))` + "\n")
		}
		report.Entries = append(report.Entries, profile.ReportEntry{
			Feature: "unix-sockets", Status: "enforced",
			Detail: "local: endpoints limited to writable roots",
		})
		if wholeHost {
			dangerous = true
			report.Entries = append(report.Entries, profile.ReportEntry{
				Feature: "unix-sockets.dangerous", Status: "narrowed",
				Detail: "local mode with a writable root at / admits every pathname socket on the host, including same-user brokers (container daemons) that start processes outside the sandbox; ProcessBoundary withheld",
			})
		}
	}

	for _, raw := range sockets.Paths {
		target, leafIsSymlink := unixSocketGrantPath(raw)
		for _, spelling := range uniqueStrings(append(seatbeltPathAliases(target, true), filepath.Clean(raw))) {
			b.WriteString(`(allow network-outbound (remote unix-socket (path-literal "` + sbplString(spelling) + `")))` + "\n")
		}
		detail := "path: connect admitted to " + raw
		if target != filepath.Clean(raw) {
			detail += " (canonical " + target + ")"
		}
		if leafIsSymlink {
			detail += "; the socket path is a symlink and Seatbelt matches the resolved endpoint, so this grant fails closed — name the target instead"
		}
		report.Entries = append(report.Entries, profile.ReportEntry{Feature: "unix-sockets", Status: "enforced", Detail: detail})
		if reason, isDangerous := dangerousUnixSocketPath(raw, target); isDangerous {
			dangerous = true
			report.Entries = append(report.Entries, profile.ReportEntry{
				Feature: "unix-sockets.dangerous", Status: "narrowed",
				Detail: raw + ": " + reason + "; ProcessBoundary withheld",
			})
		}
	}
	return dangerous
}

// unixSocketLocalRoots returns every spelling of every writable, non-exact,
// non-glob filesystem root in fs, in first-seen order, and whether one of
// them is "/" (every socket on the host). Exact entries (an exact grant, the
// null device) name a single object, not a place sockets are created; glob
// entries are deny-only in this vocabulary.
func unixSocketLocalRoots(fs []policy.FSEntry) (roots []string, wholeHost bool) {
	for _, entry := range fs {
		if entry.Access&policy.WriteAccess == 0 || entry.Exact || entry.Path == policy.NullDevicePath {
			continue
		}
		if strings.ContainsAny(entry.Path, policy.GlobMeta) {
			continue
		}
		if filepath.Clean(entry.Path) == string(filepath.Separator) {
			wholeHost = true
		}
		roots = append(roots, seatbeltPathAliases(entry.Path, entry.Canonical)...)
	}
	return uniqueStrings(roots), wholeHost
}

// unixSocketGrantPath canonicalizes a named socket path's existing PARENT
// (policy.CanonicalPath: symlinks resolved, APFS case re-spelled) and
// re-attaches the leaf unresolved, reporting whether that leaf is currently a
// symlink. When canonicalization fails the cleaned caller spelling stands —
// a rule that may match nothing, never one that matches more.
func unixSocketGrantPath(raw string) (target string, leafIsSymlink bool) {
	clean := filepath.Clean(raw)
	target = clean
	if dir, err := policy.CanonicalPath(filepath.Dir(clean)); err == nil {
		target = filepath.Join(dir, filepath.Base(clean))
	}
	if info, err := os.Lstat(target); err == nil && info.Mode()&os.ModeSymlink != 0 {
		leafIsSymlink = true
	}
	return target, leafIsSymlink
}

// darwinDangerousUnixSocketSuffixes are macOS same-user container-daemon
// sockets that profile.DangerousUnixSocket's (Linux-shaped) list does not
// name: on macOS the engine runs in a per-user VM and its API socket lives
// under the user's home, not /run. Each is root-equivalent inside that VM and
// can bind-mount the user's home, so it starts processes with the user's
// authority outside Seatbelt. Matched as a path suffix after a home prefix.
var darwinDangerousUnixSocketSuffixes = []struct{ suffix, reason string }{
	{"/.docker/run/docker.sock", "Docker Desktop daemon: starts containers with access to the user's files outside the sandbox"},
	{"/.orbstack/run/docker.sock", "OrbStack container daemon: starts containers outside the sandbox"},
	{"/.rd/docker.sock", "Rancher Desktop container daemon: starts containers outside the sandbox"},
}

// dangerousUnixSocketPath applies profile.DangerousUnixSocket to both the
// caller's spelling and the canonical one (so /var/run/docker.sock is caught
// even though Seatbelt sees /private/var/run/docker.sock), plus the macOS
// daemon sockets above and Colima's per-profile sockets
// (~/.colima/<profile>/docker.sock).
func dangerousUnixSocketPath(raw, canonical string) (string, bool) {
	for _, candidate := range []string{filepath.Clean(raw), canonical} {
		if reason, ok := profile.DangerousUnixSocket(candidate); ok {
			return reason, true
		}
		for _, entry := range darwinDangerousUnixSocketSuffixes {
			if strings.HasSuffix(candidate, entry.suffix) {
				return entry.reason, true
			}
		}
		if filepath.Base(candidate) == "docker.sock" && filepath.Base(filepath.Dir(filepath.Dir(candidate))) == ".colima" {
			return "Colima container daemon: starts containers outside the sandbox", true
		}
	}
	return "", false
}

// compileGuarantees derives the seam-facing guarantee bitmask from what the
// Seatbelt profile actually enforces for this policy. Each bit is fail-closed:
// set only when genuinely enforced. unixSocketsDangerous is compileUnixSockets'
// verdict that the profile admits a same-user broker socket.
func compileGuarantees(p policy.Effective, unixSocketsDangerous bool) uint64 {
	var bits uint64

	// sandbox-exec always wraps the spawn in an isolating boundary — unless the
	// profile hands the target a socket to a daemon that starts processes (or
	// is root-equivalent) on its behalf, outside Seatbelt entirely. Then the
	// boundary is only as good as that daemon, and the claim is withheld.
	if !unixSocketsDangerous {
		bits |= profile.GuaranteeProcessBoundary
	}

	// Writes are confined to policy-writable roots unless the policy itself grants
	// write at "/" (unconfined full access), in which case nothing is confined and
	// the claim would be dishonest. Probed with the SAME resolver the level
	// demotion uses (one consistent probe), which also catches a "/"-matching
	// write glob that a literal-"/" scan would miss.
	if policy.IsAccessRestricted(p.FS, policy.WriteAccess) {
		bits |= profile.GuaranteeWriteBoundary
	}

	// Reads are confined whenever the effective policy does not grant broad root
	// read. All process-exec and file-read allows are emitted per configured root.
	if policy.IsAccessRestricted(p.FS, policy.ReadAccess|policy.ExecAccess) {
		bits |= profile.GuaranteeReadBoundary
	}

	// The executor scrubs the child environment unless the policy inherits it
	// (mirrors the null backend's honesty fix).
	if !p.Env.Inherit {
		bits |= profile.GuaranteeEnvScrub
	}

	// Egress is default-deny + port/loopback/DNS allows, i.e. at least
	// port-restricted, unless the policy opens the network entirely.
	if !p.Net.Open {
		bits |= profile.GuaranteeNetworkBoundary
	}
	if p.Net.ProxyPort != 0 && !p.Net.Open {
		bits |= profile.GuaranteeTargetNetwork
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
// spellings confines access to the same configured filesystem object. profile.Deny
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
// NewBackend returns the darwin Seatbelt enforcement backend.
func NewBackend() enforce.Backend { return seatbeltBackend{} }

// compile generates the SBPL profile for the policy and returns a enforce.Spec that
// wraps every command/argv with `sandbox-exec -p <profile> -- ...`, plus the
// achieved level, guarantee bits, and compilation report.
//
// The profile is passed inline via -p, which is M1-verified and fine for the
// profiles this generator produces. A very large profile could exceed ARG_MAX;
// the future fallback is the temp-file `-f <path>` form of sandbox-exec, but the
// inline form keeps the transform stateless (no temp file to create or clean up)
// and is sufficient here.
func (seatbeltBackend) Compile(p policy.Effective) (enforce.Spec, profile.CompileReport, uint8, uint64, error) {
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
		Release: nil,
	}
	return spec, report, level, bits, nil
}
