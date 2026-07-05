package sandbox

import (
	"os"
	"path/filepath"
)

// This file defines the secure-default presets (SPEC §5.3, §5.4, §5.5) and the
// minimal system read set. They are exported as functions returning fresh
// slices rather than package-level slice variables on purpose: this is a
// security module, and an exported mutable []string could be reassigned or
// mutated in place to silently weaken a deny-list. Returning a copy per call
// keeps the versioned/auditable lists (which live in the function bodies here)
// tamper-proof from a consumer's perspective.

// secretHomeRelative names the per-user secret stores denied in every mode
// except unconfined (SPEC §5.3), expressed relative to the caller's home
// directory. DefaultSecretDenials joins each onto os.UserHomeDir(). It covers
// the explicit §5.3 dotfiles plus OS keychain and browser-profile directories
// for macOS and Linux (the two v1 platforms; SPEC §7).
var secretHomeRelative = []string{
	// Explicit §5.3 entries.
	".ssh",
	".aws",
	".gnupg",
	".kube",
	".config/gh",
	".netrc",
	".docker/config.json",
	// OS keychains / secret stores.
	"Library/Keychains",     // macOS user keychains
	".local/share/keyrings", // GNOME keyring (Linux)
	// Browser profile directories (cookies, saved credentials, tokens).
	"Library/Application Support/Google/Chrome",  // macOS Chrome
	"Library/Application Support/Chromium",       // macOS Chromium
	"Library/Application Support/BraveSoftware",  // macOS Brave
	"Library/Application Support/Microsoft Edge", // macOS Edge
	"Library/Application Support/Firefox",        // macOS Firefox
	"Library/Safari",                             // macOS Safari
	".config/google-chrome",                      // Linux Chrome
	".config/chromium",                           // Linux Chromium
	".config/BraveSoftware",                      // Linux Brave
	".config/microsoft-edge",                     // Linux Edge
	".mozilla",                                   // Linux Firefox
}

// secretAbsolute names secret stores at fixed absolute paths (not home-relative).
var secretAbsolute = []string{
	"/Library/Keychains", // macOS system keychain
}

// secretGlobs names glob patterns matched everywhere, including inside the
// workspace (SPEC §5.3): repo-local .env files are exactly the secrets the
// harness read-guard already denies. These are kept as bare globs and are never
// home-expanded or anchored to the workspace.
var secretGlobs = []string{
	"**/.env*",
}

// DefaultSecretDenials returns the §5.3 default deny-read paths: the per-user
// secret stores (with ~ expanded to the caller's home via os.UserHomeDir) plus
// the **/.env* glob, which stays a bare glob matched everywhere including inside
// a writable workspace. Applied in every mode except unconfined; PolicyFor emits
// each as an FSEntry with DenyAccess. If the home directory cannot be resolved,
// the home-relative entries are omitted (they cannot be safely named) but the
// absolute entries and globs are always returned. The returned slice is a fresh
// copy the caller may mutate freely.
func DefaultSecretDenials() []string {
	out := make([]string, 0, len(secretHomeRelative)+len(secretAbsolute)+len(secretGlobs))
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		for _, rel := range secretHomeRelative {
			out = append(out, filepath.Join(home, rel))
		}
	}
	out = append(out, secretAbsolute...)
	out = append(out, secretGlobs...)
	return out
}

// MetadataDenyCIDRs returns the cloud-metadata endpoints hard-denied whenever
// network is allowed (SPEC §5.4): link-local IPv4 and the EC2 IPv6 metadata
// address. This is a backend invariant, not a Policy or NetPolicy field:
// NetPolicy is deliberately allow-only (SPEC §5.2), so there is nowhere to
// encode a deny. Backends apply these CIDRs whenever they grant network and
// NetPolicy.Open is false (i.e. every non-unconfined mode). Enforcement is
// asserted in the backend tasks, not on the Policy struct. The returned slice
// is a fresh copy.
func MetadataDenyCIDRs() []string {
	return []string{
		"169.254.0.0/16", // IPv4 link-local, incl. 169.254.169.254
		"fd00:ec2::254",  // EC2 IPv6 metadata endpoint
	}
}

// MinimalSystemReadPaths returns the documented minimal set of system paths a
// basic toolchain needs to run: loaders, shared libraries, core binaries, and a
// few device/config paths. Granted Read|Exec. Used by zerotrust restricted-read
// (SPEC §4), where broad host reads are withheld and only these paths plus the
// workspace are visible. Broader modes use a single "/" read entry instead and
// do not consult this list. The returned slice is a fresh copy.
func MinimalSystemReadPaths() []string {
	return []string{
		"/usr",      // /usr/bin, /usr/lib, toolchains
		"/bin",      // core binaries (often a symlink into /usr on modern Linux)
		"/sbin",     // system binaries
		"/lib",      // shared libraries / loader
		"/lib64",    // 64-bit loader (Linux)
		"/etc",      // resolver, ssl certs, passwd
		"/dev/null", // the null device
		"/System",   // macOS system frameworks and dyld
		"/Library",  // macOS shared frameworks and support files
	}
}

// BaselineEnvAllowlist returns the §5.5 baseline environment allowlist: the
// variable names (and globs) spawned commands may inherit by default. This is
// the implicit baseline — it is NOT copied into EnvPolicy.Allow, which holds
// only additions beyond this set. A later env-assembly task consumes this preset
// when building the child environment. The returned slice is a fresh copy.
func BaselineEnvAllowlist() []string {
	return []string{
		"PATH",
		"HOME",
		"TERM",
		"LANG",
		"LC_*", // LC_ALL, LC_CTYPE, LC_MESSAGES, ... (glob)
		"USER",
		"LOGNAME",
		"SHELL",
		"TZ",
	}
}
