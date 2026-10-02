//go:build linux

package linux

import (
	"errors"
	"fmt"
	"strings"

	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
	"golang.org/x/sys/unix"
)

// This file compiles the profile's AF_UNIX escape hatch
// (profile.UnixSocketPolicy, carried on policy.Effective.UnixSockets) for both
// Linux rungs (review C2). The zero policy keeps the default: the Seccomp
// socket() allowlist refuses AF_UNIX and nothing here runs. Any non-zero
// policy makes the filter ADMIT socket(AF_UNIX) (SeccompPolicy.AllowUnix), and
// admitting the socket is the easy half: what decides the guarantee is which
// ENDPOINTS a connect() can then reach, because a same-user broker (the D-Bus
// session bus, the systemd user manager, a container daemon, an X server)
// starts processes outside every confinement layer this backend applies.
//
// Endpoints come in two namespaces, and each rung confines them differently:
//
//   - PATHNAME sockets are reached by path lookup, which Landlock (ABI <= 8)
//     does not mediate. At Rung 1 the mount view is the only bound: a socket
//     is reachable iff its path is visible in the view, so the view must not
//     bind the host's socket directories (the "/" bind HostRead Allow makes, or
//     any bind root that contains, or lies inside, /run, /var/run or
//     /tmp/.X11-unix — hostSocketExposure). At Rung 2 there is no view, so
//     every same-user pathname socket is reachable and that is reported.
//   - ABSTRACT sockets live in the network namespace. Rung 1's Netns (created
//     only for a Confined network) isolates them; Landlock's abstract-socket
//     scope (LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET, ABI >= 6) confines them on
//     either rung to sockets created inside the target's own Landlock domain,
//     and is applied whenever AF_UNIX is admitted and the compile-time ABI
//     probe allows it.
//
// Named Paths are exact grants: at Rung 1 each is bind-mounted read-only into
// the view as the one socket file (never its directory), resolved at spawn
// without following any symlink (enumerateSocketBinds / applySocketBind), and
// skipped when it is then missing or not a socket. A path whose service runs
// commands (profile.DangerousUnixSocket) is flagged per path; granting it
// makes the process boundary a statement about that daemon, so the backend
// withholds GuaranteeProcessBoundary and lowers the level, on either rung —
// the owner's position is flag-not-refuse, so the spawn still runs.

// hostSocketDirs are the host directories where the same-user and system
// broker sockets profile.DangerousUnixSocket names live. A Rung-1 bind root
// equal to one, containing one, or lying inside one makes those sockets
// visible in the mount view (hostSocketExposure).
var hostSocketDirs = []string{"/run", "/var/run", "/tmp/.X11-unix"}

// compiledUnix is one compile's AF_UNIX outcome: what stage 2 must do and what
// the backend reports and withholds.
type compiledUnix struct {
	// allow admits socket(AF_UNIX) in the Seccomp filter.
	allow bool
	// scopeAbstract requests Landlock's abstract-unix-socket scope (ABI >= 6).
	scopeAbstract bool
	// socketBinds are the named paths a Rung-1 spawn binds into its view.
	socketBinds []string
	// withholdProcessBoundary is true when an admitted endpoint escapes the
	// process boundary: an unconfined endpoint namespace or a dangerous path.
	withholdProcessBoundary bool
	// entries are the "unix-sockets" / "unix-sockets.dangerous" report rows.
	entries []profile.ReportEntry
}

// unixSocketMode names a policy's shape for report text.
func unixSocketMode(u profile.UnixSocketPolicy) string {
	switch {
	case u.Mode == profile.UnixSocketsLocal && len(u.Paths) > 0:
		return "local+paths"
	case u.Mode == profile.UnixSocketsLocal:
		return "local"
	default:
		return "paths"
	}
}

// compileUnixSockets compiles the escape hatch for rung. abi is the Landlock
// ABI the compile probed (ProbeLandlockABI); mvp and netns describe the Rung-1
// mount view and whether its network namespace exists (both ignored at Rung
// 2). The zero policy returns the zero compiledUnix: nothing is admitted and
// nothing new is reported.
func compileUnixSockets(u profile.UnixSocketPolicy, rung Rung, abi int, mvp MountViewPlan, netns bool) compiledUnix {
	if u.Mode == profile.UnixSocketsDenied && len(u.Paths) == 0 {
		return compiledUnix{}
	}
	out := compiledUnix{allow: true, scopeAbstract: abi >= 6}
	var notSockets []string
	for _, path := range u.Paths {
		if err := checkSocketPath(path); err != nil {
			notSockets = append(notSockets, fmt.Sprintf("%s (%v)", path, err))
		}
	}
	pathsDetail := ""
	if len(u.Paths) > 0 {
		pathsDetail = "; paths: " + strings.Join(u.Paths, ", ")
		if rung == RungOne {
			pathsDetail += " — each bound read-only into the mount view as the exact socket file, resolved at spawn without following symlinks; a missing, symlinked or non-socket path is skipped, never widened to its directory, and a socket beneath a deny is hidden by the deny"
		}
		if u.Mode == profile.UnixSocketsDenied {
			pathsDetail += "; AF_UNIX itself is admitted, so sockets the target creates for itself are reachable too"
		}
	}
	if len(notSockets) > 0 {
		pathsDetail += "; not a socket at compile time (re-checked at each spawn, skipped while absent): " + strings.Join(notSockets, ", ")
	}
	abstractScope := fmt.Sprintf("abstract names confined to sockets created inside this sandbox by Landlock abstract-socket scoping (ABI %d)", abi)
	if !out.scopeAbstract {
		abstractScope = ""
	}

	var status, detail string
	if rung == RungOne {
		exposing := hostSocketExposure(mvp)
		abstractIsolated := netns || out.scopeAbstract
		var reasons []string
		if len(exposing) > 0 {
			reasons = append(reasons, hostSocketExposureReason(exposing))
		}
		if !abstractIsolated {
			reasons = append(reasons, fmt.Sprintf("abstract namespace shared with the host (Net.Open creates no network namespace, and Landlock ABI %d < 6 cannot scope abstract sockets)", abi))
		}
		if len(reasons) == 0 {
			status = linuxStatusEnforced
			// With a Netns the namespace is the isolation (the Landlock scope,
			// when the ABI has it, is applied too, as defence in depth).
			abstract := "abstract names isolated by the network namespace"
			if !netns {
				abstract = abstractScope
			}
			detail = "local: pathname sockets limited to the mount view, " + abstract + ", socketpair"
			if u.Mode == profile.UnixSocketsDenied {
				detail = "paths only: pathname sockets limited to the mount view, " + abstract + ", socketpair"
			}
		} else {
			status = linuxStatusNarrowed
			out.withholdProcessBoundary = true
			detail = fmt.Sprintf("AF_UNIX admitted (%s) but its endpoints are not confined: %s — GuaranteeProcessBoundary is withheld and the level lowered to Degraded",
				unixSocketMode(u), strings.Join(reasons, "; "))
		}
		out.socketBinds = append(out.socketBinds, u.Paths...)
	} else {
		status = linuxStatusNarrowed
		out.withholdProcessBoundary = true
		abstract := abstractScope
		if !out.scopeAbstract {
			abstract = fmt.Sprintf("abstract names are NOT confined: Landlock ABI %d < 6 cannot scope abstract sockets, so host abstract names (e.g. @/tmp/.X11-unix/X0) are reachable", abi)
		}
		detail = fmt.Sprintf("AF_UNIX admitted (%s) at Rung 2, which has no mount or network namespace, and Landlock (ABI <= 8) does not mediate pathname connect(): "+
			"every same-user pathname socket is reachable — for example the D-Bus session bus (/run/user/$UID/bus) and the systemd user manager (/run/user/$UID/systemd/private), which start processes outside the sandbox; "+
			"%s; GuaranteeProcessBoundary is not claimed and the level is Degraded (flagged, not refused)",
			unixSocketMode(u), abstract)
	}
	if len(notSockets) > 0 {
		status = linuxStatusNarrowed
	}
	out.entries = append(out.entries, profile.ReportEntry{Feature: "unix-sockets", Status: status, Detail: detail + pathsDetail})
	for _, path := range u.Paths {
		reason, dangerous := profile.DangerousUnixSocket(path)
		if !dangerous {
			continue
		}
		out.withholdProcessBoundary = true
		out.entries = append(out.entries, profile.ReportEntry{
			Feature: "unix-sockets.dangerous",
			Status:  linuxStatusNarrowed,
			Detail: fmt.Sprintf("%s: %s — granting it hands the target that daemon's authority, so GuaranteeProcessBoundary is withheld and the level is Degraded",
				path, reason),
		})
	}
	return out
}

// Report status strings shared by this file (the profile surface compares
// them literally).
const (
	linuxStatusEnforced = "Enforced"
	linuxStatusNarrowed = "narrowed"
)

// hostSocketExposure returns the Rung-1 bind roots that make host broker
// sockets visible in the mount view: "/" (the HostRead-Allow host-root bind,
// which exposes every one) and any root equal to, containing, or inside a
// hostSocketDirs entry.
func hostSocketExposure(mvp MountViewPlan) []string {
	var exposing []string
	for _, root := range append(append([]string(nil), mvp.RWBinds...), mvp.ROBinds...) {
		for _, dir := range hostSocketDirs {
			if root == dir || policy.PathUnder(root, dir) || policy.PathUnder(dir, root) {
				exposing = appendUniquePath(exposing, root)
				break
			}
		}
	}
	return exposing
}

// hostSocketExposureReason renders hostSocketExposure's result for the report:
// exactly which bind exposes which host sockets.
func hostSocketExposureReason(exposing []string) string {
	for _, root := range exposing {
		if root == "/" {
			return `host sockets visible through the "/" bind (HostRead Allow binds the host root into the view, so every same-user socket under /run/user/$UID, /run and /tmp is reachable)`
		}
	}
	quoted := make([]string, 0, len(exposing))
	for _, root := range exposing {
		quoted = append(quoted, fmt.Sprintf("%q", root))
	}
	return fmt.Sprintf("host sockets visible through the %s bind (a bound root that contains or lies inside %s exposes the broker sockets there)",
		strings.Join(quoted, ", "), strings.Join(hostSocketDirs, ", "))
}

// errNotSocket reports a named socket path that resolves to another file type.
var errNotSocket = errors.New("not a socket")

// checkSocketPath resolves path exactly as a Rung-1 spawn will — without
// following a symlink in ANY component (an attacker-planted link must not
// redirect an exact grant) — and reports whether it is a socket now.
func checkSocketPath(path string) error {
	fd, err := openSocketPath(path)
	if err != nil {
		return err
	}
	return unix.Close(fd)
}

// openSocketPath returns an O_PATH descriptor to path when it names a socket,
// resolved with RESOLVE_NO_SYMLINKS (every component) and no magic links. The
// caller owns the descriptor.
func openSocketPath(path string) (int, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   uint64(unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC),
		Resolve: uint64(unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS),
	})
	if err != nil {
		return -1, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		_ = unix.Close(fd)
		return -1, errNotSocket
	}
	return fd, nil
}

// enumerateSocketBinds is the spawn-time snapshot of the named socket paths a
// Rung-1 view binds: those that are sockets NOW. A missing, symlinked or
// non-socket path is dropped (narrower, never its directory); stage 2
// re-resolves each one again before binding it (applySocketBind).
func enumerateSocketBinds(paths []string) []string {
	var out []string
	for _, path := range paths {
		if checkSocketPath(path) == nil {
			out = append(out, path)
		}
	}
	return out
}
