package profile

import (
	"fmt"
	"path"
	"path/filepath"
	"slices"
	"strings"
)

// UnixSocketMode is the coarse AF_UNIX posture of a sandboxed profile. The
// zero value denies, which is the only posture under which a backend can keep
// its process boundary unconditionally: a pathname or abstract Unix socket
// reaches same-user services (a D-Bus session bus, a user systemd manager, a
// container daemon) that will start processes outside every other mechanism.
type UnixSocketMode uint8

const (
	// UnixSocketsDenied (default): socket(AF_UNIX) is refused. socketpair()
	// and the pipe-style IPC built on it are unaffected.
	UnixSocketsDenied UnixSocketMode = iota
	// UnixSocketsLocal admits AF_UNIX sockets whose endpoints are the
	// sandbox's own: sockets the target creates beneath its writable roots
	// (Python's multiprocessing forkserver, test fixtures), anonymous pairs,
	// and abstract names inside an isolated namespace. A backend that cannot
	// confine endpoints to that set (Linux Rung 2, which has no mount or
	// network namespace) must report the mode as narrowed, withhold
	// GuaranteeProcessBoundary and lower the level, never silently widen.
	UnixSocketsLocal
)

// UnixSocketPolicy is the explicit escape hatch from the default AF_UNIX
// denial. Paths names pathname sockets OUTSIDE the sandbox's own roots the
// target may connect to (an SSH_AUTH_SOCK, a GPG agent, a container daemon);
// each is an absolute, clean path and is granted exactly, never as a tree.
// Mode and Paths compose: Paths alone admits only the named endpoints; Local
// alone admits only sandbox-local endpoints; both admit both. Every named
// path is a trust decision about the service behind it — a daemon that runs
// commands (DangerousUnixSocket) makes the process boundary a statement about
// that daemon, not about the kernel, and backends report it as such.
type UnixSocketPolicy struct {
	Mode  UnixSocketMode
	Paths []string
}

func (policy UnixSocketPolicy) isZero() bool {
	return policy.Mode == UnixSocketsDenied && len(policy.Paths) == 0
}

func (policy UnixSocketPolicy) clone() UnixSocketPolicy {
	return UnixSocketPolicy{Mode: policy.Mode, Paths: append([]string(nil), policy.Paths...)}
}

func validUnixSocketMode(mode UnixSocketMode) bool { return mode <= UnixSocketsLocal }

// normalizeUnixSockets validates and normalizes a caller's policy: a known
// mode, and absolute, clean, non-root, deduplicated and sorted paths. A path
// need not exist yet (an agent socket is often created after the profile),
// so it is held to lexical cleanliness here and resolved by the backend at
// spawn, which is also where a symlinked socket path fails closed.
func normalizeUnixSockets(policy UnixSocketPolicy) (UnixSocketPolicy, error) {
	if !validUnixSocketMode(policy.Mode) {
		return UnixSocketPolicy{}, fmt.Errorf("%w: unix socket mode %d", ErrInvalidProfile, policy.Mode)
	}
	paths := make([]string, 0, len(policy.Paths))
	for i, raw := range policy.Paths {
		// A trailing separator is tolerated (a caller joining paths produces
		// one); anything else that Clean would rewrite is refused rather than
		// silently re-spelled, so a ".." never hides in a grant.
		trimmed := strings.TrimRight(raw, string(filepath.Separator))
		if trimmed == "" || !filepath.IsAbs(trimmed) || filepath.Clean(trimmed) != trimmed {
			return UnixSocketPolicy{}, fmt.Errorf("%w: unix socket path %d %q is not an absolute clean path", ErrInvalidProfile, i, raw)
		}
		clean := trimmed
		if clean == string(filepath.Separator) || filepath.VolumeName(clean)+string(filepath.Separator) == clean {
			return UnixSocketPolicy{}, fmt.Errorf("%w: unix socket path %d names a filesystem root", ErrInvalidProfile, i)
		}
		if !slices.Contains(paths, clean) {
			paths = append(paths, clean)
		}
	}
	slices.Sort(paths)
	return UnixSocketPolicy{Mode: policy.Mode, Paths: paths}, nil
}

// minUnixSocketMode is the Restrict intersection: Denied < Local.
func minUnixSocketMode(a, b UnixSocketMode) UnixSocketMode {
	if a < b {
		return a
	}
	return b
}

// restrictUnixSockets intersects two normalized policies: the narrower mode
// and only the paths both inputs name.
func restrictUnixSockets(base, ceiling UnixSocketPolicy) UnixSocketPolicy {
	out := UnixSocketPolicy{Mode: minUnixSocketMode(base.Mode, ceiling.Mode)}
	for _, p := range base.Paths {
		if slices.Contains(ceiling.Paths, p) {
			out.Paths = append(out.Paths, p)
		}
	}
	return out
}

// dangerousUnixSocketPatterns are path globs (path.Match, "*" does not cross
// "/") of sockets whose service will run commands or inject input as the
// invoking user, so granting one hands the target the host's authority
// regardless of every other mechanism. The list is deliberately about
// brokers, not credentials: an ssh-agent or gpg-agent socket signs with a key
// but starts nothing, so it is not flagged here.
var dangerousUnixSocketPatterns = []struct{ pattern, reason string }{
	{"/run/user/*/bus", "D-Bus session bus: systemd-run --user and desktop services start arbitrary processes outside the sandbox"},
	{"/var/run/user/*/bus", "D-Bus session bus: systemd-run --user and desktop services start arbitrary processes outside the sandbox"},
	{"/run/dbus/system_bus_socket", "D-Bus system bus: privileged services accept activation requests"},
	{"/var/run/dbus/system_bus_socket", "D-Bus system bus: privileged services accept activation requests"},
	{"/run/user/*/systemd/private", "systemd user manager: starts transient units as the user outside the sandbox"},
	{"/run/user/*/systemd/notify", "systemd user manager notification socket"},
	{"/run/systemd/private", "systemd system manager: starts units outside the sandbox"},
	{"/run/systemd/notify", "systemd system manager notification socket"},
	{"/var/run/docker.sock", "container daemon: equivalent to root on the host"},
	{"/run/docker.sock", "container daemon: equivalent to root on the host"},
	{"/run/user/*/podman/podman.sock", "container daemon: starts containers as the user outside the sandbox"},
	{"/run/podman/podman.sock", "container daemon: starts containers outside the sandbox"},
	{"/var/run/containerd/containerd.sock", "container daemon: equivalent to root on the host"},
	{"/run/containerd/containerd.sock", "container daemon: equivalent to root on the host"},
	{"/tmp/.X11-unix/X*", "X11 display: keystroke injection into every unsandboxed client"},
	{"/run/user/*/wayland-*", "Wayland display: input and clipboard access to every unsandboxed client"},
	{"/run/user/*/pipewire-*", "PipeWire: screen and audio capture"},
}

// DangerousUnixSocket reports whether path names a known same-user broker
// socket — one whose service runs commands or injects input on the caller's
// behalf — with a short reason. A backend that grants such a path withholds
// GuaranteeProcessBoundary and flags the grant in its compile report; the
// profile itself remains valid, because the decision to trust that daemon is
// the caller's to make explicitly.
func DangerousUnixSocket(socketPath string) (reason string, dangerous bool) {
	candidate := filepath.ToSlash(filepath.Clean(socketPath))
	for _, entry := range dangerousUnixSocketPatterns {
		if ok, err := path.Match(entry.pattern, candidate); err == nil && ok {
			return entry.reason, true
		}
	}
	return "", false
}
