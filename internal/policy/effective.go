package policy

import (
	"github.com/looprig/sandbox/pkg/profile"
	"os"
	"path/filepath"
	"strings"
)

type FSAccess uint8

const DenyAccess FSAccess = 0

const (
	ReadAccess FSAccess = 1 << iota
	ExecAccess
	WriteAccess
)

type FSEntry struct {
	Path   string
	Access FSAccess
	Denied FSAccess
	Exact  bool
	// Canonical marks a grant path already resolved and identity-bound by the
	// executor. Backends must not follow it through symlinks again.
	Canonical bool
}

const AllAccess = ReadAccess | ExecAccess | WriteAccess

type NetPolicy struct {
	Loopback  bool
	Private   bool
	Ports     []uint16
	ProxyPort uint16
	DNS       bool
	Open      bool
}

type EnvPolicy struct {
	Inherit bool
	Allow   []string
	Set     map[string]string
}

type Limits struct {
	MaxPIDs     int
	MaxMemBytes int64
	MaxCPUPct   int
	Disabled    bool
}

type Effective struct {
	Workspace        string
	FS               []FSEntry
	RuntimeBaselines []string
	Net              NetPolicy
	Env              EnvPolicy
	Limits           Limits
	Isolation        profile.Isolation
	Home             profile.Home
	// ProjectionRoots contains only configured roots eligible for a Windows
	// restricting-SID ACL projection. Host volumes and runtime baselines are absent.
	ProjectionRoots []string
	// UnixSockets is the profile's AF_UNIX escape hatch (profile.UnixSocketPolicy):
	// the zero value denies socket(AF_UNIX); a backend that admits it must
	// confine the reachable endpoints or report what it cannot confine.
	UnixSockets profile.UnixSocketPolicy
	// RequiredGuarantees is the immutable public-profile requirement snapshot.
	// Backends use it only for typed mechanism selection errors; achieved bits
	// remain authoritative and are checked independently by the executor.
	RequiredGuarantees uint64
}

func Clone(p Effective) Effective {
	clone := p
	clone.FS = append([]FSEntry(nil), p.FS...)
	clone.RuntimeBaselines = append([]string(nil), p.RuntimeBaselines...)
	clone.ProjectionRoots = append([]string(nil), p.ProjectionRoots...)
	clone.UnixSockets.Paths = append([]string(nil), p.UnixSockets.Paths...)
	clone.Net.Ports = append([]uint16(nil), p.Net.Ports...)
	clone.Env.Allow = append([]string(nil), p.Env.Allow...)
	if p.Env.Set != nil {
		clone.Env.Set = make(map[string]string, len(p.Env.Set))
		for key, value := range p.Env.Set {
			clone.Env.Set[key] = value
		}
	}
	return clone
}

func Compile(prof *profile.Profile) (Effective, error) {
	return compileWithHostRoots(prof, hostRootPaths)
}

func compileWithHostRoots(prof *profile.Profile, roots func() ([]string, error)) (Effective, error) {
	if err := prof.Validate(); err != nil {
		return Effective{}, err
	}
	settings := prof.Settings()
	p := Effective{
		Workspace:          settings.WorkspaceRoot,
		Isolation:          settings.Isolation,
		Home:               settings.Home,
		RequiredGuarantees: settings.RequiredGuarantees,
		UnixSockets:        settings.UnixSockets,
	}
	if settings.Isolation == profile.Unconfined {
		hostRoots, err := roots()
		if err != nil {
			return Effective{}, err
		}
		sortHostRoots(hostRoots)
		for _, root := range hostRoots {
			p.FS = append(p.FS, FSEntry{Path: root, Access: ReadAccess | WriteAccess | ExecAccess})
		}
		p.Net.Open = true
		return p, nil
	}

	p.RuntimeBaselines = runtimeBaselines()
	p.FS = append(p.FS, MinimalRuntimeEntries()...)
	p.FS = append(p.FS, FSEntry{Path: NullDevicePath, Access: ReadAccess | WriteAccess, Exact: true})
	appendRootAccess(&p.FS, settings.WorkspaceRoot, settings.WorkspaceRead, settings.WorkspaceWrite)
	p.ProjectionRoots = append(p.ProjectionRoots, settings.WorkspaceRoot)
	for _, root := range settings.AdditionalRoots {
		appendRootAccess(&p.FS, root.Path, root.Read, root.Write)
		p.ProjectionRoots = append(p.ProjectionRoots, root.Path)
	}
	hostRoots, err := roots()
	if err != nil {
		return Effective{}, err
	}
	sortHostRoots(hostRoots)
	for _, root := range hostRoots {
		appendRootAccess(&p.FS, root, settings.HostRead, settings.HostWrite)
	}
	if settings.Network == profile.Allow {
		p.Net.Open = true
	}
	return p, nil
}

func appendRootAccess(entries *[]FSEntry, path string, read, write profile.Access) {
	var access, denied FSAccess
	if read == profile.Allow {
		access |= ReadAccess | ExecAccess
	} else {
		denied |= ReadAccess | ExecAccess
	}
	if write == profile.Allow {
		access |= WriteAccess
	} else {
		denied |= WriteAccess
	}
	*entries = append(*entries, FSEntry{Path: path, Access: access, Denied: denied})
}

// unixBaselineEnvAllowlist is the scrubbed-environment baseline on darwin and
// Linux (SPEC §3): the variables a POSIX shell and common toolchains need to
// start and to identify the user and locale. BaselineEnvAllowlist selects it on
// every !windows build (effective_env_unix.go). Names are matched exactly
// (EnvNameFold is the identity there).
func unixBaselineEnvAllowlist() []string {
	return []string{"PATH", "HOME", "TERM", "LANG", "LC_*", "USER", "LOGNAME", "SHELL", "TZ"}
}

// windowsBaselineEnvAllowlist is the scrubbed-environment baseline on Windows,
// selected by effective_env_windows.go. Windows environment names are
// case-insensitive, so the exec matcher compares them folded (EnvNameFold):
// "PATH" here admits the "Path" spelling os.Environ reports. Each entry is
// what the loader, the CRT or common toolchains need to START:
//
//   - PATH, PATHEXT: program lookup; PATHEXT is how cmd.exe and
//     CreateProcess-adjacent lookup resolve an extensionless name.
//   - SystemRoot, windir, SystemDrive: the Windows directory. Winsock,
//     CryptoAPI/CNG and many DLLs fail to initialise without SystemRoot.
//   - OS, PROCESSOR_* (ARCHITECTURE, IDENTIFIER, LEVEL, REVISION and the WOW64
//     ARCHITEW6432), NUMBER_OF_PROCESSORS: host identification read by build
//     tools, runtimes (Go, .NET, Node) and installers' architecture probes.
//   - ProgramData, ProgramFiles, ProgramFiles(x86), ProgramW6432,
//     CommonProgramFiles, CommonProgramFiles(x86), CommonProgramW6432,
//     ALLUSERSPROFILE: machine-wide install locations toolchains use to find
//     themselves (MSVC, Git for Windows, SDKs). They are machine directories,
//     not per-user ones; whether the child may write beneath them is decided
//     by the backend's filesystem policy, not by the variable.
//   - USERNAME, COMPUTERNAME, USERDOMAIN: identity strings, the analogue of
//     USER/LOGNAME on Unix. They name no location.
//   - TERM, LANG, LC_*, TZ: terminal and locale, as on Unix.
//
// Deliberately EXCLUDED: every variable naming a per-user writable or
// credential-bearing location — APPDATA, LOCALAPPDATA, USERPROFILE, HOME,
// HOMEDRIVE/HOMEPATH, TEMP/TMP, PUBLIC — and the network-profile names
// (LOGONSERVER, USERDOMAIN_ROAMINGPROFILE). ExecutorSet instead SETS HOME,
// USERPROFILE, TEMP, TMP and TMPDIR to executor-owned directories, so a child
// that needs them gets a location this executor owns rather than the
// caller's. ComSpec is excluded because SPEC §4 never trusts %ComSpec%:
// RunCommand runs the canonical System32 cmd.exe, and a child must not be
// handed a caller-chosen interpreter path either.
func windowsBaselineEnvAllowlist() []string {
	return []string{
		"PATH", "PATHEXT",
		"SystemRoot", "windir", "SystemDrive",
		"OS", "PROCESSOR_*", "NUMBER_OF_PROCESSORS",
		"ProgramData", "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432",
		"CommonProgramFiles", "CommonProgramFiles(x86)", "CommonProgramW6432",
		"ALLUSERSPROFILE",
		"USERNAME", "COMPUTERNAME", "USERDOMAIN",
		"TERM", "LANG", "LC_*", "TZ",
	}
}

// windowsEnvNameFold folds an environment variable name to the single key
// Windows treats every spelling of it as: names there are case-insensitive, so
// "Path", "PATH" and "path" are one variable. Upper-casing matches the
// kernel's own case-insensitive comparison for the ASCII names environments
// use in practice.
func windowsEnvNameFold(name string) string { return strings.ToUpper(name) }

func MetadataDenyCIDRs() []string {
	return []string{"169.254.0.0/16", "fd00:ec2::254"}
}

func ContainsPort(ports []uint16, port uint16) bool {
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

func netBlocked(p Effective) bool {
	net := p.Net
	return !net.Loopback && !net.Private && !net.DNS && !net.Open && len(net.Ports) == 0
}

func hasDeniedFSAccess(entries []FSEntry, access FSAccess) bool {
	for _, entry := range entries {
		if NormalizedDenied(entry)&access != 0 {
			return true
		}
	}
	return false
}

func IsAccessRestricted(entries []FSEntry, access FSAccess) bool {
	return hasDeniedFSAccess(entries, access) || ResolveFS(entries, string(filepath.Separator))&access != access
}

func RealHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Clean(home), nil
}
