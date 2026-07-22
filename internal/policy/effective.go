package policy

import (
	"github.com/looprig/sandbox/pkg/profile"
	"os"
	"path/filepath"
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
}

func Clone(p Effective) Effective {
	clone := p
	clone.FS = append([]FSEntry(nil), p.FS...)
	clone.RuntimeBaselines = append([]string(nil), p.RuntimeBaselines...)
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
		Workspace: settings.WorkspaceRoot,
		Isolation: settings.Isolation,
		Home:      settings.Home,
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
	for _, root := range settings.AdditionalRoots {
		appendRootAccess(&p.FS, root.Path, root.Read, root.Write)
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

func BaselineEnvAllowlist() []string {
	return []string{"PATH", "HOME", "TERM", "LANG", "LC_*", "USER", "LOGNAME", "SHELL", "TZ"}
}

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
