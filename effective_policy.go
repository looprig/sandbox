package sandbox

import (
	"os"
	"path/filepath"
)

type fsAccess uint8

const denyFSAccess fsAccess = 0

const (
	readFSAccess fsAccess = 1 << iota
	execFSAccess
	writeFSAccess
)

type fsEntry struct {
	Path   string
	Access fsAccess
	Denied fsAccess
	Exact  bool
	// Canonical marks a grant path already resolved and identity-bound by the
	// executor. Backends must not follow it through symlinks again.
	Canonical bool
}

const allFSAccess = readFSAccess | execFSAccess | writeFSAccess

type effectiveNetPolicy struct {
	Loopback  bool
	Private   bool
	Ports     []uint16
	ProxyPort uint16
	DNS       bool
	Open      bool
}

type effectiveEnvPolicy struct {
	Inherit bool
	Allow   []string
	Set     map[string]string
}

type effectiveLimits struct {
	MaxPIDs     int
	MaxMemBytes int64
	MaxCPUPct   int
	Disabled    bool
}

type effectivePolicy struct {
	Workspace string
	FS        []fsEntry
	Net       effectiveNetPolicy
	Env       effectiveEnvPolicy
	limits    effectiveLimits
	Isolation Isolation
	Home      Home
}

func cloneEffectivePolicy(p effectivePolicy) effectivePolicy {
	clone := p
	clone.FS = append([]fsEntry(nil), p.FS...)
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

const (
	nullDevicePath = "/dev/null"
)

func compileEffectivePolicy(profile *Profile) (effectivePolicy, error) {
	if err := profile.validate(); err != nil {
		return effectivePolicy{}, err
	}
	p := effectivePolicy{
		Workspace: profile.workspaceRoot,
		Isolation: profile.isolation,
		Home:      profile.home,
	}
	if profile.isolation == Unconfined {
		p.FS = []fsEntry{{Path: string(filepath.Separator), Access: readFSAccess | writeFSAccess | execFSAccess}}
		p.Net.Open = true
		return p, nil
	}

	p.FS = append(p.FS, minimalRuntimeEntries()...)
	p.FS = append(p.FS, fsEntry{Path: nullDevicePath, Access: readFSAccess | writeFSAccess, Exact: true})
	appendRootAccess(&p.FS, profile.workspaceRoot, profile.workspaceRead, profile.workspaceWrite)
	for _, root := range profile.additionalRoots {
		appendRootAccess(&p.FS, root.Path, root.Read, root.Write)
	}
	appendRootAccess(&p.FS, string(filepath.Separator), profile.hostRead, profile.hostWrite)
	if profile.network == Allow {
		p.Net.Open = true
	}
	return p, nil
}

func appendRootAccess(entries *[]fsEntry, path string, read, write Access) {
	var access, denied fsAccess
	if read == Allow {
		access |= readFSAccess | execFSAccess
	} else {
		denied |= readFSAccess | execFSAccess
	}
	if write == Allow {
		access |= writeFSAccess
	} else {
		denied |= writeFSAccess
	}
	*entries = append(*entries, fsEntry{Path: path, Access: access, Denied: denied})
}

func minimalRuntimeEntries() []fsEntry {
	var entries []fsEntry
	for _, path := range []string{
		"/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/libexec",
		"/usr/lib/git-core", "/lib", "/lib64",
	} {
		entries = append(entries, fsEntry{Path: path, Access: readFSAccess | execFSAccess})
	}
	for _, path := range []string{
		"/usr/lib", "/usr/lib64", "/System/Library", "/etc/ssl/certs", "/etc/pki",
	} {
		entries = append(entries, fsEntry{Path: path, Access: readFSAccess})
	}
	for _, path := range []string{
		"/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf", "/etc/services",
		"/etc/protocols", "/etc/localtime", "/etc/ld.so.cache", "/etc/ssl/cert.pem",
	} {
		entries = append(entries, fsEntry{Path: path, Access: readFSAccess, Exact: true})
	}
	return entries
}

func baselineEnvAllowlist() []string {
	return []string{"PATH", "HOME", "TERM", "LANG", "LC_*", "USER", "LOGNAME", "SHELL", "TZ"}
}

func metadataDenyCIDRs() []string {
	return []string{"169.254.0.0/16", "fd00:ec2::254"}
}

func containsPort(ports []uint16, port uint16) bool {
	for _, candidate := range ports {
		if candidate == port {
			return true
		}
	}
	return false
}

func netBlocked(p effectivePolicy) bool {
	net := p.Net
	return !net.Loopback && !net.Private && !net.DNS && !net.Open && len(net.Ports) == 0
}

func hasDeniedFSAccess(entries []fsEntry, access fsAccess) bool {
	for _, entry := range entries {
		if normalizedDenied(entry)&access != 0 {
			return true
		}
	}
	return false
}

func isFSAccessRestricted(entries []fsEntry, access fsAccess) bool {
	return hasDeniedFSAccess(entries, access) || resolveFS(entries, string(filepath.Separator))&access != access
}

func realHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Clean(home), nil
}
