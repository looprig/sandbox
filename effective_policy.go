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
}

type effectiveNetPolicy struct {
	Loopback bool
	Private  bool
	Ports    []uint16
	DNS      bool
	Open     bool
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
	writableTmpRoot = "/tmp"
	nullDevicePath  = "/dev/null"
)

func compileEffectivePolicy(profile *Profile) (effectivePolicy, error) {
	if err := profile.validate(); err != nil {
		return effectivePolicy{}, err
	}
	p := effectivePolicy{
		Workspace: profile.workspaceRoot,
		Isolation: profile.isolation,
		Home:      profile.home,
		Env: effectiveEnvPolicy{
			Set: map[string]string{"TMPDIR": writableTmpRoot},
		},
	}
	if profile.isolation == Unconfined {
		p.FS = []fsEntry{{Path: string(filepath.Separator), Access: readFSAccess | writeFSAccess | execFSAccess}}
		p.Net.Open = true
		return p, nil
	}

	for _, path := range minimalRuntimeReadPaths() {
		p.FS = append(p.FS, fsEntry{Path: path, Access: readFSAccess | execFSAccess})
	}
	p.FS = append(p.FS, fsEntry{Path: nullDevicePath, Access: readFSAccess | writeFSAccess})
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
	var access fsAccess
	if read == Allow {
		access |= readFSAccess | execFSAccess
	}
	if write == Allow {
		access |= writeFSAccess
	}
	if access != denyFSAccess {
		*entries = append(*entries, fsEntry{Path: path, Access: access})
	}
}

func minimalRuntimeReadPaths() []string {
	return []string{"/usr", "/bin", "/sbin", "/lib", "/lib64", "/etc", "/System", "/Library"}
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

func realHome() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Clean(home), nil
}
