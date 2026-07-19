package sandbox

import (
	"os"
	"path/filepath"
)

// These fixtures preserve backend unit-test shapes while production profiles
// are consumer-defined. They are not part of the package API.
type testPolicyMode uint8

type Mode = testPolicyMode

const (
	ZeroTrust testPolicyMode = iota
	ReadOnly
	Write
	Trusted
	testUnconfined
)

type PolicyOption func(*effectivePolicy)

func PolicyFor(mode testPolicyMode, workspace string, opts ...PolicyOption) effectivePolicy {
	workspace = filepath.Clean(workspace)
	p := effectivePolicy{
		Workspace: workspace,
		Env: effectiveEnvPolicy{Set: map[string]string{
			"TMPDIR": writableTmpRoot,
		}},
	}
	switch mode {
	case ZeroTrust:
		for _, path := range minimalRuntimeReadPaths() {
			p.FS = append(p.FS, fsEntry{Path: path, Access: readFSAccess | execFSAccess})
		}
		p.FS = append(p.FS, fsEntry{Path: workspace, Access: readFSAccess})
	case ReadOnly:
		p.FS = append(p.FS, fsEntry{Path: "/", Access: readFSAccess | execFSAccess})
	case Write, Trusted:
		p.FS = append(p.FS,
			fsEntry{Path: "/", Access: readFSAccess | execFSAccess},
			fsEntry{Path: workspace, Access: readFSAccess | writeFSAccess | execFSAccess},
			fsEntry{Path: "/tmp", Access: readFSAccess | writeFSAccess | execFSAccess},
			fsEntry{Path: filepath.Join(workspace, ".git"), Access: readFSAccess},
			fsEntry{Path: filepath.Join(workspace, ".looprig"), Access: readFSAccess},
		)
	case testUnconfined:
		p.FS = append(p.FS, fsEntry{Path: "/", Access: readFSAccess | writeFSAccess | execFSAccess})
		p.Net.Open = true
		p.Env.Inherit = true
		p.Isolation = Unconfined
	}
	p.FS = append(p.FS, fsEntry{Path: nullDevicePath, Access: readFSAccess | writeFSAccess})
	if mode != testUnconfined {
		p.FS = append(p.FS, testSecretDenials()...)
	}
	if mode == Trusted {
		p.Net = effectiveNetPolicy{Loopback: true, Private: true, Ports: []uint16{443}, DNS: true}
	}
	for _, opt := range opts {
		opt(&p)
	}
	return p
}

func testSecretDenials() []fsEntry {
	paths := []string{"**/.env*", "/Library/Keychains"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, ".ssh"), filepath.Join(home, ".aws"),
			filepath.Join(home, ".gnupg"), filepath.Join(home, ".kube"),
		)
	}
	entries := make([]fsEntry, 0, len(paths))
	for _, path := range paths {
		entries = append(entries, fsEntry{Path: path, Access: denyFSAccess})
	}
	return entries
}

func WithWritable(path string) PolicyOption {
	return func(p *effectivePolicy) {
		path = filepath.Clean(path)
		p.FS = append(p.FS,
			fsEntry{Path: path, Access: readFSAccess | writeFSAccess | execFSAccess},
			fsEntry{Path: filepath.Join(path, ".git"), Access: readFSAccess},
			fsEntry{Path: filepath.Join(path, ".looprig"), Access: readFSAccess},
		)
	}
}

func WithDenyRead(path string) PolicyOption {
	return func(p *effectivePolicy) { p.FS = append(p.FS, fsEntry{Path: path, Access: denyFSAccess}) }
}

func WithoutSecretDenials() PolicyOption {
	return func(p *effectivePolicy) {
		kept := p.FS[:0]
		for _, entry := range p.FS {
			if entry.Access != denyFSAccess {
				kept = append(kept, entry)
			}
		}
		p.FS = kept
	}
}

func WithNet(net effectiveNetPolicy) PolicyOption {
	return func(p *effectivePolicy) { p.Net = net }
}

func WithEnv(env effectiveEnvPolicy) PolicyOption {
	return func(p *effectivePolicy) {
		p.Env.Inherit = p.Env.Inherit || env.Inherit
		p.Env.Allow = append(p.Env.Allow, env.Allow...)
		if p.Env.Set == nil {
			p.Env.Set = make(map[string]string)
		}
		for key, value := range env.Set {
			p.Env.Set[key] = value
		}
	}
}

func WithLimits(limits effectiveLimits) PolicyOption {
	return func(p *effectivePolicy) { p.limits = limits }
}

func WithAckUnconfined() PolicyOption { return func(*effectivePolicy) {} }

func newExecutorForEffectivePolicy(p effectivePolicy, opts ...ExecOption) (*Executor, error) {
	return newExecutorFromEffective(nil, p, opts...)
}

func containsStr(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
