package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
)

const fixtureSharedTmpRoot = "/tmp"

// These fixtures preserve isolated backend mechanism shapes. They deliberately
// do not model a production profile or ExecutorSet-owned HOME/TMPDIR and must
// not be used for lifecycle, profile, or guarantee-contract tests.
type backendFixtureShape uint8

const (
	fixtureScopedRuntime backendFixtureShape = iota
	fixtureHostRead
	fixtureWorkspaceWrite
	fixtureBroadNetwork
	fixtureDirect
)

type backendFixtureOption func(*effectivePolicy)

func backendFixturePolicy(shape backendFixtureShape, workspace string, opts ...backendFixtureOption) effectivePolicy {
	workspace = filepath.Clean(workspace)
	p := effectivePolicy{
		Workspace: workspace,
		Env: effectiveEnvPolicy{Set: map[string]string{
			"TMPDIR": fixtureSharedTmpRoot,
		}},
	}
	switch shape {
	case fixtureScopedRuntime:
		p.FS = append(p.FS, minimalRuntimeEntries()...)
		p.FS = append(p.FS, fsEntry{Path: workspace, Access: readFSAccess})
	case fixtureHostRead:
		p.FS = append(p.FS, fsEntry{Path: "/", Access: readFSAccess | execFSAccess})
	case fixtureWorkspaceWrite, fixtureBroadNetwork:
		p.FS = append(p.FS,
			fsEntry{Path: "/", Access: readFSAccess | execFSAccess},
			fsEntry{Path: workspace, Access: readFSAccess | writeFSAccess | execFSAccess},
			fsEntry{Path: "/tmp", Access: readFSAccess | writeFSAccess | execFSAccess},
			fsEntry{Path: filepath.Join(workspace, ".git"), Access: readFSAccess, Denied: execFSAccess | writeFSAccess},
			fsEntry{Path: filepath.Join(workspace, ".looprig"), Access: readFSAccess, Denied: execFSAccess | writeFSAccess},
		)
	case fixtureDirect:
		p.FS = append(p.FS, fsEntry{Path: "/", Access: readFSAccess | writeFSAccess | execFSAccess})
		p.Net.Open = true
		p.Env.Inherit = true
		p.Isolation = Unconfined
	}
	p.FS = append(p.FS, fsEntry{Path: nullDevicePath, Access: readFSAccess | writeFSAccess})
	if shape != fixtureDirect {
		p.FS = append(p.FS, fixtureSecretDenials()...)
	}
	if shape == fixtureBroadNetwork {
		p.Net = effectiveNetPolicy{Loopback: true, Private: true, Ports: []uint16{443}, DNS: true}
	}
	for _, opt := range opts {
		opt(&p)
	}
	return p
}

func fixtureSecretDenials() []fsEntry {
	paths := []string{"**/.env*", "/Library/Keychains"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, ".ssh"), filepath.Join(home, ".aws"),
			filepath.Join(home, ".gnupg"), filepath.Join(home, ".kube"),
		)
	}
	entries := make([]fsEntry, 0, len(paths))
	for _, path := range paths {
		entries = append(entries, fsEntry{Path: path, Denied: allFSAccess})
	}
	return entries
}

func fixtureWithWritable(path string) backendFixtureOption {
	return func(p *effectivePolicy) {
		path = filepath.Clean(path)
		p.FS = append(p.FS,
			fsEntry{Path: path, Access: readFSAccess | writeFSAccess | execFSAccess},
			fsEntry{Path: filepath.Join(path, ".git"), Access: readFSAccess, Denied: execFSAccess | writeFSAccess},
			fsEntry{Path: filepath.Join(path, ".looprig"), Access: readFSAccess, Denied: execFSAccess | writeFSAccess},
		)
	}
}

func fixtureWithDenyRead(path string) backendFixtureOption {
	return func(p *effectivePolicy) {
		p.FS = append(p.FS, fsEntry{Path: path, Denied: readFSAccess | execFSAccess})
	}
}

func fixtureWithoutSecretDenials() backendFixtureOption {
	return func(p *effectivePolicy) {
		kept := p.FS[:0]
		for _, entry := range p.FS {
			if normalizedDenied(entry) == 0 {
				kept = append(kept, entry)
			}
		}
		p.FS = kept
	}
}

func fixtureWithNet(net effectiveNetPolicy) backendFixtureOption {
	return func(p *effectivePolicy) { p.Net = net }
}

func fixtureWithEnv(env effectiveEnvPolicy) backendFixtureOption {
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

func fixtureWithLimits(limits effectiveLimits) backendFixtureOption {
	return func(p *effectivePolicy) { p.limits = limits }
}

func fixtureWithAckUnconfined() backendFixtureOption { return func(*effectivePolicy) {} }

func newExecutorForEffectivePolicy(p effectivePolicy, opts ...ExecOption) (*Executor, error) {
	return newExecutorFromEffective(nil, p, opts...)
}

type testPassthroughBackend struct{}

func newTestPassthroughBackend() *testPassthroughBackend { return &testPassthroughBackend{} }

func (*testPassthroughBackend) compile(p effectivePolicy) (spawnSpec, CompileReport, uint8, uint64, error) {
	bits := uint64(0)
	if !p.Env.Inherit {
		bits = GuaranteeEnvScrub
	}
	return spawnSpec{wrap: func(_ string, argv []string) ([]string, func(*exec.Cmd), func()) {
		return argv, nil, nil
	}}, CompileReport{}, LevelNone, bits, nil
}

func containsStr(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
