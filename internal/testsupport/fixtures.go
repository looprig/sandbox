// Fixture policies for backend tests. These preserve isolated backend mechanism
// shapes: they deliberately do not model a production profile or an
// ExecutorSet-owned HOME/TMPDIR, and must not be used for lifecycle, profile,
// or guarantee-contract tests. They live here rather than in a _test.go file
// because the policy, darwin, linux, and executor suites all build on them.
package testsupport

import (
	"github.com/looprig/sandbox/internal/policy"
	"github.com/looprig/sandbox/pkg/profile"
	"os"
	"path/filepath"
)

const FixtureSharedTmpRoot = "/tmp"

// These fixtures preserve isolated backend mechanism shapes. They deliberately
// do not model a production profile or ExecutorSet-owned HOME/TMPDIR and must
// not be used for lifecycle, profile, or guarantee-contract tests.
type FixtureShape uint8

const (
	FixtureScopedRuntime FixtureShape = iota
	FixtureHostRead
	FixtureWorkspaceWrite
	FixtureBroadNetwork
	FixtureDirect
)

type FixtureOption func(*policy.Effective)

func FixturePolicy(shape FixtureShape, workspace string, opts ...FixtureOption) policy.Effective {
	workspace = filepath.Clean(workspace)
	p := policy.Effective{
		Workspace: workspace,
		Env: policy.EnvPolicy{Set: map[string]string{
			"TMPDIR": FixtureSharedTmpRoot,
		}},
	}
	switch shape {
	case FixtureScopedRuntime:
		p.FS = append(p.FS, policy.MinimalRuntimeEntries()...)
		p.FS = append(p.FS, policy.FSEntry{Path: workspace, Access: policy.ReadAccess})
	case FixtureHostRead:
		p.FS = append(p.FS, policy.FSEntry{Path: "/", Access: policy.ReadAccess | policy.ExecAccess})
	case FixtureWorkspaceWrite, FixtureBroadNetwork:
		p.FS = append(p.FS,
			policy.FSEntry{Path: "/", Access: policy.ReadAccess | policy.ExecAccess},
			policy.FSEntry{Path: workspace, Access: policy.ReadAccess | policy.WriteAccess | policy.ExecAccess},
			policy.FSEntry{Path: "/tmp", Access: policy.ReadAccess | policy.WriteAccess | policy.ExecAccess},
			policy.FSEntry{Path: filepath.Join(workspace, ".git"), Access: policy.ReadAccess, Denied: policy.ExecAccess | policy.WriteAccess},
			policy.FSEntry{Path: filepath.Join(workspace, ".looprig"), Access: policy.ReadAccess, Denied: policy.ExecAccess | policy.WriteAccess},
		)
	case FixtureDirect:
		p.FS = append(p.FS, policy.FSEntry{Path: "/", Access: policy.ReadAccess | policy.WriteAccess | policy.ExecAccess})
		p.Net.Open = true
		p.Env.Inherit = true
		p.Isolation = profile.Unconfined
	}
	p.FS = append(p.FS, policy.FSEntry{Path: policy.NullDevicePath, Access: policy.ReadAccess | policy.WriteAccess})
	if shape != FixtureDirect {
		p.FS = append(p.FS, FixtureSecretDenials()...)
	}
	if shape == FixtureBroadNetwork {
		p.Net = policy.NetPolicy{Loopback: true, Private: true, Ports: []uint16{443}, DNS: true}
	}
	for _, opt := range opts {
		opt(&p)
	}
	return p
}

func FixtureSecretDenials() []policy.FSEntry {
	paths := []string{"**/.env*", "/Library/Keychains"}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		paths = append(paths,
			filepath.Join(home, ".ssh"), filepath.Join(home, ".aws"),
			filepath.Join(home, ".gnupg"), filepath.Join(home, ".kube"),
		)
	}
	entries := make([]policy.FSEntry, 0, len(paths))
	for _, path := range paths {
		entries = append(entries, policy.FSEntry{Path: path, Denied: policy.AllAccess})
	}
	return entries
}

func FixtureWithWritable(path string) FixtureOption {
	return func(p *policy.Effective) {
		path = filepath.Clean(path)
		p.FS = append(p.FS,
			policy.FSEntry{Path: path, Access: policy.ReadAccess | policy.WriteAccess | policy.ExecAccess},
			policy.FSEntry{Path: filepath.Join(path, ".git"), Access: policy.ReadAccess, Denied: policy.ExecAccess | policy.WriteAccess},
			policy.FSEntry{Path: filepath.Join(path, ".looprig"), Access: policy.ReadAccess, Denied: policy.ExecAccess | policy.WriteAccess},
		)
	}
}

func FixtureWithDenyRead(path string) FixtureOption {
	return func(p *policy.Effective) {
		p.FS = append(p.FS, policy.FSEntry{Path: path, Denied: policy.ReadAccess | policy.ExecAccess})
	}
}

func FixtureWithoutSecretDenials() FixtureOption {
	return func(p *policy.Effective) {
		kept := p.FS[:0]
		for _, entry := range p.FS {
			if policy.NormalizedDenied(entry) == 0 {
				kept = append(kept, entry)
			}
		}
		p.FS = kept
	}
}

func FixtureWithNet(net policy.NetPolicy) FixtureOption {
	return func(p *policy.Effective) { p.Net = net }
}

func FixtureWithEnv(env policy.EnvPolicy) FixtureOption {
	return func(p *policy.Effective) {
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

func FixtureWithLimits(limits policy.Limits) FixtureOption {
	return func(p *policy.Effective) { p.Limits = limits }
}

func FixtureWithAckUnconfined() FixtureOption { return func(*policy.Effective) {} }
