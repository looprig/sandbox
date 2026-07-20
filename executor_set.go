package sandbox

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

var (
	ErrExecutorLimit     = errors.New("sandbox: executor set limit reached")
	ErrExecutorSetClosed = errors.New("sandbox: executor set closed")
)

type executorSetConfig struct {
	scratchRoot string
	max         int
	execOptions []ExecOption
	route       *EgressRoute
}

// ExecutorSetOption configures executor ownership and resource limits.
type ExecutorSetOption func(*executorSetConfig)

// WithScratchRoot supplies the caller-owned parent for the set's owned child.
func WithScratchRoot(path string) ExecutorSetOption {
	return func(config *executorSetConfig) { config.scratchRoot = path }
}

// WithMaxExecutors sets the hard number of memoized executor identities.
func WithMaxExecutors(max int) ExecutorSetOption {
	return func(config *executorSetConfig) { config.max = max }
}

// WithEgressRoute configures the explicit route used by target-scoped grants.
func WithEgressRoute(route EgressRoute) ExecutorSetOption {
	return func(config *executorSetConfig) { config.route = &route }
}

func withExecutorSetExecOptions(options ...ExecOption) ExecutorSetOption {
	return func(config *executorSetConfig) {
		config.execOptions = append(config.execOptions, options...)
	}
}

// ExecutorSet owns per-key executors, their grant keys, and isolated HOME dirs.
type ExecutorSet struct {
	mu        sync.Mutex
	profile   *Profile
	ownedRoot string
	max       int
	options   []ExecOption
	route     *EgressRoute
	executors map[string]*Executor
	closed    bool
	closeErr  error
}

// NewExecutorSet creates one owner-only child beneath a required scratch root.
func NewExecutorSet(profile *Profile, options ...ExecutorSetOption) (*ExecutorSet, error) {
	if err := profile.validate(); err != nil {
		return nil, err
	}
	var config executorSetConfig
	for _, option := range options {
		if option != nil {
			option(&config)
		}
	}
	if config.scratchRoot == "" {
		return nil, errors.New("sandbox: executor set scratch root is required")
	}
	if config.max <= 0 {
		return nil, errors.New("sandbox: executor set maximum must be positive")
	}
	if config.route != nil {
		if err := config.route.validate(); err != nil {
			return nil, err
		}
	}
	scratch, err := canonicalRoot(config.scratchRoot)
	if err != nil {
		return nil, fmt.Errorf("sandbox: executor set scratch root: %w", err)
	}
	owned, err := os.MkdirTemp(scratch, "sandbox-executors-")
	if err != nil {
		return nil, fmt.Errorf("sandbox: create executor set root: %w", err)
	}
	if err := os.Chmod(owned, 0o700); err != nil {
		_ = os.RemoveAll(owned)
		return nil, fmt.Errorf("sandbox: secure executor set root: %w", err)
	}
	return &ExecutorSet{
		profile: profile, ownedRoot: owned, max: config.max,
		options:   append([]ExecOption(nil), config.execOptions...),
		route:     config.route,
		executors: make(map[string]*Executor),
	}, nil
}

// For memoizes an executor with a distinct grant key and child HOME per key.
func (set *ExecutorSet) For(key string) (*Executor, error) {
	if set == nil {
		return nil, ErrExecutorSetClosed
	}
	if key == "" || strings.TrimSpace(key) != key || strings.ContainsRune(key, '\x00') {
		return nil, errors.New("sandbox: invalid executor key")
	}
	set.mu.Lock()
	defer set.mu.Unlock()
	if set.closed {
		return nil, ErrExecutorSetClosed
	}
	if executor := set.executors[key]; executor != nil {
		return executor, nil
	}
	if len(set.executors) >= set.max {
		return nil, ErrExecutorLimit
	}

	policy, err := compileEffectivePolicy(set.profile)
	if err != nil {
		return nil, err
	}
	var home string
	var ownedHome bool
	if set.profile.home == RealHome {
		home, err = realHome()
	} else {
		home, err = os.MkdirTemp(set.ownedRoot, "home-")
		ownedHome = err == nil
		if err == nil {
			err = os.Chmod(home, 0o700)
		}
	}
	if err != nil {
		if ownedHome {
			_ = os.RemoveAll(home)
		}
		return nil, fmt.Errorf("sandbox: create executor HOME: %w", err)
	}
	tmp, err := os.MkdirTemp(set.ownedRoot, "tmp-")
	if err == nil {
		err = os.Chmod(tmp, 0o700)
	}
	if err != nil {
		if ownedHome {
			_ = os.RemoveAll(home)
		}
		if tmp != "" {
			_ = os.RemoveAll(tmp)
		}
		return nil, fmt.Errorf("sandbox: create executor TMPDIR: %w", err)
	}
	if policy.Env.Set == nil {
		policy.Env.Set = make(map[string]string)
	}
	policy.Env.Set["HOME"] = home
	policy.Env.Set["TMPDIR"] = tmp
	if ownedHome {
		policy.FS = append(policy.FS, fsEntry{Path: home, Access: readFSAccess | writeFSAccess | execFSAccess})
	}
	policy.FS = append(policy.FS, fsEntry{Path: tmp, Access: readFSAccess | writeFSAccess | execFSAccess})
	var proxy *egressProxy
	if set.route != nil {
		proxy, err = newEgressProxy(*set.route)
		if err != nil {
			if ownedHome {
				_ = os.RemoveAll(home)
			}
			_ = os.RemoveAll(tmp)
			return nil, err
		}
		_, portText, splitErr := net.SplitHostPort(proxy.Addr())
		port, parseErr := strconv.ParseUint(portText, 10, 16)
		if splitErr != nil || parseErr != nil || port == 0 {
			_ = proxy.Close()
			if ownedHome {
				_ = os.RemoveAll(home)
			}
			_ = os.RemoveAll(tmp)
			return nil, errors.New("sandbox: invalid egress proxy listener")
		}
		policy.Net = effectiveNetPolicy{ProxyPort: uint16(port)}
	}
	executor, err := newExecutorFromEffective(set.profile, policy, set.options...)
	if err != nil {
		if proxy != nil {
			_ = proxy.Close()
		}
		if ownedHome {
			_ = os.RemoveAll(home)
		}
		_ = os.RemoveAll(tmp)
		return nil, err
	}
	executor.home = home
	executor.tmp = tmp
	if proxy != nil {
		executor.proxy = proxy
		executor.routeFingerprint = set.route.Fingerprint()
		executor.guaranteeBits = executor.composeRouteGuarantees(executor.guaranteeBits)
	}
	set.executors[key] = executor
	return executor, nil
}

// Close revokes all executor grant keys and removes only the set-owned child.
func (set *ExecutorSet) Close() error {
	if set == nil {
		return nil
	}
	set.mu.Lock()
	if set.closed {
		err := set.closeErr
		set.mu.Unlock()
		return err
	}
	set.closed = true
	for _, executor := range set.executors {
		executor.revoke()
	}
	err := os.RemoveAll(set.ownedRoot)
	set.closeErr = err
	set.mu.Unlock()
	return err
}

func (e *Executor) revoke() {
	if e == nil {
		return
	}
	e.grantMu.Lock()
	e.closed = true
	for i := range e.grantKey {
		e.grantKey[i] = 0
	}
	e.usedGrants = nil
	proxy := e.proxy
	e.grantMu.Unlock()
	if proxy != nil {
		_ = proxy.Close()
	}
}
