package exec

import (
	"errors"
	"fmt"
	"github.com/looprig/sandbox/internal/policy"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/looprig/sandbox/pkg/network"
	"github.com/looprig/sandbox/pkg/profile"
)

var (
	ErrExecutorLimit     = errors.New("sandbox: executor set limit reached")
	ErrExecutorSetClosed = errors.New("sandbox: executor set closed")
)

type executorSetConfig struct {
	scratchRoot string
	max         int
	executor    executorConfig
	grantTTLSet bool
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

// WithGrantTTL sets the maximum lifetime of grants minted by every executor in
// the set. The duration must be positive when explicitly configured.
func WithGrantTTL(duration time.Duration) ExecutorSetOption {
	return func(config *executorSetConfig) {
		config.executor.grantTTL = duration
		config.grantTTLSet = true
	}
}

// WithEgressRoute configures the explicit route used by target-scoped grants.
func WithEgressRoute(route EgressRoute) ExecutorSetOption {
	return func(config *executorSetConfig) { config.route = &route }
}

// ExecutorSet owns per-key executors, their grant keys, and isolated HOME dirs.
type ExecutorSet struct {
	mu        sync.Mutex
	profile   *Profile
	settings  profile.Settings
	ownedRoot string
	max       int
	executor  executorConfig
	route     *EgressRoute
	executors map[string]*Executor
	lifecycle *executorLifecycle
	closed    bool
	closeErr  error
	closeDone chan struct{}
}

// NewExecutorSet creates one owner-only child beneath a required scratch root.
func NewExecutorSet(prof *Profile, options ...ExecutorSetOption) (*ExecutorSet, error) {
	if err := prof.Validate(); err != nil {
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
	if config.grantTTLSet && config.executor.grantTTL <= 0 {
		return nil, errors.New("sandbox: executor set grant TTL must be positive")
	}
	if config.route != nil {
		if err := config.route.Validate(); err != nil {
			return nil, err
		}
	}
	scratch, err := profile.CanonicalRoot(config.scratchRoot)
	if err != nil {
		return nil, fmt.Errorf("sandbox: executor set scratch root: %w", err)
	}
	owned, err := os.MkdirTemp(scratch, "sandbox-executors-")
	if err != nil {
		return nil, fmt.Errorf("sandbox: create executor set root: %w", err)
	}
	// #nosec G302 -- 0700 is correct for a DIRECTORY: G302 assumes a regular
	// file, but stripping the owner execute bit here would make the directory
	// non-traversable and unusable. 0700 is already owner-only.
	if err := os.Chmod(owned, 0o700); err != nil {
		_ = os.RemoveAll(owned)
		return nil, fmt.Errorf("sandbox: secure executor set root: %w", err)
	}
	return &ExecutorSet{
		profile: prof, settings: prof.Settings(), ownedRoot: owned, max: config.max,
		executor:  config.executor,
		route:     config.route,
		executors: make(map[string]*Executor),
		lifecycle: newExecutorLifecycle(),
		closeDone: make(chan struct{}),
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

	pol, err := policy.Compile(set.profile)
	if err != nil {
		return nil, err
	}
	var home string
	var ownedHome bool
	if set.settings.Home == RealHome {
		home, err = policy.RealHome()
	} else {
		home, err = os.MkdirTemp(set.ownedRoot, "home-")
		ownedHome = err == nil
		if err == nil {
			// #nosec G302 -- 0700 is correct for a DIRECTORY: G302 assumes a regular
			// file, but stripping the owner execute bit here would make the directory
			// non-traversable and unusable. 0700 is already owner-only.
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
		// #nosec G302 -- 0700 is correct for a DIRECTORY: G302 assumes a regular
		// file, but stripping the owner execute bit here would make the directory
		// non-traversable and unusable. 0700 is already owner-only.
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
	if pol.Env.Set == nil {
		pol.Env.Set = make(map[string]string)
	}
	pol.Env.Set["HOME"] = home
	pol.Env.Set["TMPDIR"] = tmp
	if ownedHome {
		pol.FS = append(pol.FS, policy.FSEntry{Path: home, Access: policy.ReadAccess | policy.WriteAccess | policy.ExecAccess})
	}
	pol.FS = append(pol.FS, policy.FSEntry{Path: tmp, Access: policy.ReadAccess | policy.WriteAccess | policy.ExecAccess})
	var proxy *network.Proxy
	if set.route != nil {
		proxy, err = network.NewProxy(*set.route)
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
		pol.Net = policy.NetPolicy{ProxyPort: uint16(port)}
	}
	config := set.executor
	config.lifecycle = set.lifecycle
	executor, err := newExecutorFromEffective(set.profile, pol, config)
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
		done := set.closeDone
		set.mu.Unlock()
		<-done
		set.mu.Lock()
		err := set.closeErr
		set.mu.Unlock()
		return err
	}
	set.closed = true
	executors := make([]*Executor, 0, len(set.executors))
	for _, executor := range set.executors {
		executors = append(executors, executor)
	}
	set.mu.Unlock()

	set.lifecycle.beginClose()
	for _, executor := range executors {
		executor.markClosed()
	}
	set.lifecycle.wait()
	var releaseErr error
	for _, executor := range executors {
		releaseErr = errors.Join(releaseErr, executor.releaseCompiledSpec())
	}
	for _, executor := range executors {
		executor.revokeResources()
	}
	err := errors.Join(releaseErr, os.RemoveAll(set.ownedRoot))

	set.mu.Lock()
	set.closeErr = err
	close(set.closeDone)
	set.mu.Unlock()
	return err
}

func (e *Executor) markClosed() {
	if e == nil {
		return
	}
	e.grantMu.Lock()
	e.closed = true
	e.grantMu.Unlock()
}

func (e *Executor) revokeResources() {
	if e == nil {
		return
	}
	e.grantMu.Lock()
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
