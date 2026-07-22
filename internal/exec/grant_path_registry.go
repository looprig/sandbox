package exec

import (
	"errors"

	"github.com/looprig/sandbox/internal/policy"
)

type retainedPathHandle interface {
	Close() error
}

type noOpRetainedPathHandle struct{}

func (noOpRetainedPathHandle) Close() error { return nil }

type retainedGrantPath struct {
	binding         policy.PathBinding
	target          string
	exact           bool
	expiryUnixMilli int64
	handle          retainedPathHandle
}

type retainedGrantPaths map[[32]byte]retainedGrantPath

func (paths retainedGrantPaths) add(id [32]byte, entry retainedGrantPath) error {
	if entry.handle == nil || entry.target == "" || entry.binding.Identity == "" || entry.expiryUnixMilli == 0 {
		if entry.handle != nil {
			_ = entry.handle.Close()
		}
		return ErrGrantTargetChanged
	}
	if _, exists := paths[id]; exists {
		_ = entry.handle.Close()
		return ErrGrantReplay
	}
	paths[id] = entry
	return nil
}

func (paths retainedGrantPaths) take(id [32]byte, binding *policy.PathBinding, target string, exact bool, expiryUnixMilli int64) (retainedPathHandle, error) {
	entry, exists := paths[id]
	if !exists {
		return nil, ErrGrantReplay
	}
	if binding == nil || entry.target != target || entry.exact != exact || entry.expiryUnixMilli != expiryUnixMilli ||
		entry.binding.CanonicalPath != binding.CanonicalPath || entry.binding.ExistingPath != binding.ExistingPath ||
		entry.binding.Identity != binding.Identity {
		delete(paths, id)
		_ = entry.handle.Close()
		return nil, ErrGrantTargetChanged
	}
	delete(paths, id)
	return entry.handle, nil
}

func (paths retainedGrantPaths) prune(nowUnixMilli int64) {
	for id, entry := range paths {
		if entry.expiryUnixMilli < nowUnixMilli {
			delete(paths, id)
			_ = entry.handle.Close()
		}
	}
}

func (paths retainedGrantPaths) closeAll() error {
	var closeErr error
	for id, entry := range paths {
		delete(paths, id)
		closeErr = errors.Join(closeErr, entry.handle.Close())
	}
	return closeErr
}
