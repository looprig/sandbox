//go:build windows

package windows

import (
	"errors"
	"path/filepath"
	"strings"
	"sync"
)

var errRestrictedRuntimeRequired = errors.New("sandbox: restricted runtime coordinator is required")

type restrictedJournalOpener func(string) (*RestrictedJournal, RestrictedSweepReport, error)

type restrictedRuntimeState struct {
	once      sync.Once
	closeOnce sync.Once
	mu        sync.Mutex
	open      restrictedJournalOpener
	journal   *RestrictedJournal
	err       error
	closeErr  error
	closed    bool
}

func newRestrictedRuntimeState() restrictedRuntimeState {
	return restrictedRuntimeState{open: func(root string) (*RestrictedJournal, RestrictedSweepReport, error) {
		return OpenRestrictedJournalAndSweep(root, RestrictedACLCleaner{})
	}}
}

var restrictedRuntimeRegistry = struct {
	sync.Mutex
	entries map[string]*restrictedRuntimeRegistryEntry
}{entries: make(map[string]*restrictedRuntimeRegistryEntry)}

type restrictedRuntimeRegistryEntry struct {
	runtime *RestrictedRuntime
	refs    int
}

// AcquireRestrictedRuntime shares one lazy sweep coordinator between every
// live ExecutorSet in this process that uses the same stable root.
func AcquireRestrictedRuntime(scratchRoot string) (*RestrictedRuntime, func() error) {
	key := strings.ToUpper(filepath.Clean(scratchRoot))
	restrictedRuntimeRegistry.Lock()
	entry := restrictedRuntimeRegistry.entries[key]
	if entry == nil {
		entry = &restrictedRuntimeRegistryEntry{runtime: NewRestrictedRuntime(scratchRoot)}
		restrictedRuntimeRegistry.entries[key] = entry
	}
	entry.refs++
	restrictedRuntimeRegistry.Unlock()

	var once sync.Once
	var releaseErr error
	return entry.runtime, func() error {
		once.Do(func() {
			restrictedRuntimeRegistry.Lock()
			current := restrictedRuntimeRegistry.entries[key]
			if current != entry {
				restrictedRuntimeRegistry.Unlock()
				return
			}
			entry.refs--
			if entry.refs == 0 {
				delete(restrictedRuntimeRegistry.entries, key)
			}
			runtime := entry.runtime
			shouldClose := entry.refs == 0
			restrictedRuntimeRegistry.Unlock()
			if shouldClose {
				releaseErr = runtime.Close()
			}
		})
		return releaseErr
	}
}

func (runtime *RestrictedRuntime) closeRestrictedJournal() error {
	if runtime == nil {
		return nil
	}
	runtime.state.closeOnce.Do(func() {
		runtime.state.once.Do(func() {
			runtime.state.err = errors.New("sandbox: restricted runtime is closed")
		})
		runtime.state.mu.Lock()
		runtime.state.closed = true
		journal := runtime.state.journal
		runtime.state.mu.Unlock()
		if journal != nil {
			runtime.state.closeErr = journal.Close()
		}
	})
	return runtime.state.closeErr
}

func (runtime *RestrictedRuntime) restrictedJournal() (*RestrictedJournal, error) {
	if runtime == nil {
		return nil, errRestrictedRuntimeRequired
	}
	runtime.state.once.Do(func() {
		if runtime.state.open == nil {
			runtime.state.err = errRestrictedRuntimeRequired
			return
		}
		runtime.state.journal, _, runtime.state.err = runtime.state.open(runtime.scratchRoot)
	})
	runtime.state.mu.Lock()
	defer runtime.state.mu.Unlock()
	if runtime.state.closed {
		return nil, errors.New("sandbox: restricted runtime is closed")
	}
	return runtime.state.journal, runtime.state.err
}
