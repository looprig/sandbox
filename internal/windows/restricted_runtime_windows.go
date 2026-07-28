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
	once    sync.Once
	open    restrictedJournalOpener
	journal *RestrictedJournal
	err     error
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
func AcquireRestrictedRuntime(scratchRoot string) (*RestrictedRuntime, func()) {
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
	return entry.runtime, func() {
		once.Do(func() {
			restrictedRuntimeRegistry.Lock()
			defer restrictedRuntimeRegistry.Unlock()
			current := restrictedRuntimeRegistry.entries[key]
			if current != entry {
				return
			}
			entry.refs--
			if entry.refs == 0 {
				delete(restrictedRuntimeRegistry.entries, key)
				entry.runtime.closeRestrictedJournal()
			}
		})
	}
}

func (runtime *RestrictedRuntime) closeRestrictedJournal() {
	if runtime == nil {
		return
	}
	runtime.state.once.Do(func() {
		runtime.state.err = errors.New("sandbox: restricted runtime is closed")
	})
	if runtime.state.journal != nil {
		_ = runtime.state.journal.Close()
	}
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
	return runtime.state.journal, runtime.state.err
}
