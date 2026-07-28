//go:build windows

package windows

import (
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDirectRestrictedRuntimeCloseOwnsOpenedJournal(t *testing.T) {
	runtime := NewRestrictedRuntime(t.TempDir())
	journal := &RestrictedJournal{}
	runtime.state.open = func(string) (*RestrictedJournal, RestrictedSweepReport, error) {
		return journal, RestrictedSweepReport{}, nil
	}
	if opened, err := runtime.restrictedJournal(); err != nil || opened != journal {
		t.Fatalf("open direct runtime = (%p, %v), want journal", opened, err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if !journal.closed {
		t.Fatal("direct runtime did not close its journal")
	}
	if opened, err := runtime.restrictedJournal(); err == nil || opened != nil {
		t.Fatalf("closed direct runtime reopened journal = (%p, %v)", opened, err)
	}
}

func TestRestrictedRuntimeRegistryDoesNotHoldGlobalLockWhileClosing(t *testing.T) {
	first, releaseFirst := AcquireRestrictedRuntime(filepath.Join(t.TempDir(), "first"))
	journal, err := OpenRestrictedJournal(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	first.state.open = func(string) (*RestrictedJournal, RestrictedSweepReport, error) {
		return journal, RestrictedSweepReport{}, nil
	}
	if _, err := first.restrictedJournal(); err != nil {
		t.Fatal(err)
	}
	if err := journal.beginOperation(); err != nil {
		t.Fatal(err)
	}
	operationEnded := false
	defer func() {
		if !operationEnded {
			journal.endOperation()
		}
		_ = journal.Close()
	}()

	releaseStarted := make(chan struct{})
	releaseDone := make(chan struct{})
	go func() {
		close(releaseStarted)
		releaseFirst()
		close(releaseDone)
	}()
	<-releaseStarted
	time.Sleep(25 * time.Millisecond)

	type acquiredRuntime struct {
		runtime *RestrictedRuntime
		release func()
	}
	unrelatedRoot := filepath.Join(t.TempDir(), "unrelated")
	acquired := make(chan acquiredRuntime, 1)
	go func() {
		runtime, release := AcquireRestrictedRuntime(unrelatedRoot)
		acquired <- acquiredRuntime{runtime: runtime, release: release}
	}()
	select {
	case result := <-acquired:
		if result.runtime == nil {
			t.Fatal("unrelated runtime acquisition returned nil")
		}
		result.release()
	case <-time.After(2 * time.Second):
		t.Fatal("unrelated runtime acquisition blocked behind another root's Close")
	}

	journal.endOperation()
	operationEnded = true
	select {
	case <-releaseDone:
	case <-time.After(2 * time.Second):
		t.Fatal("last release did not finish after active operation ended")
	}
}

func TestRestrictedRuntimeSharesSweepAcrossLiveSetsAndRecoversAfterLastRelease(t *testing.T) {
	root := t.TempDir()
	first, releaseFirst := AcquireRestrictedRuntime(root)
	second, releaseSecond := AcquireRestrictedRuntime(root)
	if first != second {
		t.Fatal("concurrent same-root ExecutorSets received different restricted runtimes")
	}

	var sweeps atomic.Int32
	liveACE := false
	first.state.open = func(string) (*RestrictedJournal, RestrictedSweepReport, error) {
		sweeps.Add(1)
		liveACE = false
		return &RestrictedJournal{}, RestrictedSweepReport{}, nil
	}
	if _, err := first.restrictedJournal(); err != nil {
		t.Fatalf("first executor journal: %v", err)
	}
	liveACE = true // executor A projects its live allow ACE after construction sweep
	if _, err := second.restrictedJournal(); err != nil {
		t.Fatalf("second executor journal: %v", err)
	}
	if !liveACE {
		t.Fatal("executor B swept executor A's live ACE")
	}
	if sweeps.Load() != 1 {
		t.Fatalf("live-set sweep calls = %d; want 1", sweeps.Load())
	}

	releaseFirst()
	third, releaseThird := AcquireRestrictedRuntime(root)
	if third != second {
		t.Fatal("runtime registry dropped a coordinator while one set remained live")
	}
	if _, err := third.restrictedJournal(); err != nil {
		t.Fatalf("third live set journal: %v", err)
	}
	if sweeps.Load() != 1 || !liveACE {
		t.Fatalf("third live set unexpectedly swept: sweeps=%d live=%v", sweeps.Load(), liveACE)
	}
	releaseSecond()
	releaseThird()
	if !first.state.journal.closed {
		t.Fatal("last runtime release did not close the retained journal roots")
	}

	next, releaseNext := AcquireRestrictedRuntime(root)
	t.Cleanup(releaseNext)
	if next == first {
		t.Fatal("new set after final release reused the retired coordinator")
	}
	next.state.open = func(string) (*RestrictedJournal, RestrictedSweepReport, error) {
		sweeps.Add(1)
		liveACE = false // abandoned record is recovered by the next owner
		return &RestrictedJournal{}, RestrictedSweepReport{Removed: 1}, nil
	}
	if _, err := next.restrictedJournal(); err != nil {
		t.Fatalf("next-set journal: %v", err)
	}
	if liveACE || sweeps.Load() != 2 {
		t.Fatalf("next set did not sweep abandoned state: sweeps=%d live=%v", sweeps.Load(), liveACE)
	}
}

func TestRestrictedRuntimeConcurrentAcquireUsesOneCoordinator(t *testing.T) {
	root := t.TempDir()
	const count = 16
	runtimes := make(chan *RestrictedRuntime, count)
	releases := make(chan func(), count)
	var group sync.WaitGroup
	for range count {
		group.Add(1)
		go func() {
			defer group.Done()
			runtime, release := AcquireRestrictedRuntime(root)
			runtimes <- runtime
			releases <- release
		}()
	}
	group.Wait()
	close(runtimes)
	close(releases)
	var want *RestrictedRuntime
	for runtime := range runtimes {
		if want == nil {
			want = runtime
		} else if runtime != want {
			t.Fatal("concurrent acquire returned multiple coordinators")
		}
	}
	for release := range releases {
		release()
	}
}
