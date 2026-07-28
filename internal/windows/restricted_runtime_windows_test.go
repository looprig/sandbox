//go:build windows

package windows

import (
	"sync"
	"sync/atomic"
	"testing"
)

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
