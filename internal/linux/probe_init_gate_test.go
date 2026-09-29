//go:build linux

package linux

import "testing"

// TestProbeNamespaceCapRequiresInit pins the guard that keeps an Init-less
// process from re-executing itself. Without Init() the probe child cannot
// dispatch, so it would run the host program's own main() (or a test binary's
// whole suite), which can probe again: a self-replicating process tree on any
// host that permits unprivileged user namespaces. The probe must answer
// "absent" without spawning, and must still spawn once Init() has run.
//
// This package has no TestMain calling Init(), so initWasCalled starts false
// here. The test is not parallel because it swaps package state.
func TestProbeNamespaceCapRequiresInit(t *testing.T) {
	var spawns []string
	restoreProbe := runNamespaceProbe
	restoreInit := initWasCalled.Load()
	t.Cleanup(func() {
		runNamespaceProbe = restoreProbe
		initWasCalled.Store(restoreInit)
	})
	runNamespaceProbe = func(mode string) bool {
		spawns = append(spawns, mode)
		return true
	}

	initWasCalled.Store(false)
	for _, mode := range []string{nsProbeMount, nsProbeNet} {
		if probeNamespaceCap(mode) {
			t.Errorf("probeNamespaceCap(%q) without Init = true, want false", mode)
		}
	}
	if caps := ProbeCaps(); caps.Mountns || caps.Netns || caps.Userns {
		t.Errorf("ProbeCaps without Init = %+v, want no namespace capability", caps)
	}
	if len(spawns) != 0 {
		t.Fatalf("namespace probe spawned %v without Init; want no re-exec", spawns)
	}

	initWasCalled.Store(true)
	if !probeNamespaceCap(nsProbeMount) || !probeNamespaceCap(nsProbeNet) {
		t.Errorf("probeNamespaceCap after Init did not report the spawned probe's answer")
	}
	if want := []string{nsProbeMount, nsProbeNet}; len(spawns) != len(want) || spawns[0] != want[0] || spawns[1] != want[1] {
		t.Fatalf("namespace probe spawns after Init = %v, want %v", spawns, want)
	}
}
