//go:build darwin

package exec

import (
	"math"
	"sort"
	"testing"

	"golang.org/x/sys/unix"
)

func TestDescendantTrackerArmRejectsInvalidPID(t *testing.T) {
	tracker := &descendantTracker{}
	for _, pid := range []int{0, -1, int(math.MaxInt32) + 1} {
		if err := tracker.arm(pid); err == nil {
			t.Fatalf("arm(%d) unexpectedly succeeded", pid)
		}
	}
}

// fakeProc fabricates one kern.proc.all row for absorb. The pids used below
// sit far above any real pid (kern.maxproc is a few thousand; pid_max is
// 99999), so watch's EVFILT_PROC registration for them fails harmlessly with
// ESRCH and nothing real is ever touched.
func fakeProc(pid, ppid, pgid int32, startSec int64) unix.KinfoProc {
	var proc unix.KinfoProc
	proc.Proc.P_pid = pid
	proc.Proc.P_starttime = unix.Timeval{Sec: startSec}
	proc.Eproc.Ppid = ppid
	proc.Eproc.Pgid = pgid
	return proc
}

// unarmedTrackerForTest builds a real tracker (so watch has a kqueue to
// register against) that never started its loops, and anchors it on rootPID
// with the given start-time identity.
func unarmedTrackerForTest(t *testing.T, rootPID int32, rootStart int64) *descendantTracker {
	t.Helper()
	tracker, err := newDescendantTracker()
	if err != nil {
		t.Fatalf("newDescendantTracker: %v", err)
	}
	t.Cleanup(tracker.close)
	tracker.rootPID = rootPID
	tracker.rootStart = unix.Timeval{Sec: rootStart}
	tracker.rootStartKnown = true
	tracker.members[rootPID] = descendantMember{pid: rootPID, start: tracker.rootStart}
	return tracker
}

func memberPIDs(tracker *descendantTracker) []int32 {
	var pids []int32
	for _, member := range tracker.liveMembers() {
		pids = append(pids, member.pid)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })
	return pids
}

func samePIDs(got, want []int32) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

// TestDescendantTrackerAbsorbFollowsVerifiedAnchors is the positive control:
// a root whose snapshot row still carries its recorded start time anchors
// its child, and the child (identified by this very snapshot) anchors the
// grandchild within the same pass.
func TestDescendantTrackerAbsorbFollowsVerifiedAnchors(t *testing.T) {
	tracker := unarmedTrackerForTest(t, 900001, 100)
	tracker.absorb([]unix.KinfoProc{
		fakeProc(900001, 1, 900001, 100), // root, same identity
		fakeProc(900002, 900001, 900001, 101),
		fakeProc(900003, 900002, 900003, 102), // own group, ppid link only
		fakeProc(900099, 77, 77, 50),          // unrelated
	})
	if got, want := memberPIDs(tracker), []int32{900001, 900002, 900003}; !samePIDs(got, want) {
		t.Fatalf("members = %v, want %v", got, want)
	}
}

// TestDescendantTrackerAbsorbRefusesRecycledRootPID is L3: the root has died
// and its pid now names an unrelated same-user process (different start
// time). That process's child carries the root's pid as its ppid and must
// NOT be adopted — teardown would otherwise SIGKILL it.
func TestDescendantTrackerAbsorbRefusesRecycledRootPID(t *testing.T) {
	tracker := unarmedTrackerForTest(t, 900001, 100)
	tracker.absorb([]unix.KinfoProc{
		fakeProc(900001, 1, 900001, 500),      // recycled: same pid, later start
		fakeProc(900010, 900001, 900001, 501), // the impostor's child
	})
	if got, want := memberPIDs(tracker), []int32{900001}; !samePIDs(got, want) {
		t.Fatalf("members = %v, want only the (stale) root %v: a recycled root pid adopted an unrelated child", got, want)
	}
}

// TestDescendantTrackerAbsorbRefusesRecycledMemberPID is L3 for an ordinary
// member: it was recorded with one start time, died, and its pid was reused.
func TestDescendantTrackerAbsorbRefusesRecycledMemberPID(t *testing.T) {
	tracker := unarmedTrackerForTest(t, 900001, 100)
	tracker.members[900002] = descendantMember{pid: 900002, start: unix.Timeval{Sec: 101}}
	tracker.absorb([]unix.KinfoProc{
		fakeProc(900001, 1, 900001, 100),
		fakeProc(900002, 1, 900002, 900),      // recycled member pid
		fakeProc(900020, 900002, 900002, 901), // child of the impostor, in its group
	})
	if got, want := memberPIDs(tracker), []int32{900001, 900002}; !samePIDs(got, want) {
		t.Fatalf("members = %v, want %v: a recycled member pid adopted an unrelated child", got, want)
	}
}

// TestDescendantTrackerAbsorbKeepsGroupOfAbsentAnchor: an anchor that has
// exited entirely (absent from the snapshot) can no longer be anyone's
// parent, but its process group can outlive it, and XNU never reissues a pid
// that is still a live pgid, so the group is still the run's own and its
// remaining processes are adopted through it.
func TestDescendantTrackerAbsorbKeepsGroupOfAbsentAnchor(t *testing.T) {
	tracker := unarmedTrackerForTest(t, 900001, 100)
	tracker.absorb([]unix.KinfoProc{
		// root absent: exited and reaped
		fakeProc(900030, 1, 900001, 103), // reparented to launchd, still in the run's group
	})
	if got, want := memberPIDs(tracker), []int32{900001, 900030}; !samePIDs(got, want) {
		t.Fatalf("members = %v, want %v: the absent root's surviving group must still be adopted", got, want)
	}
}

// TestDescendantTrackerAbsorbNeverAnchorsOnLaunchd keeps the launchd guard
// under the new identity rules: even a (test-injected) pid-1 member whose
// identity matches never recruits launchd's children.
func TestDescendantTrackerAbsorbNeverAnchorsOnLaunchd(t *testing.T) {
	tracker := unarmedTrackerForTest(t, 900001, 100)
	tracker.members[launchdPID] = descendantMember{pid: launchdPID, start: unix.Timeval{Sec: 1}}
	tracker.absorb([]unix.KinfoProc{
		fakeProc(launchdPID, 0, launchdPID, 1),
		fakeProc(900001, 1, 900001, 100),
		fakeProc(900040, launchdPID, launchdPID, 5), // a daemon
	})
	for _, pid := range memberPIDs(tracker) {
		if pid == 900040 {
			t.Fatal("launchd anchored a closure join")
		}
	}
}
