//go:build darwin

package exec

import (
	"errors"
	"math"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// descendantSampleInterval paces the kern.proc.all closure sampler. A
	// NOTE_FORK kevent on any member triggers an immediate extra sample.
	descendantSampleInterval = 100 * time.Millisecond
	// wakeIdent is the EVFILT_USER identity used to unblock the kevent loop
	// on close. Any constant works; it only has to be stable within one kq.
	wakeIdent = 1
	// launchdPID is pid 1 on darwin, the universal reparent target — see the
	// pid-1 guard in sample() below.
	launchdPID int32 = 1
)

// descendantForkNoteSupported is the starting assumption for every new
// tracker's forkNote field, based on a one-time empirical check during
// development (macOS 26.5.2 arm64, see the plan doc's Step 0): registering
// EVFILT_PROC NOTE_FORK|NOTE_EXIT on a live child returned a nil error, so
// trackers default to requesting NOTE_FORK acceleration. This is NOT
// re-verified at runtime and NOT shared state across trackers — it is a
// hardcoded starting value read once by newDescendantTracker. If the
// assumption is wrong on some other host/kernel, each tracker independently
// discovers ENOTSUP via its own first watch() call and degrades its own
// forkNote field to false permanently (see watch's ENOTSUP handling); that
// per-tracker discovery never writes back to this package variable.
var descendantForkNoteSupported = true

// descendantMember is one tracked process: pid plus the start-time identity
// that guards against pid reuse (a recycled pid is a different process and
// must never be signaled on this member's behalf).
type descendantMember struct {
	pid   int32
	start unix.Timeval
}

func setHas(set map[int32]struct{}, pid int32) bool {
	_, ok := set[pid]
	return ok
}

// descendantTracker follows one spawned process's fork tree, BEST-EFFORT.
//
// Darwin has no kernel fork-following: EVFILT_PROC NOTE_TRACK is rejected
// with ENOTSUP by XNU's filt_procattach (empirically verified 2026-08-06 on
// macOS 26.5.2; the constant exists in headers for FreeBSD compatibility
// only). So membership is discovered by sampling the process table
// (kern.proc.all) and growing the transitive closure rooted at the spawn —
// ppid-of-member or pgid-equals-member-pid joins — recorded permanently as
// (pid, start-time) so reparenting to launchd cannot erase a member. kqueue
// NOTE_FORK on members triggers immediate resampling to narrow the
// between-samples race; NOTE_EXIT retires members.
//
// NOTE_FORK itself was also empirically verified on this host (registering
// EVFILT_PROC with NOTE_FORK|NOTE_EXIT on a live child returned a nil error),
// so trackers start with forkNote true and request NOTE_FORK acceleration by
// default; watch degrades a tracker to NOTE_EXIT-only permanently the first
// time a registration comes back ENOTSUP.
//
// Accepted gaps (why this is LifetimeContainmentBestEffort, never a proof):
//   - a descendant that double-forks AND leaves the group between two
//     samples, unobserved, is never discovered;
//   - a member whose pid is recycled before retirement is skipped at kill
//     time by the start-time identity check (fail-safe direction: prefer
//     missing an escapee to killing an innocent process);
//   - arming happens just after cmd.Start(), so a child forked in that
//     window is caught only by the first sample's closure walk (via its
//     ppid/pgid link), not by kevents.
//
// pid 1 (launchd) is never treated as a closure anchor in sample() even if
// it is somehow present in members (see sample()'s ppid/pgid != 1 guard):
// once a member's parent dies and it reparents to launchd, its ppid becomes
// 1, and (as above) the ancestry link is already gone by design — treating
// launchd as an anchor would instead wrongly recruit every one of its real
// children (nearly every daemon on the system) into this run's tracked set.
type descendantTracker struct {
	mu       sync.Mutex
	kq       int
	members  map[int32]descendantMember
	watched  map[int32]bool // kevent registration succeeded for this member
	closed   bool
	resample chan struct{} // NOTE_FORK → immediate sample request
	stop     chan struct{}
	loops    sync.WaitGroup
	rootPID  int32
	forkNote bool // NOTE_FORK accepted by this kernel (degrades if not)
	armed    bool // arm() already called — see arm's single-call contract
}

func newDescendantTracker() (*descendantTracker, error) {
	kq, err := unix.Kqueue()
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(kq)
	tracker := &descendantTracker{
		kq:       kq,
		members:  make(map[int32]descendantMember),
		watched:  make(map[int32]bool),
		resample: make(chan struct{}, 1),
		stop:     make(chan struct{}),
		forkNote: descendantForkNoteSupported,
	}
	// Registering the wake event first means close() can always deliver it —
	// closing a kqueue fd does NOT unblock a parked Kevent call.
	_, err = unix.Kevent(kq, []unix.Kevent_t{{
		Ident: wakeIdent, Filter: unix.EVFILT_USER, Flags: unix.EV_ADD | unix.EV_CLEAR,
	}}, nil, nil)
	if err != nil {
		_ = unix.Close(kq)
		return nil, err
	}
	return tracker, nil
}

// arm begins tracking pid (which must already exist — call after cmd.Start())
// and starts the sampler and kevent loops. arm may be called at most once
// per tracker: a second call would start a second runKevents/runSampler
// goroutine pair sharing the same kq, and since a kqueue only delivers a
// given ready event to one blocked Kevent() caller, close()'s single
// NOTE_TRIGGER wake would then unblock only one of the two concurrent
// runKevents goroutines — the other parks forever and close()'s loops.Wait()
// deadlocks. Call arm again on an already-armed tracker and it returns an
// error instead of starting a second pair.
func (tracker *descendantTracker) arm(pid int) error {
	if tracker == nil {
		return errors.New("sandbox: nil descendant tracker")
	}
	if pid <= 0 || pid > math.MaxInt32 {
		return errors.New("sandbox: descendant tracker pid is out of range")
	}
	// #nosec G115 -- pid is constrained to the positive int32 range above.
	pid32 := int32(pid)
	tracker.mu.Lock()
	if tracker.armed {
		tracker.mu.Unlock()
		return errors.New("sandbox: descendant tracker already armed")
	}
	tracker.armed = true
	tracker.mu.Unlock()
	tracker.rootPID = pid32
	if start, ok := processStartTime(pid32); ok {
		tracker.mu.Lock()
		tracker.members[pid32] = descendantMember{pid: pid32, start: start}
		tracker.mu.Unlock()
	}
	tracker.watch(pid32)
	tracker.sample() // synchronous first sample: catch pre-arm forks now
	tracker.loops.Add(2)
	go tracker.runKevents()
	go tracker.runSampler()
	return nil
}

// watch registers NOTE_FORK|NOTE_EXIT (or NOTE_EXIT alone once a kernel has
// rejected NOTE_FORK) for pid. Failure is recorded, not fatal: sampling
// still covers the member.
func (tracker *descendantTracker) watch(pid int32) {
	if pid <= 0 {
		tracker.mu.Lock()
		tracker.watched[pid] = false
		tracker.mu.Unlock()
		return
	}
	fflags := uint32(unix.NOTE_EXIT)
	tracker.mu.Lock()
	forkNote := tracker.forkNote
	tracker.mu.Unlock()
	if forkNote {
		fflags |= unix.NOTE_FORK
	}
	// #nosec G115 -- non-positive PIDs return above, so this conversion is exact.
	ident := uint64(pid)
	_, err := unix.Kevent(tracker.kq, []unix.Kevent_t{{
		Ident:  ident,
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_CLEAR,
		Fflags: fflags,
	}}, nil, nil)
	if err == syscall.ENOTSUP && forkNote {
		// Kernel without NOTE_FORK: degrade to NOTE_EXIT-only permanently.
		tracker.mu.Lock()
		tracker.forkNote = false
		tracker.mu.Unlock()
		tracker.watch(pid)
		return
	}
	tracker.mu.Lock()
	tracker.watched[pid] = err == nil
	tracker.mu.Unlock()
}

func (tracker *descendantTracker) runKevents() {
	defer tracker.loops.Done()
	events := make([]unix.Kevent_t, 16)
	for {
		n, err := unix.Kevent(tracker.kq, nil, events, nil)
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return
		}
		for _, event := range events[:n] {
			switch {
			case event.Filter == unix.EVFILT_USER:
				return // close() woke us
			case event.Filter != unix.EVFILT_PROC:
				continue
			case event.Fflags&unix.NOTE_EXIT != 0:
				if event.Ident > math.MaxInt32 {
					continue
				}
				// #nosec G115 -- event identity is bounded to int32 immediately above.
				pid := int32(event.Ident)
				tracker.mu.Lock()
				delete(tracker.members, pid)
				delete(tracker.watched, pid)
				tracker.mu.Unlock()
			case event.Fflags&unix.NOTE_FORK != 0:
				select {
				case tracker.resample <- struct{}{}:
				default:
				}
			}
		}
	}
}

func (tracker *descendantTracker) runSampler() {
	defer tracker.loops.Done()
	ticker := time.NewTicker(descendantSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-tracker.stop:
			return
		case <-tracker.resample:
		case <-ticker.C:
		}
		tracker.sample()
	}
}

// sample grows the member set to the current transitive closure rooted at
// the spawn. Iterates to fixpoint within one snapshot so a whole fork chain
// appearing between samples is captured at once.
func (tracker *descendantTracker) sample() {
	procs, err := unix.SysctlKinfoProcSlice("kern.proc.all")
	if err != nil {
		return // sampling is best-effort; the next tick retries
	}
	tracker.mu.Lock()
	memberPIDs := make(map[int32]struct{}, len(tracker.members)+1)
	for pid := range tracker.members {
		memberPIDs[pid] = struct{}{}
	}
	memberPIDs[tracker.rootPID] = struct{}{} // root anchors even pre-membership
	tracker.mu.Unlock()

	var added []int32
	for {
		grew := false
		for i := range procs {
			pid := procs[i].Proc.P_pid
			if _, known := memberPIDs[pid]; known {
				continue
			}
			ppid, pgid := procs[i].Eproc.Ppid, procs[i].Eproc.Pgid
			// launchd (launchdPID) is the universal reparent target on
			// darwin: once a member's own parent dies, its ppid becomes
			// launchdPID — the tracker's doc comment already accounts for
			// this ("the ancestry link that let us find it is gone"). It
			// must never itself act as a closure anchor, or any process
			// whose ppid or pgid is launchdPID (i.e. nearly every daemon on
			// the system) would be wrongly recruited into this run's
			// tracked set — catastrophic if launchdPID is ever a member
			// (which legitimate discovery never produces, but a test's
			// injectMemberForTest seam can).
			parentKnown := ppid != launchdPID && setHas(memberPIDs, ppid)
			groupKnown := pgid != launchdPID && setHas(memberPIDs, pgid)
			if parentKnown || groupKnown {
				memberPIDs[pid] = struct{}{}
				added = append(added, pid)
				grew = true
			}
		}
		if !grew {
			break
		}
	}
	if len(added) == 0 {
		return
	}
	tracker.mu.Lock()
	for i := range procs {
		pid := procs[i].Proc.P_pid
		for _, addedPID := range added {
			if pid == addedPID {
				tracker.members[pid] = descendantMember{pid: pid, start: procs[i].Proc.P_starttime}
			}
		}
	}
	tracker.mu.Unlock()
	for _, pid := range added {
		tracker.watch(pid)
	}
}

// liveMembers returns the currently tracked members (tests + teardown).
func (tracker *descendantTracker) liveMembers() []descendantMember {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	members := make([]descendantMember, 0, len(tracker.members))
	for _, member := range tracker.members {
		members = append(members, member)
	}
	return members
}

// memberAlive reports whether member still refers to the same live,
// non-zombie process it was recorded as. Absent, recycled (start-time
// mismatch), or zombie ⇒ gone.
func memberAlive(member descendantMember) bool {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", int(member.pid))
	if err != nil || info == nil {
		return false
	}
	if info.Proc.P_starttime != member.start {
		return false // recycled pid — a different process; hands off
	}
	return info.Proc.P_stat != darwinZombieState
}

func processStartTime(pid int32) (unix.Timeval, bool) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", int(pid))
	if err != nil || info == nil {
		return unix.Timeval{}, false
	}
	return info.Proc.P_starttime, true
}

// killAndAwaitZero SIGKILLs the process group and every identity-verified
// live member, polling until the group is inactive and no member remains.
// One final sample runs first so descendants forked just before teardown are
// included. Zombies count as gone (their reaper is launchd once the tree's
// parents are dead; waiting on a corpse would stall the proof forever).
func (tracker *descendantTracker) killAndAwaitZero(pgid int) {
	tracker.sample()
	for {
		if pgid > 0 {
			reapProcessGroup(pgid)
		}
		groupActive := false
		if pgid > 0 {
			var err error
			groupActive, err = processGroupActive(pgid)
			if err != nil {
				groupActive = true // no evidence of absence — keep going
			}
		}
		anyMember := false
		for _, member := range tracker.liveMembers() {
			if !memberAlive(member) {
				tracker.mu.Lock()
				delete(tracker.members, member.pid)
				tracker.mu.Unlock()
				continue
			}
			anyMember = true
			_ = syscall.Kill(int(member.pid), syscall.SIGKILL)
		}
		if !groupActive && !anyMember {
			return
		}
		if pgid > 0 {
			_ = syscall.Kill(-pgid, syscall.SIGKILL)
		}
		time.Sleep(time.Millisecond)
	}
}

func (tracker *descendantTracker) close() {
	tracker.mu.Lock()
	if tracker.closed {
		tracker.mu.Unlock()
		return
	}
	tracker.closed = true
	tracker.mu.Unlock()
	close(tracker.stop)
	// Wake the kevent loop, join both loops, then release the kqueue.
	_, _ = unix.Kevent(tracker.kq, []unix.Kevent_t{{
		Ident: wakeIdent, Filter: unix.EVFILT_USER, Fflags: unix.NOTE_TRIGGER,
	}}, nil, nil)
	tracker.loops.Wait()
	_ = unix.Close(tracker.kq)
}
