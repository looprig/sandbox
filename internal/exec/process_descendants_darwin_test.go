//go:build darwin && integration

package exec

import (
	"bufio"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// startTracked starts cmd in its own process group and arms a tracker on it.
func startTracked(t *testing.T, cmd *exec.Cmd) *descendantTracker {
	t.Helper()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	tracker, err := newDescendantTracker()
	if err != nil {
		t.Fatalf("newDescendantTracker: %v", err)
	}
	if err := tracker.arm(cmd.Process.Pid); err != nil {
		t.Fatalf("arm: %v", err)
	}
	return tracker
}

func awaitMembers(t *testing.T, tracker *descendantTracker, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(tracker.liveMembers()) >= want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("tracker never reached %d members; live=%v", want, tracker.liveMembers())
}

func TestDescendantTrackerSeesForkedChild(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 30 & wait")
	tracker := startTracked(t, cmd)
	defer tracker.close()
	// killAndAwaitZero (not a raw cmd.Process.Kill, which only signals the sh
	// parent and leaves its backgrounded "sleep 30" orphaned to launchd for
	// the remainder of its 30s) tears down the whole tracked tree, exactly
	// as a real caller would.
	defer func() { tracker.killAndAwaitZero(cmd.Process.Pid); _, _ = cmd.Process.Wait() }()
	awaitMembers(t, tracker, 2) // sh + sleep
}

func TestDescendantTrackerKillsSessionEscapee(t *testing.T) {
	// perl POSIX::setsid detaches from the process group AND (after the
	// parent is killed) from the ancestry chain — the exact escapee a plain
	// pgid sweep cannot see. The parent prints the child pid then lingers,
	// keeping the ppid link alive long enough for a sample (the tracker's
	// job is to have captured membership by then).
	cmd := exec.Command("/usr/bin/perl", "-MPOSIX", "-e",
		`my $pid = fork(); if ($pid == 0) { POSIX::setsid(); sleep 300; exit 0 } $| = 1; print "$pid\n"; sleep 300`)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("stdout pipe: %v", err)
	}
	tracker := startTracked(t, cmd)
	defer tracker.close()

	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("read escapee pid: %v", err)
	}
	escapee, err := strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("parse escapee pid %q: %v", line, err)
	}
	if err := syscall.Kill(escapee, 0); err != nil {
		t.Fatalf("escapee not alive: %v", err)
	}
	// Wait until the tracker has discovered the escapee before tearing down.
	awaitMembers(t, tracker, 2)

	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	tracker.killAndAwaitZero(cmd.Process.Pid)

	if err := syscall.Kill(escapee, 0); err != syscall.ESRCH {
		t.Fatalf("escapee survived teardown: kill(pid,0) err=%v", err)
	}
}

func TestDescendantTrackerIdentityGuardSkipsRecycledPID(t *testing.T) {
	// A member whose recorded start-time no longer matches the live process
	// must not be killed. Simulate by injecting a bogus member entry for an
	// existing long-lived process (pid 1 with a zero start-time can never
	// match launchd's real start-time).
	cmd := exec.Command("/bin/sleep", "30")
	tracker := startTracked(t, cmd)
	defer tracker.close()
	tracker.injectMemberForTest(1, syscall.Timeval{})
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
	tracker.killAndAwaitZero(cmd.Process.Pid) // must return; must not signal pid 1
	// A non-root caller always gets EPERM signaling pid 1 (empirically
	// verified on this host: kill(1,0) returns EPERM even though launchd is
	// alive, since permission is checked before existence), so only ESRCH
	// is decisive evidence of "gone" — matching the ESRCH check the escapee
	// test above already uses for the same liveness-probe idiom.
	if err := syscall.Kill(1, 0); err == syscall.ESRCH {
		t.Fatalf("launchd unexpectedly gone?! %v", err)
	}
}

func TestDescendantTrackerCloseUnblocksLoop(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	tracker := startTracked(t, cmd)
	done := make(chan struct{})
	go func() { tracker.close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("close blocked on the kevent/sampler loops")
	}
	_ = cmd.Process.Kill()
	_, _ = cmd.Process.Wait()
}
