package exec

import (
	"context"
	"errors"
	"testing"
	"time"
)

// Review L6: grant expiry was judged only against the wall clock
// (e.clock()). A token's validity window is a promise about elapsed time, so
// a wall-clock step BACKWARD after issuance (an NTP correction, a VM resume,
// an operator's date(1)) silently stretched it: a grant issued "for one
// minute" stayed valid for as long as the clock had been wound back. Issuance
// now also records a deadline on the executor's monotonic clock, and a grant
// must satisfy both: the signed wall-clock expiry (the caller's contract,
// unchanged) and the monotonic deadline (which no wall-clock step can move).

// fakeMonotonicForTest pins an executor's monotonic clock to *elapsed.
func fakeMonotonicForTest(executor *Executor, elapsed *time.Duration) {
	executor.grantMu.Lock()
	defer executor.grantMu.Unlock()
	executor.monotonic = func() time.Duration { return *elapsed }
}

func newGrantClockTestExecutor(t *testing.T, wall *time.Time) (*Executor, string) {
	t.Helper()
	workspace := mustCanonicalGrantRoot(t, t.TempDir())
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Deny, Command: Gated,
	})
	executor, err := newTestExecutor(profile,
		withBackend(&captureBackend{bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeEnvScrub}),
		withClock(func() time.Time { return *wall }))
	if err != nil {
		t.Fatal(err)
	}
	return executor, workspace
}

// TestGrantBackwardWallClockStepDoesNotExtendValidity: a one-minute grant,
// then the wall clock is wound back an hour while two real minutes pass. By
// the wall clock alone the token has 61 minutes left; it must be expired.
func TestGrantBackwardWallClockStepDoesNotExtendValidity(t *testing.T) {
	wall := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	var elapsed time.Duration
	executor, workspace := newGrantClockTestExecutor(t, &wall)
	fakeMonotonicForTest(executor, &elapsed)
	command := portableSuccessCommand()

	token := issueTestGrant(t, executor, wall, "exec-step", command, workspace,
		"command.execute", "", "command.start.v1", command)

	wall = wall.Add(-time.Hour)
	elapsed = 2 * time.Minute
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-step", workspace, command, []string{token}); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("grant after a backward wall-clock step past its monotonic deadline: err = %v, want ErrGrantExpired", err)
	}
	executor.grantMu.Lock()
	used := len(executor.usedGrants)
	executor.grantMu.Unlock()
	if used != 0 {
		t.Fatalf("an expired grant was consumed (%d used entries)", used)
	}
}

// TestGrantMonotonicDeadlinePositiveControl: the same backward step with
// only thirty real seconds elapsed leaves the token inside its window, so it
// runs — the monotonic deadline narrows nothing that time has not used up.
func TestGrantMonotonicDeadlinePositiveControl(t *testing.T) {
	wall := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	var elapsed time.Duration
	executor, workspace := newGrantClockTestExecutor(t, &wall)
	fakeMonotonicForTest(executor, &elapsed)
	command := portableSuccessCommand()

	token := issueTestGrant(t, executor, wall, "exec-ok", command, workspace,
		"command.execute", "", "command.start.v1", command)
	wall = wall.Add(-time.Hour)
	elapsed = 30 * time.Second
	if _, code, err := executor.RunCommandWithGrants(context.Background(), "exec-ok", workspace, command, []string{token}); err != nil || code != 0 {
		t.Fatalf("grant inside its monotonic window: code %d err %v, want success", code, err)
	}
}

// TestGrantForwardWallClockStepStillExpires: the signed wall-clock expiry is
// still enforced on its own; the monotonic deadline is an additional bound,
// not a replacement.
func TestGrantForwardWallClockStepStillExpires(t *testing.T) {
	wall := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	var elapsed time.Duration
	executor, workspace := newGrantClockTestExecutor(t, &wall)
	fakeMonotonicForTest(executor, &elapsed)
	command := portableSuccessCommand()

	token := issueTestGrant(t, executor, wall, "exec-fwd", command, workspace,
		"command.execute", "", "command.start.v1", command)
	wall = wall.Add(2 * time.Minute)
	elapsed = time.Second
	if _, _, err := executor.RunCommandWithGrants(context.Background(), "exec-fwd", workspace, command, []string{token}); !errors.Is(err, ErrGrantExpired) {
		t.Fatalf("grant past its signed wall-clock expiry: err = %v, want ErrGrantExpired", err)
	}
}
