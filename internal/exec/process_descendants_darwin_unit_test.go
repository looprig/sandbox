//go:build darwin

package exec

import (
	"math"
	"testing"
)

func TestDescendantTrackerArmRejectsInvalidPID(t *testing.T) {
	tracker := &descendantTracker{}
	for _, pid := range []int{0, -1, int(math.MaxInt32) + 1} {
		if err := tracker.arm(pid); err == nil {
			t.Fatalf("arm(%d) unexpectedly succeeded", pid)
		}
	}
}
