//go:build linux

package exec

import (
	"context"
	"strings"
	"testing"

	"github.com/looprig/sandbox/internal/linux"
	"github.com/looprig/sandbox/internal/policy"
)

// TestLinuxDevNullWritable proves the backend's fixed /dev/null grant
// (policy.NullDevicePath) is live on both Linux rungs: a confined shell can
// redirect into it and read from it. Landlock's descriptor-bound file rules once
// admitted only regular files, which dropped the grant for the character device,
// so `echo x > /dev/null` failed with EACCES in every confined spawn.
func TestLinuxDevNullWritable(t *testing.T) {
	requireLandlockV4(t)
	requireSeccomp(t)
	tests := []struct {
		name    string
		rung1   bool
		backend func() *linux.Backend
	}{
		{"rung2", false, linux.NewBackend},
		{"rung1", true, linux.NewBackendRung1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.rung1 {
				requireRung1Caps(t)
			}
			ws := carveoutWorkspace(t)
			// The production shape of the grant: exact, read+write.
			p := backendFixturePolicy(fixtureWorkspaceWrite, ws)
			p.FS = append(p.FS, policy.FSEntry{Path: policy.NullDevicePath, Access: policy.ReadAccess | policy.WriteAccess, Exact: true})
			e, err := newExecutorForEffectivePolicy(p, withBackend(tt.backend()))
			if err != nil {
				t.Fatalf("NewExecutor: %v", err)
			}
			out, code, err := e.RunCommand(context.Background(), ws,
				`echo x > /dev/null && echo WROTE; cat /dev/null && echo READ`)
			if err != nil || code != 0 {
				t.Fatalf("RunCommand: err=%v code=%d out=%q", err, code, out)
			}
			if s := string(out); !strings.Contains(s, "WROTE") || !strings.Contains(s, "READ") || strings.Contains(s, "denied") {
				t.Fatalf("/dev/null not usable at %s; out=%q", tt.name, s)
			}
		})
	}
}
