//go:build linux

package exec

import (
	"github.com/looprig/sandbox/internal/linux"
	"testing"
)

// TestSelectRung is the host-independent heart of the coverage: it feeds
// synthetic linux.Caps values into linux.SelectRung and asserts the chosen rung. The
// ladder (SPEC §7.2):
//
//   - linux.RungOne  iff Userns AND Mountns AND Netns AND LandlockABI>=1 AND Seccomp
//     (namespaces give the mount view + a Netns for nftables; Landlock+Seccomp
//     are still applied, so Landlock ABI>=1 and Seccomp are required — but NOT
//     ABI>=4, because rung 1 scopes network with nftables, not Landlock TCP
//     rules, so it does not need the v4 TCP-rule feature).
//   - else linux.RungTwo iff LandlockABI>=4 AND Seccomp (v4 is where Landlock TCP
//     port rules land — rung 2's port allowlist needs them).
//   - else linux.RungNone.
func TestSelectRung(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		caps linux.Caps
		want linux.Rung
	}{
		{
			name: "all present, landlock v4 -> linux.RungOne",
			caps: linux.Caps{LandlockABI: 4, Seccomp: true, Userns: true, Mountns: true, Netns: true},
			want: linux.RungOne,
		},
		{
			name: "all namespaces + Seccomp + landlock v1 -> linux.RungOne (linux.Rung 1 needs only ABI>=1)",
			caps: linux.Caps{LandlockABI: 1, Seccomp: true, Userns: true, Mountns: true, Netns: true},
			want: linux.RungOne,
		},
		{
			name: "all namespaces + Seccomp + landlock v3 -> linux.RungOne (ABI>=1 suffices for linux.Rung 1)",
			caps: linux.Caps{LandlockABI: 3, Seccomp: true, Userns: true, Mountns: true, Netns: true},
			want: linux.RungOne,
		},
		{
			name: "landlock v4 + Seccomp, no namespaces -> linux.RungTwo",
			caps: linux.Caps{LandlockABI: 4, Seccomp: true},
			want: linux.RungTwo,
		},
		{
			name: "Userns+Mountns but no Netns, landlock v4 + Seccomp -> linux.RungTwo (linux.Rung 1 needs Netns)",
			caps: linux.Caps{LandlockABI: 4, Seccomp: true, Userns: true, Mountns: true},
			want: linux.RungTwo,
		},
		{
			name: "Userns+Netns but no Mountns, landlock v4 + Seccomp -> linux.RungTwo (linux.Rung 1 needs Mountns)",
			caps: linux.Caps{LandlockABI: 4, Seccomp: true, Userns: true, Netns: true},
			want: linux.RungTwo,
		},
		{
			name: "all namespaces + Seccomp but landlock v3 (no Netns) -> not applicable; here all ns false",
			caps: linux.Caps{LandlockABI: 3, Seccomp: true},
			want: linux.RungNone,
		},
		{
			name: "landlock v4 present but Seccomp missing -> linux.RungNone (both rungs need Seccomp)",
			caps: linux.Caps{LandlockABI: 4},
			want: linux.RungNone,
		},
		{
			name: "all namespaces + Seccomp but landlock absent (ABI 0) -> linux.RungNone (no FS enforcement)",
			caps: linux.Caps{LandlockABI: 0, Seccomp: true, Userns: true, Mountns: true, Netns: true},
			want: linux.RungNone,
		},
		{
			name: "all namespaces + landlock v4 but no Seccomp -> linux.RungNone",
			caps: linux.Caps{LandlockABI: 4, Userns: true, Mountns: true, Netns: true},
			want: linux.RungNone,
		},
		{
			name: "namespaces present but Netns missing and only landlock v4+Seccomp -> linux.RungTwo",
			caps: linux.Caps{LandlockABI: 4, Seccomp: true, Userns: true, Mountns: true, Netns: false},
			want: linux.RungTwo,
		},
		{
			name: "the real apparmor-restricted host: Userns stripped, landlock v4 + Seccomp -> linux.RungTwo",
			caps: linux.Caps{LandlockABI: 4, Seccomp: true, Userns: false, Mountns: false, Netns: false, CgroupV2: true, CgroupPids: "/sys/fs/cgroup/user.slice"},
			want: linux.RungTwo,
		},
		{
			name: "zero value (nothing available) -> linux.RungNone",
			caps: linux.Caps{},
			want: linux.RungNone,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.caps.SelectRung(); got != tt.want {
				t.Errorf("linux.SelectRung() = %v, want %v (caps=%+v)", got, tt.want, tt.caps)
			}
		})
	}
}

// TestProbeLinuxCapsConsistency runs the REAL probe once and asserts the result
// is internally self-consistent — invariants that must hold on EVERY host,
// regardless of which mechanisms are actually present. It never skips: an
// unavailable mechanism must be REPORTED as absent (false/0/""), and that
// absence is itself an assertion target, not a reason to skip.
func TestProbeLinuxCapsConsistency(t *testing.T) {
	t.Parallel()
	caps := linux.ProbeCaps()
	t.Logf("probed host caps: %+v", caps)

	tests := []struct {
		name    string
		invalid bool // true when the invariant is VIOLATED
		reason  string
	}{
		{
			name:    "Netns implies Userns",
			invalid: caps.Netns && !caps.Userns,
			reason:  "Netns reported available but Userns is not (Netns cannot exist without a usable Userns)",
		},
		{
			name:    "Mountns implies Userns",
			invalid: caps.Mountns && !caps.Userns,
			reason:  "Mountns reported available but Userns is not (Mountns cannot exist without a usable Userns)",
		},
		{
			name:    "Userns implies at least one of Mountns/Netns (Userns is the usable-Userns rollup)",
			invalid: caps.Userns && !caps.Mountns && !caps.Netns,
			reason:  "Userns reported usable but neither the mount nor the net capability probe succeeded",
		},
		{
			name:    "delegated pids Ancestor implies cgroup v2 unified",
			invalid: caps.CgroupPids != "" && !caps.CgroupV2,
			reason:  "a delegated pids Ancestor was resolved but cgroup v2 unified is not present",
		},
		{
			name:    "landlock ABI is non-negative",
			invalid: caps.LandlockABI < 0,
			reason:  "landlock ABI must be 0 (unavailable) or a positive version",
		},
		{
			name:    "linux.SelectRung matches a manual re-derivation from the same fields",
			invalid: caps.SelectRung() != rederiveRung(caps),
			reason:  "linux.SelectRung disagrees with an independent recomputation of the ladder",
		},
		{
			name:    "when Userns is absent the host can never be linux.Rung 1",
			invalid: !caps.Userns && caps.SelectRung() == linux.RungOne,
			reason:  "linux.SelectRung returned linux.RungOne despite Userns being unavailable",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.invalid {
				t.Errorf("invariant violated: %s (caps=%+v)", tt.reason, caps)
			}
		})
	}
}

// rederiveRung is an independent, deliberately naive restatement of the SPEC
// §7.2 ladder used only to cross-check linux.SelectRung against the same inputs. If
// linux.SelectRung and this ever disagree, one of them has drifted from the spec.
func rederiveRung(c linux.Caps) linux.Rung {
	switch {
	case c.Userns && c.Mountns && c.Netns && c.LandlockABI >= 1 && c.Seccomp:
		return linux.RungOne
	case c.LandlockABI >= 4 && c.Seccomp:
		return linux.RungTwo
	default:
		return linux.RungNone
	}
}

// TestProbeLinuxCapsReportsAbsence asserts that the REAL probe reports the rung
// implied by its own measured fields, and — crucially — that a rung is never
// claimed above what the measured capabilities support. This is written as a
// relationship (not a hardcoded rung) so it is correct on both an
// apparmor-restricted host (Userns stripped -> linux.RungTwo here) and a
// Userns-enabled CI host (-> linux.RungOne).
func TestProbeLinuxCapsReportsAbsence(t *testing.T) {
	t.Parallel()
	caps := linux.ProbeCaps()
	got := caps.SelectRung()
	t.Logf("host linux.Rung=%v caps=%+v", got, caps)

	switch got {
	case linux.RungOne:
		if !(caps.Userns && caps.Mountns && caps.Netns && caps.LandlockABI >= 1 && caps.Seccomp) {
			t.Fatalf("linux.SelectRung=linux.RungOne but the linux.Rung-1 preconditions are not all met: caps=%+v", caps)
		}
	case linux.RungTwo:
		if !(caps.LandlockABI >= 4 && caps.Seccomp) {
			t.Fatalf("linux.SelectRung=linux.RungTwo but LandlockABI>=4 && Seccomp is not satisfied: caps=%+v", caps)
		}
		if caps.Userns && caps.Mountns && caps.Netns && caps.LandlockABI >= 1 {
			t.Fatalf("linux.SelectRung=linux.RungTwo but all linux.Rung-1 preconditions are met (should be linux.RungOne): caps=%+v", caps)
		}
	case linux.RungNone:
		if caps.LandlockABI >= 4 && caps.Seccomp {
			t.Fatalf("linux.SelectRung=linux.RungNone but LandlockABI>=4 && Seccomp holds (should be at least linux.RungTwo): caps=%+v", caps)
		}
	default:
		t.Fatalf("linux.SelectRung returned an unknown Rung: %v", got)
	}
}
