//go:build linux

package sandbox

import "testing"

// TestSelectRung is the host-independent heart of the coverage: it feeds
// synthetic linuxCaps values into selectRung and asserts the chosen rung. The
// ladder (SPEC §7.2):
//
//   - rungOne  iff userns AND mountns AND netns AND landlockABI>=1 AND seccomp
//     (namespaces give the mount view + a netns for nftables; Landlock+seccomp
//     are still applied, so Landlock ABI>=1 and seccomp are required — but NOT
//     ABI>=4, because rung 1 scopes network with nftables, not Landlock TCP
//     rules, so it does not need the v4 TCP-rule feature).
//   - else rungTwo iff landlockABI>=4 AND seccomp (v4 is where Landlock TCP
//     port rules land — rung 2's port allowlist needs them).
//   - else rungNone.
func TestSelectRung(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		caps linuxCaps
		want rung
	}{
		{
			name: "all present, landlock v4 -> rungOne",
			caps: linuxCaps{landlockABI: 4, seccomp: true, userns: true, mountns: true, netns: true},
			want: rungOne,
		},
		{
			name: "all namespaces + seccomp + landlock v1 -> rungOne (rung 1 needs only ABI>=1)",
			caps: linuxCaps{landlockABI: 1, seccomp: true, userns: true, mountns: true, netns: true},
			want: rungOne,
		},
		{
			name: "all namespaces + seccomp + landlock v3 -> rungOne (ABI>=1 suffices for rung 1)",
			caps: linuxCaps{landlockABI: 3, seccomp: true, userns: true, mountns: true, netns: true},
			want: rungOne,
		},
		{
			name: "landlock v4 + seccomp, no namespaces -> rungTwo",
			caps: linuxCaps{landlockABI: 4, seccomp: true},
			want: rungTwo,
		},
		{
			name: "userns+mountns but no netns, landlock v4 + seccomp -> rungTwo (rung 1 needs netns)",
			caps: linuxCaps{landlockABI: 4, seccomp: true, userns: true, mountns: true},
			want: rungTwo,
		},
		{
			name: "userns+netns but no mountns, landlock v4 + seccomp -> rungTwo (rung 1 needs mountns)",
			caps: linuxCaps{landlockABI: 4, seccomp: true, userns: true, netns: true},
			want: rungTwo,
		},
		{
			name: "all namespaces + seccomp but landlock v3 (no netns) -> not applicable; here all ns false",
			caps: linuxCaps{landlockABI: 3, seccomp: true},
			want: rungNone,
		},
		{
			name: "landlock v4 present but seccomp missing -> rungNone (both rungs need seccomp)",
			caps: linuxCaps{landlockABI: 4},
			want: rungNone,
		},
		{
			name: "all namespaces + seccomp but landlock absent (ABI 0) -> rungNone (no FS enforcement)",
			caps: linuxCaps{landlockABI: 0, seccomp: true, userns: true, mountns: true, netns: true},
			want: rungNone,
		},
		{
			name: "all namespaces + landlock v4 but no seccomp -> rungNone",
			caps: linuxCaps{landlockABI: 4, userns: true, mountns: true, netns: true},
			want: rungNone,
		},
		{
			name: "namespaces present but netns missing and only landlock v4+seccomp -> rungTwo",
			caps: linuxCaps{landlockABI: 4, seccomp: true, userns: true, mountns: true, netns: false},
			want: rungTwo,
		},
		{
			name: "the real apparmor-restricted host: userns stripped, landlock v4 + seccomp -> rungTwo",
			caps: linuxCaps{landlockABI: 4, seccomp: true, userns: false, mountns: false, netns: false, cgroupV2: true, cgroupPids: "/sys/fs/cgroup/user.slice"},
			want: rungTwo,
		},
		{
			name: "zero value (nothing available) -> rungNone",
			caps: linuxCaps{},
			want: rungNone,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.caps.selectRung(); got != tt.want {
				t.Errorf("selectRung() = %v, want %v (caps=%+v)", got, tt.want, tt.caps)
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
	caps := probeLinuxCaps()
	t.Logf("probed host caps: %+v", caps)

	tests := []struct {
		name    string
		invalid bool // true when the invariant is VIOLATED
		reason  string
	}{
		{
			name:    "netns implies userns",
			invalid: caps.netns && !caps.userns,
			reason:  "netns reported available but userns is not (netns cannot exist without a usable userns)",
		},
		{
			name:    "mountns implies userns",
			invalid: caps.mountns && !caps.userns,
			reason:  "mountns reported available but userns is not (mountns cannot exist without a usable userns)",
		},
		{
			name:    "userns implies at least one of mountns/netns (userns is the usable-userns rollup)",
			invalid: caps.userns && !caps.mountns && !caps.netns,
			reason:  "userns reported usable but neither the mount nor the net capability probe succeeded",
		},
		{
			name:    "delegated pids ancestor implies cgroup v2 unified",
			invalid: caps.cgroupPids != "" && !caps.cgroupV2,
			reason:  "a delegated pids ancestor was resolved but cgroup v2 unified is not present",
		},
		{
			name:    "landlock ABI is non-negative",
			invalid: caps.landlockABI < 0,
			reason:  "landlock ABI must be 0 (unavailable) or a positive version",
		},
		{
			name:    "selectRung matches a manual re-derivation from the same fields",
			invalid: caps.selectRung() != rederiveRung(caps),
			reason:  "selectRung disagrees with an independent recomputation of the ladder",
		},
		{
			name:    "when userns is absent the host can never be rung 1",
			invalid: !caps.userns && caps.selectRung() == rungOne,
			reason:  "selectRung returned rungOne despite userns being unavailable",
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
// §7.2 ladder used only to cross-check selectRung against the same inputs. If
// selectRung and this ever disagree, one of them has drifted from the spec.
func rederiveRung(c linuxCaps) rung {
	switch {
	case c.userns && c.mountns && c.netns && c.landlockABI >= 1 && c.seccomp:
		return rungOne
	case c.landlockABI >= 4 && c.seccomp:
		return rungTwo
	default:
		return rungNone
	}
}

// TestProbeLinuxCapsReportsAbsence asserts that the REAL probe reports the rung
// implied by its own measured fields, and — crucially — that a rung is never
// claimed above what the measured capabilities support. This is written as a
// relationship (not a hardcoded rung) so it is correct on both an
// apparmor-restricted host (userns stripped -> rungTwo here) and a
// userns-enabled CI host (-> rungOne).
func TestProbeLinuxCapsReportsAbsence(t *testing.T) {
	t.Parallel()
	caps := probeLinuxCaps()
	got := caps.selectRung()
	t.Logf("host rung=%v caps=%+v", got, caps)

	switch got {
	case rungOne:
		if !(caps.userns && caps.mountns && caps.netns && caps.landlockABI >= 1 && caps.seccomp) {
			t.Fatalf("selectRung=rungOne but the rung-1 preconditions are not all met: caps=%+v", caps)
		}
	case rungTwo:
		if !(caps.landlockABI >= 4 && caps.seccomp) {
			t.Fatalf("selectRung=rungTwo but landlockABI>=4 && seccomp is not satisfied: caps=%+v", caps)
		}
		if caps.userns && caps.mountns && caps.netns && caps.landlockABI >= 1 {
			t.Fatalf("selectRung=rungTwo but all rung-1 preconditions are met (should be rungOne): caps=%+v", caps)
		}
	case rungNone:
		if caps.landlockABI >= 4 && caps.seccomp {
			t.Fatalf("selectRung=rungNone but landlockABI>=4 && seccomp holds (should be at least rungTwo): caps=%+v", caps)
		}
	default:
		t.Fatalf("selectRung returned an unknown rung: %v", got)
	}
}
