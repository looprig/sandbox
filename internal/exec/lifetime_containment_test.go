package exec

import "testing"

func TestLifetimeContainmentString(t *testing.T) {
	cases := []struct {
		name string
		c    LifetimeContainment
		want string
	}{
		{"unspecified", LifetimeContainmentUnspecified, "unspecified"},
		{"enforced", LifetimeContainmentEnforced, "enforced"},
		{"best-effort", LifetimeContainmentBestEffort, "best-effort"},
		{"out-of-range", LifetimeContainment(99), "LifetimeContainment(99)"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.c.String(); got != tc.want {
				t.Errorf("LifetimeContainment(%d).String() = %q, want %q", uint8(tc.c), got, tc.want)
			}
		})
	}
}
