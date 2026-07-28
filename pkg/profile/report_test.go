package profile

import "testing"

func TestReportStatusValues(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "enforced", got: StatusEnforced, want: "Enforced"},
		{name: "narrowed", got: StatusNarrowed, want: "narrowed"},
		{name: "unenforced", got: StatusUnenforced, want: "unenforced"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.got != test.want {
				t.Fatalf("status = %q, want %q", test.got, test.want)
			}
		})
	}
}
