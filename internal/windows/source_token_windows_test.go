//go:build windows

package windows

import "testing"

func TestValidateDisposableSourceTokenShape(t *testing.T) {
	tests := []struct {
		name  string
		shape sourceTokenShape
		want  bool
	}{
		{name: "standard user", shape: sourceTokenShape{}, want: true},
		{name: "restricted standard user", shape: sourceTokenShape{restricted: true}},
		{name: "elevated administrator", shape: sourceTokenShape{elevated: true, administrator: true}},
		{name: "filtered administrator membership", shape: sourceTokenShape{administrator: true}},
		{name: "UAC split token", shape: sourceTokenShape{splitAdministrator: true}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateDisposableSourceTokenShape(test.shape)
			if (err == nil) != test.want {
				t.Fatalf("eligibility error = %v, want eligible %t", err, test.want)
			}
		})
	}
}
