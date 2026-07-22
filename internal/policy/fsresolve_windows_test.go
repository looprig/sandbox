//go:build windows

package policy

import "testing"

func TestLiteralMatchesWindowsPathKeysIgnoreCaseAndSeparatorSpelling(t *testing.T) {
	tests := []struct {
		name   string
		entry  string
		target string
		exact  bool
	}{
		{name: "case insensitive tree", entry: `C:\Work\Repo`, target: `c:\work\repo\src\main.go`},
		{name: "slash and backslash equivalent", entry: `C:\work\repo`, target: `c:/work/repo/src/main.go`},
		{name: "case insensitive exact", entry: `C:\Work\Repo`, target: `c:/work/repo`, exact: true},
		{name: "drive root", entry: `C:\`, target: `c:/work/repo`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !LiteralMatches(test.entry, test.target, test.exact) {
				t.Fatalf("LiteralMatches(%q, %q, %t) = false, want true", test.entry, test.target, test.exact)
			}
		})
	}
}
