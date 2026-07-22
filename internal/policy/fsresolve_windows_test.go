//go:build windows

package policy

import "testing"

func TestLiteralMatchesWindowsPathKeysIgnoreCaseAndSeparatorSpelling(t *testing.T) {
	tests := []struct {
		name   string
		entry  string
		target string
		exact  bool
		want   bool
	}{
		{name: "case insensitive tree", entry: `C:\Work\Repo`, target: `c:\work\repo\src\main.go`, want: true},
		{name: "slash and backslash equivalent", entry: `C:\work\repo`, target: `c:/work/repo/src/main.go`, want: true},
		{name: "case insensitive exact", entry: `C:\Work\Repo`, target: `c:/work/repo`, exact: true, want: true},
		{name: "same drive root", entry: `C:\`, target: `c:/work/repo`, want: true},
		{name: "different drive root", entry: `C:\`, target: `D:\secret`, want: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := LiteralMatches(test.entry, test.target, test.exact); got != test.want {
				t.Fatalf("LiteralMatches(%q, %q, %t) = %t, want %t", test.entry, test.target, test.exact, got, test.want)
			}
		})
	}
}

func TestWindowsLiteralComparisonUsesOrdinalUnicodeSemantics(t *testing.T) {
	if !literalPathEqual(`C:\Straße`, `c:\STRAẞE`) {
		t.Fatal("ordinal case-insensitive equality rejected sharp-s case pair")
	}
	if !literalPathHasComponentPrefix(`c:\STRAẞE\child`, `C:\Straße`) {
		t.Fatal("ordinal component prefix rejected sharp-s case pair")
	}
	if literalPathHasComponentPrefix(`C:\Straße-other`, `c:\STRAẞE`) {
		t.Fatal("ordinal prefix crossed a component boundary")
	}
	if !literalVolumeEqual(`c:`, `C:`) || literalVolumeEqual(`C:`, `D:`) {
		t.Fatal("ordinal volume comparison contract violated")
	}
}
