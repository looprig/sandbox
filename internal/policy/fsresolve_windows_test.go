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
	if literalPathEqual(`C:\Straße`, `c:\STRAẞE`) {
		t.Fatal("ordinal comparison performed a linguistic sharp-s expansion")
	}
	if literalPathHasComponentPrefix(`c:\STRAẞE\child`, `C:\Straße`) {
		t.Fatal("ordinal component prefix performed a linguistic sharp-s expansion")
	}
	if literalPathHasComponentPrefix(`C:\Straße-other`, `c:\STRAẞE`) {
		t.Fatal("ordinal prefix crossed a component boundary")
	}
	if !literalVolumeEqual(`c:`, `C:`) || literalVolumeEqual(`C:`, `D:`) {
		t.Fatal("ordinal volume comparison contract violated")
	}
}

func TestWindowsGlobMatchingUsesOrdinalPathKeySemantics(t *testing.T) {
	entries := []FSEntry{{Path: `C:/work/**/.env*`, Denied: AllAccess}}
	for _, target := range []string{
		`C:\work\src\.env`,
		`C:/work/src/.env.local`,
		`c:\WORK/src\.ENV`,
		`C:\WoRk\SRC\.EnV.Local`,
	} {
		if got := ResolveFS(entries, target); got != DenyAccess {
			t.Fatalf("ResolveFS(%q) = %v, want deny", target, got)
		}
	}
	ordinary := append([]FSEntry{{Path: `C:\work`, Access: AllAccess}}, entries...)
	if access := ResolveFS(ordinary, `C:\work\src\env`); access != AllAccess {
		t.Fatalf("ordinary filename access = %v, want allow", access)
	}
}

func TestWindowsGlobClassesAndQuestionMarksIgnoreCaseButNotSeparators(t *testing.T) {
	entries := []FSEntry{
		{Path: `C:\work\[a-c]onfig\?.TXT`, Access: ReadAccess},
	}
	for _, target := range []string{`c:/WORK/Config/x.txt`, `C:\work\bONFIG\Z.TxT`} {
		if got := ResolveFS(entries, target); got != ReadAccess {
			t.Fatalf("ResolveFS(%q) = %v, want read", target, got)
		}
	}
	for _, target := range []string{`C:\work\config\deep\x.txt`, `C:\work\donfig\x.txt`} {
		if got := ResolveFS(entries, target); got != DenyAccess {
			t.Fatalf("ResolveFS(%q) = %v, want deny", target, got)
		}
	}
}
