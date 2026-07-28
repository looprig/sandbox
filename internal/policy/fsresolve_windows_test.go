//go:build windows

package policy

import (
	"strings"
	"testing"
	"time"
)

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

func TestWindowsGlobCanonicalParserParity(t *testing.T) {
	tests := []struct {
		pattern string
		target  string
		want    bool
	}{
		{pattern: `C:\café\[à-ÿ].TXT`, target: `c:/CAFÉ/É.txt`, want: true},
		{pattern: `C:\δ\file[.txt`, target: `c:/Δ/FILE[.TXT`, want: true},
		{pattern: `C:/Mix/**/?.TXT`, target: `c:\mIX\one/two\λ.txt`, want: true},
		{pattern: `C:/Mix/*/?.TXT`, target: `c:\mIX\one/two\λ.txt`, want: false},
	}
	for _, test := range tests {
		got, valid := globMatches(test.pattern, test.target)
		if !valid {
			t.Fatalf("globMatches(%q, %q) unexpectedly invalid", test.pattern, test.target)
		}
		if got != test.want {
			t.Errorf("globMatches(%q, %q) = %t, want %t", test.pattern, test.target, got, test.want)
		}
	}
	for _, malformed := range []string{`C:\[ω-α].txt`, `C:\[z-a].txt`} {
		if matched, valid := globMatches(malformed, `C:\x.txt`); matched || valid {
			t.Errorf("globMatches(%q) = (%t, %t), want malformed fail-closed signal", malformed, matched, valid)
		}
	}
}

func TestWindowsGlobLongAdversarialInputIsBounded(t *testing.T) {
	const n = 700
	pattern := `C:\` + strings.Repeat(`*a`, n) + `b`
	target := `c:\` + strings.Repeat(`a`, n) + `c`
	started := time.Now()
	matched, valid := globMatches(pattern, target)
	if !valid || matched {
		t.Fatalf("globMatches(long adversarial input) = (%t, %t), want (false, true)", matched, valid)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("globMatches(long adversarial input) took %v; DP complexity regressed", elapsed)
	}
}

func BenchmarkWindowsGlobLongAdversarial(b *testing.B) {
	const n = 300
	pattern := `C:\` + strings.Repeat(`*a`, n) + `b`
	target := `c:\` + strings.Repeat(`a`, n) + `c`
	for i := 0; i < b.N; i++ {
		globMatches(pattern, target)
	}
}
