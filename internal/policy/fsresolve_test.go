package policy

import (
	"path/filepath"
	"runtime"
	"testing"
)

// Access-bit shorthands for readable test tables.
const (
	tRWX = ReadAccess | WriteAccess | ExecAccess
	tRX  = ReadAccess | ExecAccess
)

// accessString renders an FSAccess for legible failure messages.
func accessString(a FSAccess) string {
	if a == DenyAccess {
		return "Deny"
	}
	s := ""
	if a&ReadAccess != 0 {
		s += "R"
	}
	if a&WriteAccess != 0 {
		s += "W"
	}
	if a&ExecAccess != 0 {
		s += "X"
	}
	return s
}

// TestResolve exercises the SPEC §5.1 precedence model: fail-closed default,
// longest-match allow, the read-only carveout inside a writable root, secret and
// glob denies as hard overrides, and path-boundary matching.
func TestResolve(t *testing.T) {
	const ws = "/work/ws"

	tests := []struct {
		name    string
		entries []FSEntry
		path    string
		want    FSAccess
	}{
		{
			// 1. Empty policy denies everything (fail-closed).
			name:    "empty entries fail closed",
			entries: nil,
			path:    "/anything/at/all",
			want:    DenyAccess,
		},
		{
			// 2. Broad read root matches any path.
			name:    "root broad read matches everything",
			entries: []FSEntry{{"/", tRX, 0, false, false}},
			path:    "/usr/bin/sh",
			want:    tRX,
		},
		{
			// 3. Longest allow wins: writable root beats the broad read.
			name:    "writable root beats broad read",
			entries: []FSEntry{{"/", tRX, 0, false, false}, {ws, tRWX, 0, false, false}},
			path:    ws + "/foo",
			want:    tRWX,
		},
		{
			name:    "outside writable root falls back to broad read",
			entries: []FSEntry{{"/", tRX, 0, false, false}, {ws, tRWX, 0, false, false}},
			path:    "/etc/hosts",
			want:    tRX,
		},
		{
			// 4. Carveout: the longer allow (.git, read-only) beats the writable
			// root it sits inside.
			name:    "carveout git dir is read-only inside writable root",
			entries: []FSEntry{{ws, tRWX, 0, false, false}, {ws + "/.git", ReadAccess, ExecAccess | WriteAccess, false, false}},
			path:    ws + "/.git/config",
			want:    ReadAccess,
		},
		{
			name:    "carveout sibling stays writable",
			entries: []FSEntry{{ws, tRWX, 0, false, false}, {ws + "/.git", ReadAccess, ExecAccess | WriteAccess, false, false}},
			path:    ws + "/src/a.go",
			want:    tRWX,
		},
		{
			// 5. Secret deny wins over the broad read that also matches.
			name:    "secret deny under broad read",
			entries: []FSEntry{{"/", tRX, 0, false, false}, {"/home/u/.ssh", DenyAccess, 0, false, false}},
			path:    "/home/u/.ssh/id_rsa",
			want:    DenyAccess,
		},
		{
			name:    "non-secret sibling keeps broad read",
			entries: []FSEntry{{"/", tRX, 0, false, false}, {"/home/u/.ssh", DenyAccess, 0, false, false}},
			path:    "/home/u/.bashrc",
			want:    tRX,
		},
		{
			// 6. Glob deny is a hard override even inside a writable root.
			name:    "glob deny overrides writable root .env",
			entries: []FSEntry{{ws, tRWX, 0, false, false}, {"**/.env*", DenyAccess, 0, false, false}},
			path:    ws + "/.env",
			want:    DenyAccess,
		},
		{
			name:    "glob deny overrides nested .env.local",
			entries: []FSEntry{{ws, tRWX, 0, false, false}, {"**/.env*", DenyAccess, 0, false, false}},
			path:    ws + "/sub/.env.local",
			want:    DenyAccess,
		},
		{
			name:    "glob deny matches at filesystem root",
			entries: []FSEntry{{"/", tRX, 0, false, false}, {"**/.env*", DenyAccess, 0, false, false}},
			path:    "/.env",
			want:    DenyAccess,
		},
		{
			name:    "glob deny leaves ordinary file writable",
			entries: []FSEntry{{ws, tRWX, 0, false, false}, {"**/.env*", DenyAccess, 0, false, false}},
			path:    ws + "/main.go",
			want:    tRWX,
		},
		{
			name:    "glob deny requires the dot: env has none",
			entries: []FSEntry{{ws, tRWX, 0, false, false}, {"**/.env*", DenyAccess, 0, false, false}},
			path:    ws + "/env",
			want:    tRWX,
		},
		{
			name:    "glob deny does not match notenv",
			entries: []FSEntry{{ws, tRWX, 0, false, false}, {"**/.env*", DenyAccess, 0, false, false}},
			path:    ws + "/notenv",
			want:    tRWX,
		},
		{
			// 7. Path boundary: prefix that is not a path segment must not match.
			name:    "path boundary rejects repository under repo",
			entries: []FSEntry{{"/work/repo", tRWX, 0, false, false}},
			path:    "/work/repository",
			want:    DenyAccess,
		},
		{
			name:    "path boundary accepts nested under repo",
			entries: []FSEntry{{"/work/repo", tRWX, 0, false, false}},
			path:    "/work/repo/src",
			want:    tRWX,
		},
		{
			// 8. Exact match returns the entry's access.
			name:    "exact match returns entry access",
			entries: []FSEntry{{"/work/repo", tRWX, 0, false, false}},
			path:    "/work/repo",
			want:    tRWX,
		},
		{
			// 9. A more-specific allow overrides a broader root deny.
			name:    "more specific allow overrides broad deny",
			entries: []FSEntry{{ws + "/secret", tRWX, 0, false, false}, {ws, DenyAccess, 0, false, false}},
			path:    ws + "/secret/key",
			want:    tRWX,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveFS(tt.entries, tt.path)
			if got != tt.want {
				t.Errorf("ResolveFS(%v, %q) = %s, want %s",
					tt.entries, tt.path, accessString(got), accessString(tt.want))
			}
		})
	}
}

// TestResolveTieUnion pins the rule 2 tie-break: two allow entries with the same
// specificity union their access bits.
func TestResolveTieUnion(t *testing.T) {
	entries := []FSEntry{
		{"/work/ws", ReadAccess, 0, false, false},
		{"/work/ws", WriteAccess | ExecAccess, 0, false, false},
	}
	got := ResolveFS(entries, "/work/ws/file")
	want := ReadAccess | WriteAccess | ExecAccess
	if got != want {
		t.Errorf("union tie = %s, want %s", accessString(got), accessString(want))
	}
}

// TestResolveCanonicalizesTarget confirms the target path is cleaned before
// matching, so lexical noise resolves the same as its canonical form.
func TestResolveCanonicalizesTarget(t *testing.T) {
	entries := []FSEntry{{"/work/ws", tRWX, 0, false, false}}
	if got := ResolveFS(entries, "/work/ws/./src/../a.go"); got != tRWX {
		t.Errorf("ResolveFS on noisy path = %s, want RWX", accessString(got))
	}
}

func TestLiteralMatchesUnixPathKeysAreByteAndSeparatorSensitive(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix path-key semantics")
	}
	tests := []struct {
		name   string
		entry  string
		target string
	}{
		{name: "case variant", entry: "/work/Repo", target: "/work/repo/file"},
		{name: "backslash is not separator", entry: "/work/repo", target: `/work/repo\\file`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if LiteralMatches(test.entry, test.target, false) {
				t.Fatalf("LiteralMatches(%q, %q, false) = true, want false", test.entry, test.target)
			}
		})
	}
}

func TestVolumeRootMatchingKeysDoNotCrossVolumes(t *testing.T) {
	if !rootMatchesVolume("C:", "C:") {
		t.Fatal("same-volume root did not match")
	}
	if rootMatchesVolume("C:", "D:") {
		t.Fatal("cross-volume root matched")
	}
}

// TestResolveMalformedGlob pins the fail-closed contract for uncompilable glob
// patterns. "/data/[z-a].secret" contains a bracket metacharacter (so it is
// treated as a glob) but translates to an invalid regexp character-class range,
// so it cannot compile. A malformed DENY glob must still deny (over-deny), and a
// malformed ALLOW glob must grant nothing (under-grant) — fail closed both ways.
func TestResolveMalformedGlob(t *testing.T) {
	const bad = "/data/[z-a].secret"

	// (a) The critical case: a malformed deny glob must still deny.
	denyEntries := []FSEntry{{"/", tRX, 0, false, false}, {bad, DenyAccess, 0, false, false}}
	if got := ResolveFS(denyEntries, "/data/x.secret"); got != DenyAccess {
		t.Errorf("malformed deny glob: ResolveFS = %s, want Deny (fail closed)", accessString(got))
	}

	// (b) A malformed allow glob grants nothing.
	allowEntries := []FSEntry{{bad, tRWX, 0, false, false}}
	if got := ResolveFS(allowEntries, "/data/x.secret"); got != DenyAccess {
		t.Errorf("malformed allow glob: ResolveFS = %s, want Deny (grants nothing)", accessString(got))
	}
}

func TestGlobRegexpUnicodeAndUnmatchedBracket(t *testing.T) {
	tests := []struct {
		pattern string
		target  string
		want    bool
	}{
		{pattern: `/data/café.txt`, target: `/data/café.txt`, want: true},
		{pattern: `/data/[α-ω].txt`, target: `/data/λ.txt`, want: true},
		{pattern: `/data/[α-ω].txt`, target: `/data/A.txt`, want: false},
		{pattern: `/data/name[.txt`, target: `/data/name[.txt`, want: true},
		{pattern: `/data/name[.txt`, target: `/data/nameX.txt`, want: false},
	}
	for _, test := range tests {
		re := GlobRegexp(test.pattern)
		if re == nil {
			t.Fatalf("GlobRegexp(%q) unexpectedly rejected", test.pattern)
		}
		if got := re.MatchString(globPathKey(test.target)); got != test.want {
			t.Errorf("GlobRegexp(%q).MatchString(%q) = %t, want %t", test.pattern, test.target, got, test.want)
		}
	}
	for _, malformed := range []string{`/data/[z-a].txt`, `/data/[ω-α].txt`} {
		if GlobRegexp(malformed) != nil {
			t.Errorf("GlobRegexp(%q) accepted reversed class", malformed)
		}
	}
}

// TestResolveGlobBranches exercises the "?" single-char and "[...]"/"[!...]"
// bracket-class glob branches, plus the allow-glob specificity ranking against a
// literal (tie-union and longer-prefix win).
func TestResolveGlobBranches(t *testing.T) {
	tests := []struct {
		name    string
		entries []FSEntry
		path    string
		want    FSAccess
	}{
		{
			name:    "? matches a single char",
			entries: []FSEntry{{"/work/?.txt", tRWX, 0, false, false}},
			path:    "/work/a.txt",
			want:    tRWX,
		},
		{
			name:    "? does not span two chars",
			entries: []FSEntry{{"/work/?.txt", tRWX, 0, false, false}},
			path:    "/work/ab.txt",
			want:    DenyAccess,
		},
		{
			name:    "bracket class matches a member",
			entries: []FSEntry{{"/data/[abc].log", tRWX, 0, false, false}},
			path:    "/data/b.log",
			want:    tRWX,
		},
		{
			name:    "bracket class rejects a non-member",
			entries: []FSEntry{{"/data/[abc].log", tRWX, 0, false, false}},
			path:    "/data/d.log",
			want:    DenyAccess,
		},
		{
			name:    "negated bracket class matches outside the set",
			entries: []FSEntry{{"/data/[!x].log", tRWX, 0, false, false}},
			path:    "/data/a.log",
			want:    tRWX,
		},
		{
			name:    "negated bracket class rejects a member",
			entries: []FSEntry{{"/data/[!x].log", tRWX, 0, false, false}},
			path:    "/data/x.log",
			want:    DenyAccess,
		},
		{
			// Equal literal-prefix specificity: glob and literal union.
			name:    "allow glob ties with literal and unions bits",
			entries: []FSEntry{{"/work", ReadAccess, 0, false, false}, {"/work/*.go", WriteAccess, 0, false, false}},
			path:    "/work/main.go",
			want:    ReadAccess | WriteAccess,
		},
		{
			// Longer literal prefix: the glob allow beats the shorter literal.
			name:    "allow glob with longer prefix beats literal",
			entries: []FSEntry{{"/work", ReadAccess, 0, false, false}, {"/work/sub/*", WriteAccess, 0, false, false}},
			path:    "/work/sub/x",
			want:    ReadAccess | WriteAccess,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ResolveFS(tt.entries, tt.path); got != tt.want {
				t.Errorf("ResolveFS(%v, %q) = %s, want %s",
					tt.entries, tt.path, accessString(got), accessString(tt.want))
			}
		})
	}
}

// TestResolveWithBackendFixture feeds an internal mechanism fixture through the
// resolver, proving its emission and precedence agree end to end.
func TestResolveWithBackendFixture(t *testing.T) {
	const ws = "/work/ws"
	fs := workspaceWriteFixtureFS(ws)

	cases := []struct {
		path string
		want FSAccess
	}{
		{filepath.Join(ws, "main.go"), tRWX},              // workspace file: writable
		{filepath.Join(ws, ".git", "config"), ReadAccess}, // carveout: read-only
		{filepath.Join(ws, ".env"), DenyAccess},           // secret glob: denied
		{"/etc/hosts", tRX},                               // broad host read
	}
	for _, c := range cases {
		if got := ResolveFS(fs, c.path); got != c.want {
			t.Errorf("ResolveFS(backendFixturePolicy(fixtureWorkspaceWrite,%q).FS, %q) = %s, want %s",
				ws, c.path, accessString(got), accessString(c.want))
		}
	}
}

func TestResolveDistinguishesExactPathFromRecursiveTree(t *testing.T) {
	const target = "/work/ws/generated"
	tests := []struct {
		name  string
		entry FSEntry
		path  string
		want  FSAccess
	}{
		{name: "exact grants target", entry: FSEntry{Path: target, Access: WriteAccess, Exact: true}, path: target, want: WriteAccess},
		{name: "exact does not grant child", entry: FSEntry{Path: target, Access: WriteAccess, Exact: true}, path: target + "/child", want: DenyAccess},
		{name: "tree grants target", entry: FSEntry{Path: target, Access: WriteAccess}, path: target, want: WriteAccess},
		{name: "tree grants child", entry: FSEntry{Path: target, Access: WriteAccess}, path: target + "/child", want: WriteAccess},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ResolveFS([]FSEntry{test.entry}, test.path); got != test.want {
				t.Fatalf("ResolveFS() = %s, want %s", accessString(got), accessString(test.want))
			}
		})
	}
}

func TestResolveExactGrantOutranksTreeDenialOnlyAtTarget(t *testing.T) {
	const target = "/work/ws/target"
	entries := []FSEntry{
		{Path: target, Denied: WriteAccess},
		{Path: target, Access: WriteAccess, Exact: true},
	}
	if got := ResolveFS(entries, target); got != WriteAccess {
		t.Fatalf("exact target access = %s, want W", accessString(got))
	}
	if got := ResolveFS(entries, target+"/child"); got != DenyAccess {
		t.Fatalf("tree denial was opened below exact target: %s", accessString(got))
	}
}
