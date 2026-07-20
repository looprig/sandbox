package sandbox

import (
	"path/filepath"
	"testing"
)

// Access-bit shorthands for readable test tables.
const (
	tRWX = readFSAccess | writeFSAccess | execFSAccess
	tRX  = readFSAccess | execFSAccess
)

// accessString renders an fsAccess for legible failure messages.
func accessString(a fsAccess) string {
	if a == denyFSAccess {
		return "Deny"
	}
	s := ""
	if a&readFSAccess != 0 {
		s += "R"
	}
	if a&writeFSAccess != 0 {
		s += "W"
	}
	if a&execFSAccess != 0 {
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
		entries []fsEntry
		path    string
		want    fsAccess
	}{
		{
			// 1. Empty policy denies everything (fail-closed).
			name:    "empty entries fail closed",
			entries: nil,
			path:    "/anything/at/all",
			want:    denyFSAccess,
		},
		{
			// 2. Broad read root matches any path.
			name:    "root broad read matches everything",
			entries: []fsEntry{{"/", tRX, 0, false, false}},
			path:    "/usr/bin/sh",
			want:    tRX,
		},
		{
			// 3. Longest allow wins: writable root beats the broad read.
			name:    "writable root beats broad read",
			entries: []fsEntry{{"/", tRX, 0, false, false}, {ws, tRWX, 0, false, false}},
			path:    ws + "/foo",
			want:    tRWX,
		},
		{
			name:    "outside writable root falls back to broad read",
			entries: []fsEntry{{"/", tRX, 0, false, false}, {ws, tRWX, 0, false, false}},
			path:    "/etc/hosts",
			want:    tRX,
		},
		{
			// 4. Carveout: the longer allow (.git, read-only) beats the writable
			// root it sits inside.
			name:    "carveout git dir is read-only inside writable root",
			entries: []fsEntry{{ws, tRWX, 0, false, false}, {ws + "/.git", readFSAccess, execFSAccess | writeFSAccess, false, false}},
			path:    ws + "/.git/config",
			want:    readFSAccess,
		},
		{
			name:    "carveout sibling stays writable",
			entries: []fsEntry{{ws, tRWX, 0, false, false}, {ws + "/.git", readFSAccess, execFSAccess | writeFSAccess, false, false}},
			path:    ws + "/src/a.go",
			want:    tRWX,
		},
		{
			// 5. Secret deny wins over the broad read that also matches.
			name:    "secret deny under broad read",
			entries: []fsEntry{{"/", tRX, 0, false, false}, {"/home/u/.ssh", denyFSAccess, 0, false, false}},
			path:    "/home/u/.ssh/id_rsa",
			want:    denyFSAccess,
		},
		{
			name:    "non-secret sibling keeps broad read",
			entries: []fsEntry{{"/", tRX, 0, false, false}, {"/home/u/.ssh", denyFSAccess, 0, false, false}},
			path:    "/home/u/.bashrc",
			want:    tRX,
		},
		{
			// 6. Glob deny is a hard override even inside a writable root.
			name:    "glob deny overrides writable root .env",
			entries: []fsEntry{{ws, tRWX, 0, false, false}, {"**/.env*", denyFSAccess, 0, false, false}},
			path:    ws + "/.env",
			want:    denyFSAccess,
		},
		{
			name:    "glob deny overrides nested .env.local",
			entries: []fsEntry{{ws, tRWX, 0, false, false}, {"**/.env*", denyFSAccess, 0, false, false}},
			path:    ws + "/sub/.env.local",
			want:    denyFSAccess,
		},
		{
			name:    "glob deny matches at filesystem root",
			entries: []fsEntry{{"/", tRX, 0, false, false}, {"**/.env*", denyFSAccess, 0, false, false}},
			path:    "/.env",
			want:    denyFSAccess,
		},
		{
			name:    "glob deny leaves ordinary file writable",
			entries: []fsEntry{{ws, tRWX, 0, false, false}, {"**/.env*", denyFSAccess, 0, false, false}},
			path:    ws + "/main.go",
			want:    tRWX,
		},
		{
			name:    "glob deny requires the dot: env has none",
			entries: []fsEntry{{ws, tRWX, 0, false, false}, {"**/.env*", denyFSAccess, 0, false, false}},
			path:    ws + "/env",
			want:    tRWX,
		},
		{
			name:    "glob deny does not match notenv",
			entries: []fsEntry{{ws, tRWX, 0, false, false}, {"**/.env*", denyFSAccess, 0, false, false}},
			path:    ws + "/notenv",
			want:    tRWX,
		},
		{
			// 7. Path boundary: prefix that is not a path segment must not match.
			name:    "path boundary rejects repository under repo",
			entries: []fsEntry{{"/work/repo", tRWX, 0, false, false}},
			path:    "/work/repository",
			want:    denyFSAccess,
		},
		{
			name:    "path boundary accepts nested under repo",
			entries: []fsEntry{{"/work/repo", tRWX, 0, false, false}},
			path:    "/work/repo/src",
			want:    tRWX,
		},
		{
			// 8. Exact match returns the entry's access.
			name:    "exact match returns entry access",
			entries: []fsEntry{{"/work/repo", tRWX, 0, false, false}},
			path:    "/work/repo",
			want:    tRWX,
		},
		{
			// 9. A more-specific allow overrides a broader root deny.
			name:    "more specific allow overrides broad deny",
			entries: []fsEntry{{ws + "/secret", tRWX, 0, false, false}, {ws, denyFSAccess, 0, false, false}},
			path:    ws + "/secret/key",
			want:    tRWX,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveFS(tt.entries, tt.path)
			if got != tt.want {
				t.Errorf("resolveFS(%v, %q) = %s, want %s",
					tt.entries, tt.path, accessString(got), accessString(tt.want))
			}
		})
	}
}

// TestResolveTieUnion pins the rule 2 tie-break: two allow entries with the same
// specificity union their access bits.
func TestResolveTieUnion(t *testing.T) {
	entries := []fsEntry{
		{"/work/ws", readFSAccess, 0, false, false},
		{"/work/ws", writeFSAccess | execFSAccess, 0, false, false},
	}
	got := resolveFS(entries, "/work/ws/file")
	want := readFSAccess | writeFSAccess | execFSAccess
	if got != want {
		t.Errorf("union tie = %s, want %s", accessString(got), accessString(want))
	}
}

// TestResolveCanonicalizesTarget confirms the target path is cleaned before
// matching, so lexical noise resolves the same as its canonical form.
func TestResolveCanonicalizesTarget(t *testing.T) {
	entries := []fsEntry{{"/work/ws", tRWX, 0, false, false}}
	if got := resolveFS(entries, "/work/ws/./src/../a.go"); got != tRWX {
		t.Errorf("resolveFS on noisy path = %s, want RWX", accessString(got))
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
	denyEntries := []fsEntry{{"/", tRX, 0, false, false}, {bad, denyFSAccess, 0, false, false}}
	if got := resolveFS(denyEntries, "/data/x.secret"); got != denyFSAccess {
		t.Errorf("malformed deny glob: resolveFS = %s, want Deny (fail closed)", accessString(got))
	}

	// (b) A malformed allow glob grants nothing.
	allowEntries := []fsEntry{{bad, tRWX, 0, false, false}}
	if got := resolveFS(allowEntries, "/data/x.secret"); got != denyFSAccess {
		t.Errorf("malformed allow glob: resolveFS = %s, want Deny (grants nothing)", accessString(got))
	}
}

// TestResolveGlobBranches exercises the "?" single-char and "[...]"/"[!...]"
// bracket-class glob branches, plus the allow-glob specificity ranking against a
// literal (tie-union and longer-prefix win).
func TestResolveGlobBranches(t *testing.T) {
	tests := []struct {
		name    string
		entries []fsEntry
		path    string
		want    fsAccess
	}{
		{
			name:    "? matches a single char",
			entries: []fsEntry{{"/work/?.txt", tRWX, 0, false, false}},
			path:    "/work/a.txt",
			want:    tRWX,
		},
		{
			name:    "? does not span two chars",
			entries: []fsEntry{{"/work/?.txt", tRWX, 0, false, false}},
			path:    "/work/ab.txt",
			want:    denyFSAccess,
		},
		{
			name:    "bracket class matches a member",
			entries: []fsEntry{{"/data/[abc].log", tRWX, 0, false, false}},
			path:    "/data/b.log",
			want:    tRWX,
		},
		{
			name:    "bracket class rejects a non-member",
			entries: []fsEntry{{"/data/[abc].log", tRWX, 0, false, false}},
			path:    "/data/d.log",
			want:    denyFSAccess,
		},
		{
			name:    "negated bracket class matches outside the set",
			entries: []fsEntry{{"/data/[!x].log", tRWX, 0, false, false}},
			path:    "/data/a.log",
			want:    tRWX,
		},
		{
			name:    "negated bracket class rejects a member",
			entries: []fsEntry{{"/data/[!x].log", tRWX, 0, false, false}},
			path:    "/data/x.log",
			want:    denyFSAccess,
		},
		{
			// Equal literal-prefix specificity: glob and literal union.
			name:    "allow glob ties with literal and unions bits",
			entries: []fsEntry{{"/work", readFSAccess, 0, false, false}, {"/work/*.go", writeFSAccess, 0, false, false}},
			path:    "/work/main.go",
			want:    readFSAccess | writeFSAccess,
		},
		{
			// Longer literal prefix: the glob allow beats the shorter literal.
			name:    "allow glob with longer prefix beats literal",
			entries: []fsEntry{{"/work", readFSAccess, 0, false, false}, {"/work/sub/*", writeFSAccess, 0, false, false}},
			path:    "/work/sub/x",
			want:    readFSAccess | writeFSAccess,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveFS(tt.entries, tt.path); got != tt.want {
				t.Errorf("resolveFS(%v, %q) = %s, want %s",
					tt.entries, tt.path, accessString(got), accessString(tt.want))
			}
		})
	}
}

// TestResolveWithBackendFixture feeds an internal mechanism fixture through the
// resolver, proving its emission and precedence agree end to end.
func TestResolveWithBackendFixture(t *testing.T) {
	const ws = "/work/ws"
	fs := backendFixturePolicy(fixtureWorkspaceWrite, ws).FS

	cases := []struct {
		path string
		want fsAccess
	}{
		{filepath.Join(ws, "main.go"), tRWX},                // workspace file: writable
		{filepath.Join(ws, ".git", "config"), readFSAccess}, // carveout: read-only
		{filepath.Join(ws, ".env"), denyFSAccess},           // secret glob: denied
		{"/etc/hosts", tRX},                                 // broad host read
	}
	for _, c := range cases {
		if got := resolveFS(fs, c.path); got != c.want {
			t.Errorf("resolveFS(backendFixturePolicy(fixtureWorkspaceWrite,%q).FS, %q) = %s, want %s",
				ws, c.path, accessString(got), accessString(c.want))
		}
	}
}

func TestResolveDistinguishesExactPathFromRecursiveTree(t *testing.T) {
	const target = "/work/ws/generated"
	tests := []struct {
		name  string
		entry fsEntry
		path  string
		want  fsAccess
	}{
		{name: "exact grants target", entry: fsEntry{Path: target, Access: writeFSAccess, Exact: true}, path: target, want: writeFSAccess},
		{name: "exact does not grant child", entry: fsEntry{Path: target, Access: writeFSAccess, Exact: true}, path: target + "/child", want: denyFSAccess},
		{name: "tree grants target", entry: fsEntry{Path: target, Access: writeFSAccess}, path: target, want: writeFSAccess},
		{name: "tree grants child", entry: fsEntry{Path: target, Access: writeFSAccess}, path: target + "/child", want: writeFSAccess},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := resolveFS([]fsEntry{test.entry}, test.path); got != test.want {
				t.Fatalf("resolveFS() = %s, want %s", accessString(got), accessString(test.want))
			}
		})
	}
}

func TestResolveExactGrantOutranksTreeDenialOnlyAtTarget(t *testing.T) {
	const target = "/work/ws/target"
	entries := []fsEntry{
		{Path: target, Denied: writeFSAccess},
		{Path: target, Access: writeFSAccess, Exact: true},
	}
	if got := resolveFS(entries, target); got != writeFSAccess {
		t.Fatalf("exact target access = %s, want W", accessString(got))
	}
	if got := resolveFS(entries, target+"/child"); got != denyFSAccess {
		t.Fatalf("tree denial was opened below exact target: %s", accessString(got))
	}
}
