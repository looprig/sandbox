package sandbox

import (
	"path/filepath"
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
			entries: []FSEntry{{"/", tRX}},
			path:    "/usr/bin/sh",
			want:    tRX,
		},
		{
			// 3. Longest allow wins: writable root beats the broad read.
			name:    "writable root beats broad read",
			entries: []FSEntry{{"/", tRX}, {ws, tRWX}},
			path:    ws + "/foo",
			want:    tRWX,
		},
		{
			name:    "outside writable root falls back to broad read",
			entries: []FSEntry{{"/", tRX}, {ws, tRWX}},
			path:    "/etc/hosts",
			want:    tRX,
		},
		{
			// 4. Carveout: the longer allow (.git, read-only) beats the writable
			// root it sits inside.
			name:    "carveout git dir is read-only inside writable root",
			entries: []FSEntry{{ws, tRWX}, {ws + "/.git", ReadAccess}},
			path:    ws + "/.git/config",
			want:    ReadAccess,
		},
		{
			name:    "carveout sibling stays writable",
			entries: []FSEntry{{ws, tRWX}, {ws + "/.git", ReadAccess}},
			path:    ws + "/src/a.go",
			want:    tRWX,
		},
		{
			// 5. Secret deny wins over the broad read that also matches.
			name:    "secret deny under broad read",
			entries: []FSEntry{{"/", tRX}, {"/home/u/.ssh", DenyAccess}},
			path:    "/home/u/.ssh/id_rsa",
			want:    DenyAccess,
		},
		{
			name:    "non-secret sibling keeps broad read",
			entries: []FSEntry{{"/", tRX}, {"/home/u/.ssh", DenyAccess}},
			path:    "/home/u/.bashrc",
			want:    tRX,
		},
		{
			// 6. Glob deny is a hard override even inside a writable root.
			name:    "glob deny overrides writable root .env",
			entries: []FSEntry{{ws, tRWX}, {"**/.env*", DenyAccess}},
			path:    ws + "/.env",
			want:    DenyAccess,
		},
		{
			name:    "glob deny overrides nested .env.local",
			entries: []FSEntry{{ws, tRWX}, {"**/.env*", DenyAccess}},
			path:    ws + "/sub/.env.local",
			want:    DenyAccess,
		},
		{
			name:    "glob deny matches at filesystem root",
			entries: []FSEntry{{"/", tRX}, {"**/.env*", DenyAccess}},
			path:    "/.env",
			want:    DenyAccess,
		},
		{
			name:    "glob deny leaves ordinary file writable",
			entries: []FSEntry{{ws, tRWX}, {"**/.env*", DenyAccess}},
			path:    ws + "/main.go",
			want:    tRWX,
		},
		{
			name:    "glob deny requires the dot: env has none",
			entries: []FSEntry{{ws, tRWX}, {"**/.env*", DenyAccess}},
			path:    ws + "/env",
			want:    tRWX,
		},
		{
			name:    "glob deny does not match notenv",
			entries: []FSEntry{{ws, tRWX}, {"**/.env*", DenyAccess}},
			path:    ws + "/notenv",
			want:    tRWX,
		},
		{
			// 7. Path boundary: prefix that is not a path segment must not match.
			name:    "path boundary rejects repository under repo",
			entries: []FSEntry{{"/work/repo", tRWX}},
			path:    "/work/repository",
			want:    DenyAccess,
		},
		{
			name:    "path boundary accepts nested under repo",
			entries: []FSEntry{{"/work/repo", tRWX}},
			path:    "/work/repo/src",
			want:    tRWX,
		},
		{
			// 8. Exact match returns the entry's access.
			name:    "exact match returns entry access",
			entries: []FSEntry{{"/work/repo", tRWX}},
			path:    "/work/repo",
			want:    tRWX,
		},
		{
			// 9. Deny is a hard override even over a more specific allow.
			name:    "deny overrides more specific allow",
			entries: []FSEntry{{ws + "/secret", tRWX}, {ws, DenyAccess}},
			path:    ws + "/secret/key",
			want:    DenyAccess,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(tt.entries, tt.path)
			if got != tt.want {
				t.Errorf("Resolve(%v, %q) = %s, want %s",
					tt.entries, tt.path, accessString(got), accessString(tt.want))
			}
		})
	}
}

// TestResolveTieUnion pins the rule 2 tie-break: two allow entries with the same
// specificity union their access bits.
func TestResolveTieUnion(t *testing.T) {
	entries := []FSEntry{
		{"/work/ws", ReadAccess},
		{"/work/ws", WriteAccess | ExecAccess},
	}
	got := Resolve(entries, "/work/ws/file")
	want := ReadAccess | WriteAccess | ExecAccess
	if got != want {
		t.Errorf("union tie = %s, want %s", accessString(got), accessString(want))
	}
}

// TestResolveCanonicalizesTarget confirms the target path is cleaned before
// matching, so lexical noise resolves the same as its canonical form.
func TestResolveCanonicalizesTarget(t *testing.T) {
	entries := []FSEntry{{"/work/ws", tRWX}}
	if got := Resolve(entries, "/work/ws/./src/../a.go"); got != tRWX {
		t.Errorf("Resolve on noisy path = %s, want RWX", accessString(got))
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
	denyEntries := []FSEntry{{"/", tRX}, {bad, DenyAccess}}
	if got := Resolve(denyEntries, "/data/x.secret"); got != DenyAccess {
		t.Errorf("malformed deny glob: Resolve = %s, want Deny (fail closed)", accessString(got))
	}

	// (b) A malformed allow glob grants nothing.
	allowEntries := []FSEntry{{bad, tRWX}}
	if got := Resolve(allowEntries, "/data/x.secret"); got != DenyAccess {
		t.Errorf("malformed allow glob: Resolve = %s, want Deny (grants nothing)", accessString(got))
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
			entries: []FSEntry{{"/work/?.txt", tRWX}},
			path:    "/work/a.txt",
			want:    tRWX,
		},
		{
			name:    "? does not span two chars",
			entries: []FSEntry{{"/work/?.txt", tRWX}},
			path:    "/work/ab.txt",
			want:    DenyAccess,
		},
		{
			name:    "bracket class matches a member",
			entries: []FSEntry{{"/data/[abc].log", tRWX}},
			path:    "/data/b.log",
			want:    tRWX,
		},
		{
			name:    "bracket class rejects a non-member",
			entries: []FSEntry{{"/data/[abc].log", tRWX}},
			path:    "/data/d.log",
			want:    DenyAccess,
		},
		{
			name:    "negated bracket class matches outside the set",
			entries: []FSEntry{{"/data/[!x].log", tRWX}},
			path:    "/data/a.log",
			want:    tRWX,
		},
		{
			name:    "negated bracket class rejects a member",
			entries: []FSEntry{{"/data/[!x].log", tRWX}},
			path:    "/data/x.log",
			want:    DenyAccess,
		},
		{
			// Equal literal-prefix specificity: glob and literal union.
			name:    "allow glob ties with literal and unions bits",
			entries: []FSEntry{{"/work", ReadAccess}, {"/work/*.go", WriteAccess}},
			path:    "/work/main.go",
			want:    ReadAccess | WriteAccess,
		},
		{
			// Longer literal prefix: the glob allow beats the shorter literal.
			name:    "allow glob with longer prefix beats literal",
			entries: []FSEntry{{"/work", ReadAccess}, {"/work/sub/*", WriteAccess}},
			path:    "/work/sub/x",
			want:    WriteAccess,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Resolve(tt.entries, tt.path); got != tt.want {
				t.Errorf("Resolve(%v, %q) = %s, want %s",
					tt.entries, tt.path, accessString(got), accessString(tt.want))
			}
		})
	}
}

// TestResolveWithPolicyFor feeds real PolicyFor output through the resolver,
// proving PolicyFor's emission and the resolver's precedence agree end to end.
func TestResolveWithPolicyFor(t *testing.T) {
	const ws = "/work/ws"
	fs := PolicyFor(Write, ws).FS

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
		if got := Resolve(fs, c.path); got != c.want {
			t.Errorf("Resolve(PolicyFor(Write,%q).FS, %q) = %s, want %s",
				ws, c.path, accessString(got), accessString(c.want))
		}
	}
}
