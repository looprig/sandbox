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
