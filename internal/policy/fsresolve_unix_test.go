//go:build !windows

package policy

import "testing"

func TestUnixGlobMatchingRemainsCaseSensitive(t *testing.T) {
	entries := []FSEntry{
		{Path: `/work`, Access: AllAccess},
		{Path: `**/.env*`, Denied: AllAccess},
	}
	if got := ResolveFS(entries, `/work/.env.local`); got != DenyAccess {
		t.Fatalf("lowercase secret access = %v, want deny", got)
	}
	if got := ResolveFS(entries, `/work/.ENV.local`); got != AllAccess {
		t.Fatalf("case-distinct Unix path access = %v, want allow", got)
	}
}
