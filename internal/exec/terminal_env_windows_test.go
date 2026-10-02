//go:build windows

package exec

import (
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// decodeConPTYEnvBlock splits a double-NUL-terminated UTF-16 environment
// block back into its KEY=VALUE entries, failing the test if the block is not
// terminated the way CreateProcess requires.
func decodeConPTYEnvBlock(t *testing.T, block []uint16) []string {
	t.Helper()
	if n := len(block); n < 2 || block[n-1] != 0 || block[n-2] != 0 {
		t.Fatalf("environment block %v is not double-NUL terminated", block)
	}
	var entries []string
	for start, i := 0, 0; i < len(block)-1; i++ {
		if block[i] != 0 {
			continue
		}
		if i > start {
			entries = append(entries, windows.UTF16ToString(block[start:i]))
		}
		start = i + 1
	}
	return entries
}

// TestConPTYLaunchEnvBlockAddsSystemRoot is the M2 ConPTY regression guard:
// the ConPTY path calls CreateProcess itself, so it must add SYSTEMROOT the
// way cmd.Start does. A non-nil EMPTY env (a scrub that admitted nothing)
// still yields a valid block, and that block carries SYSTEMROOT and nothing
// else; a nil env fails closed the same way rather than inheriting the
// parent environment.
func TestConPTYLaunchEnvBlockAddsSystemRoot(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "secret")
	want := []string{"SYSTEMROOT=" + os.Getenv("SYSTEMROOT")}
	for name, env := range map[string][]string{"empty": {}, "nil": nil} {
		block, err := conPTYLaunchEnvBlock(&exec.Cmd{Env: env})
		if err != nil {
			t.Fatalf("%s env: conPTYLaunchEnvBlock: %v", name, err)
		}
		if got := decodeConPTYEnvBlock(t, block); !slices.Equal(got, want) {
			t.Errorf("%s env: block entries = %v, want %v", name, got, want)
		}
	}
}

// TestConPTYLaunchEnvBlockDedupsCaseInsensitively proves the ConPTY block
// matches cmd.Start's case-insensitive dedup (the last spelling wins) and
// keeps a caller-supplied SystemRoot instead of adding a second one.
func TestConPTYLaunchEnvBlockDedupsCaseInsensitively(t *testing.T) {
	block, err := conPTYLaunchEnvBlock(&exec.Cmd{Env: []string{
		`Path=C:\first`, `SystemRoot=C:\Windows`, `PATH=C:\second`,
	}})
	if err != nil {
		t.Fatalf("conPTYLaunchEnvBlock: %v", err)
	}
	got := decodeConPTYEnvBlock(t, block)
	if want := []string{`SystemRoot=C:\Windows`, `PATH=C:\second`}; !slices.Equal(got, want) {
		t.Fatalf("block entries = %v, want %v", got, want)
	}
}

// TestConPTYLaunchEnvBlockRejectsNUL proves an entry containing NUL is an
// error rather than the silent drop exec.Cmd.Environ would apply.
func TestConPTYLaunchEnvBlockRejectsNUL(t *testing.T) {
	_, err := conPTYLaunchEnvBlock(&exec.Cmd{Env: []string{"A=b\x00c"}})
	if err == nil || !strings.Contains(err.Error(), "NUL") {
		t.Fatalf("conPTYLaunchEnvBlock(NUL entry) err = %v, want a NUL rejection", err)
	}
}
