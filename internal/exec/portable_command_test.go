package exec

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestPortableWriteCommandForOSPreservesNestedWindowsPath(t *testing.T) {
	workspace := t.TempDir()
	marker := filepath.Join(workspace, "work", "portable-marker")
	relative := strings.ReplaceAll(filepath.Join("work", "portable-marker"), string(filepath.Separator), `\`)

	got := portableWriteCommandForOS("windows", workspace, marker, "started")
	want := `> "` + relative + `" echo started`
	if got != want {
		t.Fatalf("nested Windows write command = %q, want %q", got, want)
	}
}

func TestPortableWriteCommandKeepsWindowsRootCallerContract(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "portable-marker")
	got := portableWriteCommandForOS("windows", "", marker, "started")
	if want := "> portable-marker echo started"; got != want {
		t.Fatalf("root Windows write command = %q, want %q", got, want)
	}
}
