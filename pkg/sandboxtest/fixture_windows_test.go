//go:build windows

package sandboxtest_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestConservativeSUTResolvesRelativeCmdOperandsAgainstDir(t *testing.T) {
	workspace := t.TempDir()
	sut := conservativeSUT{workspace: workspace}

	if out, code, err := sut.RunCommand(context.Background(), workspace, "type nul > inside.txt"); err != nil || code != 0 {
		t.Fatalf("relative write: out=%q code=%d err=%v", out, code, err)
	}
	inside := filepath.Join(workspace, "inside.txt")
	if _, err := os.Stat(inside); err != nil {
		t.Fatalf("relative write target %q: %v", inside, err)
	}

	if err := os.WriteFile(inside, []byte("inside-control"), 0o600); err != nil {
		t.Fatalf("seed relative read target: %v", err)
	}
	out, code, err := sut.RunCommand(context.Background(), workspace, "type inside.txt")
	if err != nil || code != 0 || string(out) != "inside-control" {
		t.Fatalf("relative read: out=%q code=%d err=%v", out, code, err)
	}
}
