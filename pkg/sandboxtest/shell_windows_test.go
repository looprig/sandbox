//go:build windows

package sandboxtest

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type liveCmdSUT struct{}

func (liveCmdSUT) RunCommand(ctx context.Context, dir, command string) ([]byte, int, error) {
	// Deliberately enable delayed expansion in the parent. The probe script must
	// disable it before its path-bearing line rather than rely on caller state.
	cmd := exec.CommandContext(ctx, "cmd.exe", "/D", "/V:ON", "/S", "/C", command)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err == nil {
		return out, 0, nil
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return out, exit.ExitCode(), nil
	}
	return out, -1, err
}

func (liveCmdSUT) Level() uint8          { return LevelNone }
func (liveCmdSUT) GuaranteeBits() uint64 { return 0 }

func TestWindowsPathProbeTransportPreservesCmdMetacharacters(t *testing.T) {
	t.Setenv("LRSANDBOXTEST_PATH_EXPANSION", "expanded-away")
	root := t.TempDir()
	dir := filepath.Join(root, `dir %LRSANDBOXTEST_PATH_EXPANSION% ! & (caret^) spaces`)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, `value %LRSANDBOXTEST_PATH_EXPANSION% ! & (caret^) ' spaces.txt`)
	if out, code, err := platformWrite(context.Background(), liveCmdSUT{}, dir, path); err != nil || code != 0 {
		t.Fatalf("write metacharacter path: out=%q code=%d err=%v", out, code, err)
	}
	const content = "cmd-path-transport-control"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code, err := runRead(context.Background(), liveCmdSUT{}, dir, path)
	if err != nil || code != 0 || !strings.Contains(string(out), content) {
		t.Fatalf("read metacharacter path: out=%q code=%d err=%v", out, code, err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("literal percent path was not preserved: %v", err)
	}
}

func TestWindowsPathProbeRejectsUnrepresentablePath(t *testing.T) {
	if _, err := batchPath("bad\"path"); err == nil {
		t.Fatal("quote-bearing path accepted")
	}
}
