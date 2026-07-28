//go:build windows

package windows

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"

	win "golang.org/x/sys/windows"
)

func TestElevatedStdioBridgeCopiesOnlyThreeExplicitStreams(t *testing.T) {
	var stdout, stderr bytes.Buffer
	bridge, err := newElevatedStdioBridge(context.Background(), strings.NewReader("input"), &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	input, err := io.ReadAll(bridge.childStdin)
	if err != nil {
		t.Fatal(err)
	}
	if string(input) != "input" {
		t.Fatalf("stdin = %q", input)
	}
	if _, err := bridge.childStdout.Write([]byte("out")); err != nil {
		t.Fatal(err)
	}
	if _, err := bridge.childStderr.Write([]byte("err")); err != nil {
		t.Fatal(err)
	}
	if err := bridge.CloseChildEnds(); err != nil {
		t.Fatal(err)
	}
	if err := bridge.WaitOutput(); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "out" || stderr.String() != "err" {
		t.Fatalf("stdout/stderr = %q/%q", stdout.String(), stderr.String())
	}
	if err := bridge.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsEnvironmentBlockRejectsAmbiguousOrMutableInput(t *testing.T) {
	env := []string{"ZED=last", "Alpha=first"}
	block, err := windowsEnvironmentBlock(env)
	if err != nil {
		t.Fatal(err)
	}
	env[0] = "MUTATED=yes"
	text := win.UTF16ToString(block)
	if strings.Contains(text, "MUTATED") || !strings.HasPrefix(text, "Alpha=first") {
		t.Fatalf("environment block was not an immutable sorted snapshot: %q", text)
	}
	if _, err := windowsEnvironmentBlock([]string{"Path=one", "PATH=two"}); err == nil {
		t.Fatal("case-insensitive duplicate environment was accepted")
	}
	if _, err := windowsEnvironmentBlock([]string{"missing-separator"}); err == nil {
		t.Fatal("malformed environment was accepted")
	}
}

func TestElevatedRunnerRejectsCallerSelectedDesktopBeforeJobCreation(t *testing.T) {
	api := &fakeElevatedRunnerAPI{}
	launcher, err := newElevatedRunnerLauncher(api)
	if err != nil {
		t.Fatal(err)
	}
	spec := validElevatedRunnerLaunchForTest(api)
	spec.Desktop = `WinSta0\Default`
	if execution, err := launcher.Launch(spec); err == nil || execution != nil {
		t.Fatal("interactive desktop was accepted")
	}
	if got := strings.Join(api.events, ","); got != "verify-host,verify-token,close-token" {
		t.Fatalf("events = %q", got)
	}
}
