//go:build windows

package enforce

import (
	"testing"

	"github.com/looprig/sandbox/internal/winpath"
)

func TestWindowsShellUsesHandleValidatedSystemInterpreter(t *testing.T) {
	path := system32CommandInterpreter()
	if path == "" {
		t.Fatal("System32 command interpreter validation failed closed")
	}
	object, err := winpath.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	if object.Kind != winpath.KindFile || object.ReparseTag != 0 ||
		commandInterpreterObject == nil || !object.SameIdentity(commandInterpreterObject) {
		t.Fatalf("shell path is not the retained interpreter identity: %+v", object)
	}
}
