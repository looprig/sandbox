//go:build windows

package enforce

import (
	"errors"
	"slices"
	"testing"

	"github.com/looprig/sandbox/internal/winpath"
)

func TestWindowsShellUsesRevalidatedSystemInterpreter(t *testing.T) {
	argv := ShellArgv("echo verified")
	if len(argv) == 0 || argv[0] == "" {
		t.Fatal("System32 command interpreter validation failed closed")
	}
	object, err := winpath.Open(argv[0])
	if err != nil {
		t.Fatal(err)
	}
	defer object.Close()
	baseline := commandInterpreterResolver.baseline
	if object.Kind != winpath.KindFile || object.ReparseTag != 0 || baseline == nil ||
		!baseline.interpreter.sameIdentity(&windowsShellPathObject{object: object}) {
		t.Fatalf("shell path is not the retained interpreter identity: %+v", object)
	}
}

type fakeShellPathObject struct {
	identity string
	name     string
	shape    winpath.Kind
	tag      uint32
	closes   int
}

func (object *fakeShellPathObject) path() string       { return object.name }
func (object *fakeShellPathObject) kind() winpath.Kind { return object.shape }
func (object *fakeShellPathObject) reparseTag() uint32 { return object.tag }
func (object *fakeShellPathObject) close() error {
	object.closes++
	return nil
}
func (object *fakeShellPathObject) sameIdentity(other shellPathObject) bool {
	candidate, ok := other.(*fakeShellPathObject)
	return ok && object.identity == candidate.identity && object.name == candidate.name &&
		object.shape == candidate.shape && object.tag == candidate.tag
}

func TestSystemShellResolverRevalidatesUnchangedIdentityOnEveryUse(t *testing.T) {
	const (
		directoryPath   = `C:\Windows\System32`
		interpreterPath = `C:\Windows\System32\cmd.exe`
	)
	baselineDirectory := &fakeShellPathObject{identity: "directory", name: directoryPath, shape: winpath.KindDirectory}
	baselineInterpreter := &fakeShellPathObject{identity: "cmd", name: interpreterPath, shape: winpath.KindFile}
	firstDirectory := &fakeShellPathObject{identity: "directory", name: directoryPath, shape: winpath.KindDirectory}
	firstInterpreter := &fakeShellPathObject{identity: "cmd", name: interpreterPath, shape: winpath.KindFile}
	secondDirectory := &fakeShellPathObject{identity: "directory", name: directoryPath, shape: winpath.KindDirectory}
	secondInterpreter := &fakeShellPathObject{identity: "cmd", name: interpreterPath, shape: winpath.KindFile}
	resolver, opened := fakeSystemShellResolver(t, baselineDirectory, baselineInterpreter,
		firstDirectory, firstInterpreter, secondDirectory, secondInterpreter)

	if got := resolver.resolve(); got != interpreterPath {
		t.Fatalf("first resolve = %q, want %q", got, interpreterPath)
	}
	if got := resolver.resolve(); got != interpreterPath {
		t.Fatalf("second resolve = %q, want %q", got, interpreterPath)
	}
	if want := []string{directoryPath, interpreterPath, directoryPath, interpreterPath, directoryPath, interpreterPath}; !slices.Equal(*opened, want) {
		t.Fatalf("opened paths = %q, want %q", *opened, want)
	}
	if baselineDirectory.closes != 0 || baselineInterpreter.closes != 0 {
		t.Fatal("baseline identity handles closed while resolver remains live")
	}
	for _, current := range []*fakeShellPathObject{firstDirectory, firstInterpreter, secondDirectory, secondInterpreter} {
		if current.closes != 1 {
			t.Fatalf("current identity %q closes = %d, want 1", current.identity, current.closes)
		}
	}
	resolver.baseline.close()
	if baselineDirectory.closes != 1 || baselineInterpreter.closes != 1 {
		t.Fatal("baseline identity lifecycle did not close both retained handles")
	}
}

func TestSystemShellResolverFailsClosedOnPOSIXStyleReplacement(t *testing.T) {
	const (
		directoryPath   = `C:\Windows\System32`
		interpreterPath = `C:\Windows\System32\cmd.exe`
	)
	tests := []struct {
		name       string
		currentDir *fakeShellPathObject
		currentCmd *fakeShellPathObject
	}{
		{
			name:       "directory replaced while baseline handle remains open",
			currentDir: &fakeShellPathObject{identity: "replacement-directory", name: directoryPath, shape: winpath.KindDirectory},
		},
		{
			name:       "interpreter replaced while baseline handle remains open",
			currentDir: &fakeShellPathObject{identity: "directory", name: directoryPath, shape: winpath.KindDirectory},
			currentCmd: &fakeShellPathObject{identity: "replacement-cmd", name: interpreterPath, shape: winpath.KindFile},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			baselineDirectory := &fakeShellPathObject{identity: "directory", name: directoryPath, shape: winpath.KindDirectory}
			baselineInterpreter := &fakeShellPathObject{identity: "cmd", name: interpreterPath, shape: winpath.KindFile}
			objects := []shellPathObject{baselineDirectory, baselineInterpreter, test.currentDir}
			if test.currentCmd != nil {
				objects = append(objects, test.currentCmd)
			}
			resolver, _ := fakeSystemShellResolver(t, objects...)
			if got := resolver.resolve(); got != "" {
				t.Fatalf("resolve after replacement = %q, want empty fail-closed path", got)
			}
			if baselineDirectory.closes != 0 || baselineInterpreter.closes != 0 {
				t.Fatal("POSIX-style replacement closed retained baseline handles")
			}
			if test.currentDir.closes != 1 {
				t.Fatalf("current directory closes = %d, want 1", test.currentDir.closes)
			}
			if test.currentCmd != nil && test.currentCmd.closes != 1 {
				t.Fatalf("current interpreter closes = %d, want 1", test.currentCmd.closes)
			}
			resolver.baseline.close()
		})
	}
}

func fakeSystemShellResolver(t *testing.T, objects ...shellPathObject) (*systemShellResolver, *[]string) {
	t.Helper()
	remaining := append([]shellPathObject(nil), objects...)
	opened := []string{}
	resolver := &systemShellResolver{
		getSystemDirectory: func() (string, error) { return `C:\Windows\System32`, nil },
		openPinned: func(path string) (shellPathObject, error) {
			opened = append(opened, path)
			if len(remaining) == 0 {
				return nil, errors.New("unexpected shell path open")
			}
			object := remaining[0]
			remaining = remaining[1:]
			if object == nil || !winpath.EqualPath(object.path(), path) {
				t.Fatalf("open(%q) returned object for %q", path, object.path())
			}
			return object, nil
		},
	}
	return resolver, &opened
}
