//go:build windows

package enforce

import (
	"path/filepath"
	"sync"

	"github.com/looprig/sandbox/internal/winpath"
	"golang.org/x/sys/windows"
)

// ShellArgv uses the identity-pinned System32 command interpreter and never
// trusts ComSpec or an unverified executable path.
func ShellArgv(command string) []string {
	return []string{commandInterpreterResolver.resolve(), "/D", "/S", "/C", command}
}

// shellPathObject is the minimum object-path contract the shell resolver needs.
// Keeping Win32 discovery behind this boundary makes replacement behavior
// deterministic in tests without weakening the production identity comparison.
type shellPathObject interface {
	path() string
	kind() winpath.Kind
	reparseTag() uint32
	sameIdentity(shellPathObject) bool
	close() error
}

type windowsShellPathObject struct{ object *winpath.Object }

func (object *windowsShellPathObject) path() string       { return object.object.DOSPath }
func (object *windowsShellPathObject) kind() winpath.Kind { return object.object.Kind }
func (object *windowsShellPathObject) reparseTag() uint32 { return object.object.ReparseTag }
func (object *windowsShellPathObject) close() error       { return object.object.Close() }
func (object *windowsShellPathObject) sameIdentity(other shellPathObject) bool {
	candidate, ok := other.(*windowsShellPathObject)
	return ok && object.object.SameIdentity(candidate.object)
}

type shellPathOpener func(string) (shellPathObject, error)

type systemShellIdentity struct {
	directory   shellPathObject
	interpreter shellPathObject
	path        string
}

func (identity *systemShellIdentity) close() {
	if identity == nil {
		return
	}
	if identity.interpreter != nil {
		_ = identity.interpreter.close()
	}
	if identity.directory != nil {
		_ = identity.directory.close()
	}
}

// systemShellResolver retains the initial System32 and cmd.exe identities and
// treats their paths only as lookup keys. Every resolve re-opens both names and
// compares complete object identity immediately before returning the command
// path. A POSIX-style rename therefore fails closed even when delete-sharing
// denial did not keep the original name in place.
type systemShellResolver struct {
	once               sync.Once
	getSystemDirectory func() (string, error)
	openPinned         shellPathOpener
	baseline           *systemShellIdentity
}

func (resolver *systemShellResolver) resolve() string {
	resolver.once.Do(func() { resolver.baseline = resolver.capture() })
	baseline := resolver.baseline
	if baseline == nil {
		return ""
	}

	directory, err := resolver.openPinned(baseline.directory.path())
	if err != nil {
		return ""
	}
	defer directory.close()
	if !validSystemDirectory(directory) || !baseline.directory.sameIdentity(directory) {
		return ""
	}

	interpreter, err := resolver.openPinned(baseline.path)
	if err != nil {
		return ""
	}
	defer interpreter.close()
	if !validCommandInterpreter(directory, interpreter) ||
		!baseline.interpreter.sameIdentity(interpreter) {
		return ""
	}
	return baseline.path
}

func (resolver *systemShellResolver) capture() *systemShellIdentity {
	systemDirectory, err := resolver.getSystemDirectory()
	if err != nil || systemDirectory == "" {
		return nil
	}
	directory, err := resolver.openPinned(systemDirectory)
	if err != nil {
		return nil
	}
	if !validSystemDirectory(directory) {
		_ = directory.close()
		return nil
	}
	interpreter, err := resolver.openPinned(filepath.Join(directory.path(), "cmd.exe"))
	if err != nil {
		_ = directory.close()
		return nil
	}
	if !validCommandInterpreter(directory, interpreter) {
		_ = interpreter.close()
		_ = directory.close()
		return nil
	}
	return &systemShellIdentity{
		directory: directory, interpreter: interpreter, path: interpreter.path(),
	}
}

func validSystemDirectory(directory shellPathObject) bool {
	return directory != nil && directory.kind() == winpath.KindDirectory && directory.reparseTag() == 0
}

func validCommandInterpreter(directory, interpreter shellPathObject) bool {
	return validSystemDirectory(directory) && interpreter != nil &&
		interpreter.kind() == winpath.KindFile && interpreter.reparseTag() == 0 &&
		winpath.EqualPath(filepath.Dir(interpreter.path()), directory.path())
}

func openPinnedShellPath(path string) (shellPathObject, error) {
	object, err := winpath.OpenPinned(path)
	if err != nil {
		return nil, err
	}
	return &windowsShellPathObject{object: object}, nil
}

var commandInterpreterResolver = systemShellResolver{
	getSystemDirectory: windows.GetSystemDirectory,
	openPinned:         openPinnedShellPath,
}
