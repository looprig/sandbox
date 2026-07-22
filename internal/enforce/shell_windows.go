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
	return []string{system32CommandInterpreter(), "/D", "/S", "/C", command}
}

var (
	commandInterpreterOnce sync.Once
	commandInterpreterPath string
	// These process-lifetime handles deny delete sharing, preventing System32 or
	// cmd.exe replacement after their identities have been validated.
	commandInterpreterDirectory *winpath.Object
	commandInterpreterObject    *winpath.Object
)

func system32CommandInterpreter() string {
	commandInterpreterOnce.Do(func() {
		systemDirectory, err := windows.GetSystemDirectory()
		if err != nil || systemDirectory == "" {
			return
		}
		directory, err := winpath.OpenPinned(systemDirectory)
		if err != nil || directory.Kind != winpath.KindDirectory || directory.ReparseTag != 0 {
			if directory != nil {
				_ = directory.Close()
			}
			return
		}
		interpreter, err := winpath.OpenPinned(filepath.Join(directory.DOSPath, "cmd.exe"))
		if err != nil || interpreter.Kind != winpath.KindFile || interpreter.ReparseTag != 0 ||
			!winpath.EqualPath(filepath.Dir(interpreter.DOSPath), directory.DOSPath) {
			if interpreter != nil {
				_ = interpreter.Close()
			}
			_ = directory.Close()
			return
		}
		commandInterpreterDirectory = directory
		commandInterpreterObject = interpreter
		commandInterpreterPath = interpreter.DOSPath
	})
	return commandInterpreterPath
}
