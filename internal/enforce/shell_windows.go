//go:build windows

package enforce

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// ShellArgv uses the canonical System32 command interpreter and never trusts
// ComSpec. Task 6 replaces this bootstrap resolution with handle validation.
func ShellArgv(command string) []string {
	return []string{system32CommandInterpreter(), "/D", "/S", "/C", command}
}

func system32CommandInterpreter() string {
	return windowsCommandInterpreter(windows.GetSystemDirectory, func(directory, executable string) string {
		return filepath.Join(directory, executable)
	})
}
