//go:build windows

package exec

import (
	"os/exec"
	"syscall"
)

// applyShellCommandLine pins cmd's raw Windows command line when cmd is a
// shell spawn (enforce.ShellArgv's cmd.exe /D /S /C <command> shape), so
// cmd.exe receives the command verbatim instead of the CommandLineToArgvW
// escaping syscall.StartProcess would otherwise build — an encoding cmd.exe
// cannot decode (see commandInterpreterCommandLine). Any other argv is left
// to os/exec's own escaping, which is the right encoding for every program
// that parses its arguments with CommandLineToArgvW or the C runtime.
//
// It runs after the backend's configure hook (which may build SysProcAttr
// from scratch) and before the process tree or a ConPTY launch reads it;
// processTree.startConPTY honours the same field (process_tree_windows.go).
// An argv a backend has already rewritten into some other program is, by
// construction, no longer the shell shape and is never touched.
func applyShellCommandLine(cmd *exec.Cmd) {
	if cmd == nil {
		return
	}
	line, ok := commandInterpreterCommandLine(cmd.Args)
	if !ok {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	if cmd.SysProcAttr.CmdLine != "" {
		// A backend that already chose a raw command line owns it.
		return
	}
	cmd.SysProcAttr.CmdLine = line
}
