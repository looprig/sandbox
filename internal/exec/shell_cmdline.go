package exec

import "strings"

// commandInterpreterCommandLine returns the raw Windows command line for an
// argv of exactly enforce.ShellArgv's shape — the command interpreter
// (cmd.exe), then /D /S /C, then one command string — and false for any other
// argv.
//
// cmd.exe does not recover its arguments with CommandLineToArgvW the way
// C-runtime programs do: with /S it strips the first and the last double
// quote that follow /C and executes everything between them verbatim. The
// CommandLineToArgvW-style escaping syscall.StartProcess applies when
// SysProcAttr.CmdLine is empty (`"` becomes `\"`) is therefore not an
// encoding cmd.exe can decode: it ran `> "x" echo y` as `> \"x\" echo y`.
// There is exactly one correct encoding of "run this command string" for
// cmd.exe, and it is this one: the interpreter path quoted (it is only ever
// used by CreateProcess's own image lookup through lpApplicationName, which
// os/exec sets independently, and by the child's GetCommandLine), then the
// switches, then the command wrapped in one pair of quotes for /S to strip.
//
// The switches are matched case-insensitively and re-emitted in
// ShellArgv's canonical spelling, as cmd.exe itself treats them. An
// interpreter path containing a double quote is refused rather than
// escaped: no real System32 path contains one, and cmd.exe has no escape for
// it in this position.
func commandInterpreterCommandLine(args []string) (string, bool) {
	if len(args) != 5 {
		return "", false
	}
	interpreter, command := args[0], args[4]
	if interpreter == "" || command == "" || strings.ContainsRune(interpreter, '"') {
		return "", false
	}
	// filepath.Base is OS-specific, so the Windows interpreter path is split
	// on both separators by hand: this pure function then behaves
	// identically when its table test runs on a Unix host.
	base := interpreter[strings.LastIndexAny(interpreter, `\/`)+1:]
	if !strings.EqualFold(base, "cmd.exe") {
		return "", false
	}
	for index, want := range []string{"/D", "/S", "/C"} {
		if !strings.EqualFold(args[index+1], want) {
			return "", false
		}
	}
	return `"` + interpreter + `" /D /S /C "` + command + `"`, true
}
