package exec

import "testing"

// TestCommandInterpreterCommandLine pins the raw command line a Windows shell
// spawn (enforce.ShellArgv: cmd.exe /D /S /C <command>) is launched with.
//
// The first Windows CI run failed TestPortableShellFixtures with "The system
// cannot find the path specified." for `> "work\portable-marker" echo
// started`. Without SysProcAttr.CmdLine, syscall.StartProcess builds the
// command line with CommandLineToArgvW escaping, so that command reached
// cmd.exe as `"> \"work\portable-marker\" echo started"`. cmd.exe does not
// parse its command line with CommandLineToArgvW: /S strips the first and
// last quote after /C and runs the rest verbatim, so it ran
// `> \"work\portable-marker\" echo started` and redirected to the
// root-relative path `\"work\...`. Every command containing a double quote
// was mangled the same way (ConPTY's `findstr "^"` became a search for the
// literal `\"^\"`).
func TestCommandInterpreterCommandLine(t *testing.T) {
	const interpreter = `C:\Windows\system32\cmd.exe`
	for _, test := range []struct {
		name string
		args []string
		want string
		ok   bool
	}{
		{
			name: "quoted redirect operand reaches cmd verbatim",
			args: []string{interpreter, "/D", "/S", "/C", `> "work\portable-marker" echo started`},
			want: `"C:\Windows\system32\cmd.exe" /D /S /C "> "work\portable-marker" echo started"`,
			ok:   true,
		},
		{
			name: "quoted argument to a program",
			args: []string{interpreter, "/D", "/S", "/C", `findstr "^"`},
			want: `"C:\Windows\system32\cmd.exe" /D /S /C "findstr "^""`,
			ok:   true,
		},
		{
			name: "unquoted command",
			args: []string{interpreter, "/D", "/S", "/C", "set /p x="},
			want: `"C:\Windows\system32\cmd.exe" /D /S /C "set /p x="`,
			ok:   true,
		},
		{
			name: "switch and interpreter case are not significant to cmd",
			args: []string{`C:\WINDOWS\System32\CMD.EXE`, "/d", "/s", "/c", "echo hi"},
			want: `"C:\WINDOWS\System32\CMD.EXE" /D /S /C "echo hi"`,
			ok:   true,
		},
		{name: "not the interpreter", args: []string{`C:\tools\app.exe`, "/D", "/S", "/C", "echo hi"}},
		{name: "keep-open switch is not the shell shape", args: []string{interpreter, "/D", "/S", "/K", "echo hi"}},
		{name: "missing /S keeps legacy quote handling", args: []string{interpreter, "/D", "/C", "echo hi"}},
		{name: "extra argument", args: []string{interpreter, "/D", "/S", "/C", "echo", "hi"}},
		{name: "empty command", args: []string{interpreter, "/D", "/S", "/C", ""}},
		{name: "interpreter path with a quote", args: []string{`C:\odd"dir\cmd.exe`, "/D", "/S", "/C", "echo hi"}},
		{name: "unresolved interpreter", args: []string{"", "/D", "/S", "/C", "echo hi"}},
		{name: "empty argv"},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, ok := commandInterpreterCommandLine(test.args)
			if ok != test.ok || got != test.want {
				t.Fatalf("commandInterpreterCommandLine(%q) = (%q, %v), want (%q, %v)", test.args, got, ok, test.want, test.ok)
			}
		})
	}
}
