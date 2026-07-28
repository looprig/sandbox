package enforce

func windowsCommandInterpreter(resolve func() (string, error), join func(string, string) string) string {
	systemDirectory, err := resolve()
	if err != nil || systemDirectory == "" {
		return ""
	}
	return join(systemDirectory, "cmd.exe")
}
