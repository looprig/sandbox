package enforce

import (
	"errors"
	"testing"
)

func TestWindowsCommandInterpreterUsesResolvedSystemDirectory(t *testing.T) {
	const systemDirectory = `D:\Windows\System32`
	got := windowsCommandInterpreter(
		func() (string, error) { return systemDirectory, nil },
		func(directory, executable string) string {
			if directory != systemDirectory || executable != "cmd.exe" {
				t.Fatalf("join arguments = (%q, %q), want (%q, %q)", directory, executable, systemDirectory, "cmd.exe")
			}
			return directory + `\` + executable
		},
	)
	if want := systemDirectory + `\cmd.exe`; got != want {
		t.Fatalf("command interpreter = %q, want %q", got, want)
	}
}

func TestWindowsCommandInterpreterFailsClosedWhenSystemDirectoryUnavailable(t *testing.T) {
	tests := []struct {
		name    string
		resolve func() (string, error)
	}{
		{name: "resolver error", resolve: func() (string, error) { return "", errors.New("unavailable") }},
		{name: "empty directory", resolve: func() (string, error) { return "", nil }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := windowsCommandInterpreter(test.resolve, func(_, _ string) string {
				t.Fatal("join called without a resolved system directory")
				return ""
			})
			if got != "" {
				t.Fatalf("command interpreter = %q, want empty fail-closed path", got)
			}
		})
	}
}
