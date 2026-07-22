//go:build windows

package sandboxtest

import (
	"context"
	"strings"
)

func runEnvironment(ctx context.Context, sut SUT, dir string) ([]byte, int, error) {
	// SET is a cmd builtin, so this intentionally exercises RunCommand. The
	// canonical executor contract resolves System32 cmd.exe and supplies
	// /D /S /C; the suite never consults ComSpec.
	return sut.RunCommand(ctx, dir, "set")
}

func runRead(ctx context.Context, sut SUT, dir, path string) ([]byte, int, error) {
	// TYPE is a cmd builtin and avoids assuming PowerShell, Unix utilities, or
	// optional Windows components are installed.
	return sut.RunCommand(ctx, dir, "type "+cmdQuote(path))
}

func platformWrite(ctx context.Context, sut SUT, dir, path string) ([]byte, int, error) {
	// NUL and redirection are cmd syntax; TYPE emits no bytes and creates or
	// truncates the target without requiring an external executable.
	return sut.RunCommand(ctx, dir, "type nul > "+cmdQuote(path))
}

func cmdQuote(value string) string {
	// Temp and home paths cannot contain a double quote. Doubling percent signs
	// prevents environment expansion inside cmd's quoted argument.
	return `"` + strings.ReplaceAll(value, "%", "%%") + `"`
}
