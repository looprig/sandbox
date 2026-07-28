//go:build !windows

package sandboxtest

import (
	"context"
	"strings"
)

func runEnvironment(ctx context.Context, sut SUT, dir string) ([]byte, int, error) {
	if argv, ok := sut.(ArgvSUT); ok {
		return argv.RunArgv(ctx, dir, []string{"env"})
	}
	return sut.RunCommand(ctx, dir, "env")
}

func runRead(ctx context.Context, sut SUT, dir, path string) ([]byte, int, error) {
	if argv, ok := sut.(ArgvSUT); ok {
		return argv.RunArgv(ctx, dir, []string{"cat", path})
	}
	return sut.RunCommand(ctx, dir, "cat -- "+shQuote(path))
}

func platformWrite(ctx context.Context, sut SUT, dir, path string) ([]byte, int, error) {
	// File creation is intrinsically a shell-redirection probe; all operations
	// with direct executable forms use ArgvSUT above.
	return sut.RunCommand(ctx, dir, ": > "+shQuote(path))
}

func shQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
