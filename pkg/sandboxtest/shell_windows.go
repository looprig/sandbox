//go:build windows

package sandboxtest

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func runEnvironment(ctx context.Context, sut SUT, dir string) ([]byte, int, error) {
	// SET is a cmd builtin, so this intentionally exercises RunCommand. The
	// canonical executor contract resolves System32 cmd.exe and supplies
	// /D /S /C; the suite never consults ComSpec.
	return sut.RunCommand(ctx, dir, "set")
}

func runRead(ctx context.Context, sut SUT, dir, path string) ([]byte, int, error) {
	operand, err := batchPath(path)
	if err != nil {
		return nil, -1, err
	}
	return runPathScript(ctx, sut, dir, "@type "+operand+"\r\n")
}

func platformWrite(ctx context.Context, sut SUT, dir, path string) ([]byte, int, error) {
	operand, err := batchPath(path)
	if err != nil {
		return nil, -1, err
	}
	return runPathScript(ctx, sut, dir, "@type nul > "+operand+"\r\n")
}

// runPathScript transports a path through a temporary batch file rather than
// interpolating it into cmd.exe's /C command string. Percent escaping has batch
// semantics there (%% means a literal %), and the script disables delayed
// expansion before parsing the path-bearing line so ! remains literal even if
// the caller enabled it. The launched command contains only a generated safe
// basename, so metacharacters in dir or path never pass through the /C parser.
func runPathScript(ctx context.Context, sut SUT, dir, body string) ([]byte, int, error) {
	script, err := os.CreateTemp(dir, ".lrsandboxtest-path-*.cmd")
	if err != nil {
		return nil, -1, fmt.Errorf("create Windows path probe: %w", err)
	}
	name := script.Name()
	defer os.Remove(name)
	if _, err := script.WriteString("@setlocal DisableDelayedExpansion\r\n" + body); err != nil {
		_ = script.Close()
		return nil, -1, fmt.Errorf("write Windows path probe: %w", err)
	}
	if err := script.Close(); err != nil {
		return nil, -1, fmt.Errorf("close Windows path probe: %w", err)
	}
	base := filepath.Base(name)
	if strings.ContainsAny(base, ` &|<>^()%!"`) {
		return nil, -1, fmt.Errorf("unsafe generated Windows path-probe name %q", base)
	}
	return sut.RunCommand(ctx, dir, base)
}

func batchPath(value string) (string, error) {
	// A double quote and CR/LF cannot occur in a valid Windows path. Escaping %
	// is necessary in a batch file; runPathScript disables delayed expansion
	// before this path-bearing line, so ! remains literal. Quoting neutralizes the
	// remaining command metacharacters, including &, parentheses, and spaces.
	if strings.ContainsAny(value, "\"\r\n") {
		return "", fmt.Errorf("unsupported Windows probe path %q", value)
	}
	return `"` + strings.ReplaceAll(value, "%", "%%") + `"`, nil
}
