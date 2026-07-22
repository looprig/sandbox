//go:build !windows

package windows

import (
	"context"
	"errors"

	"github.com/looprig/sandbox/internal/enforce"
)

// ValidateConfig rejects Windows-only executor settings on non-Windows hosts.
func ValidateConfig(config Config) error {
	if config.Mode != Auto || config.StateRoot != "" {
		return errors.New("sandbox: non-default Windows executor options are unavailable on this host")
	}
	return nil
}

func Inspect(context.Context, SetupConfig) (SetupStatus, error) {
	return SetupStatus{}, enforce.ErrUnavailable
}

func Setup(context.Context, SetupConfig) error { return enforce.ErrUnavailable }

func Remove(context.Context, SetupConfig) error { return enforce.ErrUnavailable }
