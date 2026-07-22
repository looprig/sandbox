//go:build windows

package windows

import (
	"context"
	"errors"

	"github.com/looprig/sandbox/internal/enforce"
)

// ValidateConfig accepts the defined Windows modes. Mechanism-specific
// validation is added with the selector that consumes each mode.
func ValidateConfig(config Config) error {
	switch config.Mode {
	case Auto, RestrictedToken, Elevated:
		return nil
	default:
		return errors.New("sandbox: invalid Windows sandbox mode")
	}
}

// PlatformBackend selects the Windows tier while keeping ExecutorSet-scoped
// restricted recovery coordination distinct from elevated installation state.
func PlatformBackend(config Config, runtime *RestrictedRuntime) (enforce.Backend, error) {
	if err := ValidateConfig(config); err != nil {
		return nil, err
	}
	switch config.Mode {
	case Auto, RestrictedToken:
		return newRestrictedBackend(config, runtime), nil
	case Elevated:
		return nil, ErrSetupRequired
	default:
		panic("validated Windows mode became invalid")
	}
}

func Inspect(context.Context, SetupConfig) (SetupStatus, error) {
	return SetupStatus{}, enforce.ErrUnavailable
}

func Setup(context.Context, SetupConfig) error { return enforce.ErrUnavailable }

func Remove(context.Context, SetupConfig) error { return enforce.ErrUnavailable }
