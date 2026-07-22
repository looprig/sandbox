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

// PlatformBackend is the compile-safe Windows selector seam. The real
// restricted-token and elevated selectors are introduced in later phases; until
// then it fails closed and makes no enforcement claim.
func PlatformBackend(config Config) (enforce.Backend, error) {
	if err := ValidateConfig(config); err != nil {
		return nil, err
	}
	return nil, enforce.ErrUnavailable
}

func Inspect(context.Context, SetupConfig) (SetupStatus, error) {
	return SetupStatus{}, enforce.ErrUnavailable
}

func Setup(context.Context, SetupConfig) error { return enforce.ErrUnavailable }

func Remove(context.Context, SetupConfig) error { return enforce.ErrUnavailable }
