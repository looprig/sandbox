package windows

import (
	"errors"

	"github.com/looprig/sandbox/internal/enforce"
)

type unavailableError string

func (err unavailableError) Error() string { return string(err) }

func (unavailableError) Unwrap() error { return enforce.ErrUnavailable }

var (
	ErrSetupRequired error = unavailableError("sandbox: Windows elevated setup required")
	ErrSetupStale    error = unavailableError("sandbox: Windows elevated setup is stale")

	ErrElevationRequired = errors.New("sandbox: Windows setup requires elevation")
)
