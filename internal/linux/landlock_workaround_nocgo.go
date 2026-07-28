//go:build linux && !cgo

package linux

import (
	"github.com/looprig/sandbox/internal/policy"
)

func landlockThreadWorkaroundRules() []policy.FSRule { return nil }
