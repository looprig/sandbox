//go:build linux && !cgo

package sandbox

import (
	"github.com/looprig/sandbox/internal/policy"
)

func landlockThreadWorkaroundRules() []policy.FSRule { return nil }
