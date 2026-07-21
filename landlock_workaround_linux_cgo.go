//go:build linux && cgo

package sandbox

import (
	"fmt"
	"github.com/looprig/sandbox/internal/policy"
	"os"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func landlockThreadWorkaroundRules() []policy.FSRule {
	return []policy.FSRule{{
		Path:           fmt.Sprintf("/proc/%d/task", os.Getpid()),
		LandlockAccess: uint64(llsys.AccessFSReadDir),
		IsDir:          true,
	}}
}
