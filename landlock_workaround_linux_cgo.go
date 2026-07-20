//go:build linux && cgo

package sandbox

import (
	"fmt"
	"os"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func landlockThreadWorkaroundRules() []fsRule {
	return []fsRule{{
		Path:           fmt.Sprintf("/proc/%d/task", os.Getpid()),
		LandlockAccess: uint64(llsys.AccessFSReadDir),
		IsDir:          true,
	}}
}
