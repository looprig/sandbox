//go:build !windows

package exec

import "os/exec"

func configureChildHandleList(*exec.Cmd) (func(), error) {
	return func() {}, nil
}
