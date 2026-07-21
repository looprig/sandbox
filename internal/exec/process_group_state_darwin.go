//go:build darwin

package exec

import (
	"syscall"

	"golang.org/x/sys/unix"
)

const darwinZombieState = 5

func processGroupActive(pgid int) (bool, error) {
	processes, err := unix.SysctlKinfoProcSlice("kern.proc.pgrp", pgid)
	if err != nil {
		return true, err
	}
	for _, process := range processes {
		if process.Proc.P_stat != darwinZombieState {
			return true, nil
		}
	}
	return false, nil
}

func reapProcessGroup(pgid int) {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-pgid, &status, syscall.WNOHANG, nil)
		if err != nil || pid <= 0 {
			return
		}
	}
}
