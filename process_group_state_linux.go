//go:build linux

package sandbox

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// processGroupActive inspects /proc because kill(-pgid, 0) continues to report
// a group containing only zombies. Zombies cannot execute or retain authority;
// every other state, including stopped or uninterruptible tasks, remains active.
func processGroupActive(pgid int) (bool, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return true, err
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		stat, err := os.ReadFile("/proc/" + entry.Name() + "/stat")
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return true, err
		}
		active, err := activeProcessGroupStat(stat, pgid)
		if err != nil {
			return true, fmt.Errorf("parse /proc/%s/stat: %w", entry.Name(), err)
		}
		if active {
			return true, nil
		}
	}
	return false, nil
}

func activeProcessGroupStat(stat []byte, pgid int) (bool, error) {
	closeParen := strings.LastIndex(string(stat), ") ")
	if closeParen < 0 {
		return false, errors.New("malformed stat")
	}
	fields := strings.Fields(string(stat[closeParen+2:]))
	if len(fields) < 3 {
		return false, errors.New("short stat")
	}
	group, err := strconv.Atoi(fields[2])
	if err != nil {
		return false, fmt.Errorf("parse pgrp: %w", err)
	}
	return group == pgid && fields[0] != "Z", nil
}

// A supervisor that is PID 1 (or a configured subreaper) adopts orphaned group
// members. Reap only this run's process group; ECHILD simply means another init
// owns the zombies and will reap them.
func reapProcessGroup(pgid int) {
	for {
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(-pgid, &status, syscall.WNOHANG, nil)
		if errors.Is(err, syscall.ECHILD) || err != nil || pid <= 0 {
			return
		}
	}
}
