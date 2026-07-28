//go:build darwin || linux

package policy

import (
	"os"
	"syscall"
)

func directRegularFileRuleSafe(info os.FileInfo) bool {
	if !info.Mode().IsRegular() {
		return true
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && uint64(stat.Nlink) == 1
}
