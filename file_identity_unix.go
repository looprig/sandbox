//go:build darwin || linux

package sandbox

import (
	"fmt"
	"os"
	"syscall"
)

func platformFileIdentity(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("sandbox: filesystem identity unavailable for %q", path)
	}
	return fmt.Sprintf("%d:%d:%d", uint64(stat.Dev), uint64(stat.Ino), uint32(info.Mode().Type())), nil
}
