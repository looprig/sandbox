//go:build darwin || linux

package policy

import (
	"fmt"
	"os"
	"syscall"
)

func FileIdentity(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	return fileInfoIdentity(info)
}

func fileInfoIdentity(info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("sandbox: filesystem identity unavailable")
	}
	// No fixed-width conversion: Stat_t.Dev is int32 on darwin and uint64 on
	// linux, so any cast would be wrong on one of them. %d formats each field in
	// its native width, and the result is an opaque identity only ever compared
	// for equality against another identity captured on the same host.
	return fmt.Sprintf("%d:%d:%d", stat.Dev, stat.Ino, info.Mode().Type()), nil
}
