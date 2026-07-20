//go:build !linux

package sandbox

import "os"

func enumerateGrantPathHandle(*grantPathHandle, string, fsAccess, []string, int) ([]fsRule, []*os.File, error) {
	return nil, nil, ErrGrantUnsupported
}
