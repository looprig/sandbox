//go:build !windows

package profile

import "os"

func equivalentRootSpelling(path string) string {
	return path + string(os.PathSeparator) + "."
}
