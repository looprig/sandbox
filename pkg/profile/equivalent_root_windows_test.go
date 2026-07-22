//go:build windows

package profile

import "strings"

// equivalentRootSpelling exercises the supported extended-path and separator
// normalization without introducing a dot component, which Windows rejects.
func equivalentRootSpelling(path string) string {
	return `\\?\` + strings.ReplaceAll(path, `\`, `/`)
}
