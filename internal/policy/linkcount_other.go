//go:build !darwin && !linux

package policy

import "os"

func directRegularFileRuleSafe(os.FileInfo) bool {
	return true
}
