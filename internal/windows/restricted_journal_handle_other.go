//go:build !windows

package windows

import (
	"os"
)

func restrictedJournalHandleIsSafe(_ *os.File, _ os.FileInfo) bool {
	return true
}

func syncRestrictedJournalDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
