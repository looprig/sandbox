//go:build windows

package windows

import (
	"errors"
	"os"

	win "golang.org/x/sys/windows"
)

func restrictedJournalHandleIsSafe(file *os.File, _ os.FileInfo) bool {
	var info win.ByHandleFileInformation
	if err := win.GetFileInformationByHandle(win.Handle(file.Fd()), &info); err != nil {
		return false
	}
	return info.FileAttributes&win.FILE_ATTRIBUTE_REPARSE_POINT == 0
}

func syncRestrictedJournalDirectory(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	defer directory.Close()
	err = directory.Sync()
	// Windows does not universally support FlushFileBuffers on directory
	// handles. These documented platform errors mean the directory-sync
	// primitive is unavailable; every other failure remains fatal.
	if errors.Is(err, win.ERROR_ACCESS_DENIED) || errors.Is(err, win.ERROR_INVALID_FUNCTION) || errors.Is(err, win.ERROR_INVALID_HANDLE) {
		return nil
	}
	return err
}
