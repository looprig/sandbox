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
	if errors.Is(err, win.ERROR_ACCESS_DENIED) || errors.Is(err, win.ERROR_INVALID_FUNCTION) || errors.Is(err, win.ERROR_INVALID_HANDLE) {
		return nil
	}
	return err
}
