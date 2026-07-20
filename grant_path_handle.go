package sandbox

import "os"

// grantPathHandle owns the identity-bound descriptor for one exact-file or
// tree-directory grant between authentication and child confinement setup.
type grantPathHandle struct {
	file   *os.File
	target string
	exact  bool
	isDir  bool
	access fsAccess
}

func (handle *grantPathHandle) Close() error {
	if handle == nil || handle.file == nil {
		return nil
	}
	return handle.file.Close()
}

func closeGrantPathHandles(handles []*grantPathHandle) {
	for _, handle := range handles {
		_ = handle.Close()
	}
}
