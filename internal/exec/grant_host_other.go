//go:build !windows

package exec

func hostFilesystemGrantsSupported() bool { return true }
