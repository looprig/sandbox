//go:build !linux

package sandbox

import "os"

type pinnedPathResolution struct {
	file    *os.File
	childFD int
	isDir   bool
}

type pinnedPathResolver struct {
	files []*os.File
}

func newPinnedPathResolver([]*grantPathHandle, int) *pinnedPathResolver {
	return &pinnedPathResolver{}
}

func (*pinnedPathResolver) resolve(string, bool) (pinnedPathResolution, bool, error) {
	return pinnedPathResolution{}, false, nil
}

func (*pinnedPathResolver) resolveAny(string) (pinnedPathResolution, bool, error) {
	return pinnedPathResolution{}, false, nil
}

func (*pinnedPathResolver) addFile(*os.File) int { return 0 }

func enumeratePinnedTree(*os.File, string, fsAccess, []string, func(*os.File) int, *pinnedPathResolver) ([]fsRule, error) {
	return nil, ErrGrantUnsupported
}

func enumerateGrantPathHandle(*grantPathHandle, string, fsAccess, []string, int) ([]fsRule, []*os.File, error) {
	return nil, nil, ErrGrantUnsupported
}
