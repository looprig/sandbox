//go:build !linux

package policy

import "os"

// PinnedPathResolution is one path resolved through an identity-pinned handle:
// the open descriptor, the number it will carry in the child, and whether it is
// a directory.
type PinnedPathResolution struct {
	File    *os.File
	ChildFD int
	IsDir   bool
}

type PinnedPathResolver struct {
	files []*os.File
}

func NewPinnedPathResolver([]*PathHandle, int) *PinnedPathResolver {
	return &PinnedPathResolver{}
}

func (*PinnedPathResolver) resolve(string, bool) (PinnedPathResolution, bool, error) {
	return PinnedPathResolution{}, false, nil
}

func (*PinnedPathResolver) ResolveAny(string) (PinnedPathResolution, bool, error) {
	return PinnedPathResolution{}, false, nil
}

func (*PinnedPathResolver) addFile(*os.File) int { return 0 }

func enumeratePinnedTree(*os.File, string, FSAccess, []fsExclude, func(*os.File) int, *PinnedPathResolver) ([]FSRule, error) {
	return nil, ErrUnsupportedClass
}
