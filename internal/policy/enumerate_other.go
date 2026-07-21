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

func (*PinnedPathResolver) resolveAny(string) (PinnedPathResolution, bool, error) {
	return PinnedPathResolution{}, false, nil
}

func (*PinnedPathResolver) addFile(*os.File) int { return 0 }

func enumeratePinnedTree(*os.File, string, FSAccess, []string, func(*os.File) int, *PinnedPathResolver) ([]FSRule, error) {
	return nil, ErrUnsupportedClass
}

func enumerateGrantPathHandle(*PathHandle, string, FSAccess, []string, int) ([]FSRule, []*os.File, error) {
	return nil, nil, ErrUnsupportedClass
}
