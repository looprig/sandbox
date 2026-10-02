//go:build !windows

package exec

import "os/exec"

// platformConfigureChildHandleList is a no-op off Windows: a Unix child
// inherits exactly the descriptors os/exec wires (fd 0-2 plus ExtraFiles),
// every other descriptor being close-on-exec, so there is no ambient handle
// list to narrow and no parent-held duplicate to release.
func platformConfigureChildHandleList(*exec.Cmd) (func(), error) {
	return func() {}, nil
}
