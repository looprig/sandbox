//go:build darwin

package exec

import "os/exec"

// attachSupervisedProof is Darwin's stub counterpart to process_tree_linux.go
// (SPEC Task 12b is Linux-only containment scope; Darwin's fail-closed
// contract is Task 12c's job, implemented at PrepareProcess time rather than
// here). Returning (nil, nil) attaches no extra proof, which preserves
// processTree's pre-existing process-group behavior on Darwin exactly as it
// was before this microtask — this file exists only so
// process_tree_unix.go's shared newProcessTree can call
// attachSupervisedProof unconditionally on both Unix platforms without a
// runtime OS check.
func attachSupervisedProof(cmd *exec.Cmd, options processTreeOptions) (zeroProver, error) {
	return nil, nil
}
