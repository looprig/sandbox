//go:build !linux

package policy

func AcquirePathHandle(binding *PathBinding, target string, _ bool) (*PathHandle, error) {
	if err := RevalidatePathBinding(binding, target); err != nil {
		return nil, err
	}
	return nil, nil
}
