//go:build !linux

package sandbox

func acquireGrantPathHandle(binding *grantPathBinding, target string, _ bool) (*grantPathHandle, error) {
	if err := revalidateGrantPathBinding(binding, target); err != nil {
		return nil, err
	}
	return nil, nil
}
