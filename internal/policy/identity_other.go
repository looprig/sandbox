//go:build !darwin && !linux && !windows

package policy

func FileIdentity(string) (string, error) {
	return "", ErrUnsupportedClass
}
