//go:build !darwin && !linux

package policy

func FileIdentity(string) (string, error) {
	return "", ErrUnsupportedClass
}
