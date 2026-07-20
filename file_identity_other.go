//go:build !darwin && !linux

package sandbox

func platformFileIdentity(string) (string, error) {
	return "", ErrGrantUnsupported
}
