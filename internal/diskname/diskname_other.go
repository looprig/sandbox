//go:build !darwin

package diskname

// Respell returns path unchanged: outside macOS a path's bytes are its
// identity.
func Respell(path string) (string, error) { return path, nil }
