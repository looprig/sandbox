//go:build !windows

package sandboxtest_test

import "testing"

func requireLivePlatformBackend(*testing.T) {}
