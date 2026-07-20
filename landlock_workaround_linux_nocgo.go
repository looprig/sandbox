//go:build linux && !cgo

package sandbox

func landlockThreadWorkaroundRules() []fsRule { return nil }
