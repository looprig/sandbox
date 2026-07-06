//go:build !darwin && !linux

package sandbox

// platformBackend selects the OS enforcement backend on every platform that is
// neither darwin (Seatbelt, platform_darwin.go) nor linux (the Landlock/namespace
// ladder, platform_linux.go). Such platforms degrade to the null backend — honest
// LevelNone (no OS enforcement) — rather than failing to construct.
//
// Windows (SPEC §7.3) is unsupported in v1 and must fail with
// ErrUnsupportedPlatform BEFORE reaching null: null's spawnSpec execs the Unix
// "/bin/sh", which is not a valid Windows fallback. That windows selector is a
// separate build-tagged file; it is intentionally not added here, so this
// remaining-platforms selector currently also covers windows as a placeholder
// until the windows file exists.
func platformBackend() (backend, error) { return newNullBackend(), nil }
