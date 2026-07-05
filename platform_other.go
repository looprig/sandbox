//go:build !darwin

package sandbox

// platformBackend selects the OS enforcement backend on every non-darwin platform.
// Today that is the null backend (no OS enforcement); the Linux namespace/Landlock
// ladder (SPEC §7.2) lands in Phase 3 and will replace this file's selection on
// linux with a probing selector. Until then linux and any other Unix degrade to
// "no isolation" — honest LevelNone — rather than failing to construct.
//
// Windows (SPEC §7.3) is unsupported in v1 and must fail with
// ErrUnsupportedPlatform BEFORE reaching null: null's spawnSpec execs the Unix
// "/bin/sh", which is not a valid Windows fallback. That windows selector is a
// separate build-tagged file (not built on this darwin host); it is intentionally
// not added here, so this !darwin selector currently also covers windows as a
// placeholder until the windows file exists.
func platformBackend() backend { return newNullBackend() }
