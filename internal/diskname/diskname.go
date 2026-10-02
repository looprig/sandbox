// Package diskname re-spells an existing absolute path with the names the
// filesystem stores, so that two spellings of one object canonicalize to one
// string.
//
// It exists for macOS: APFS and HFS+ volumes are by default case- and
// Unicode-normalization-insensitive, and Seatbelt matches the vnode's path, so
// "/R/SECRET/key" opens and is policed as "/R/secret/key". A byte-exact root
// comparison over the caller's spelling would therefore miss a Deny root that
// the kernel applies. Every other platform keeps the caller's bytes: Linux
// paths are byte-exact, and Windows canonicalizes through its own handle-based
// path derivation.
package diskname
