// Package safetext holds the single predicate every untrusted single-line
// identifier in this module is validated against — grant fields, execution IDs,
// and proxy credentials alike. It exists as its own package so the grant layer
// and the egress layer share one definition of "safe text" rather than drifting
// apart with two near-identical copies.
package safetext

import (
	"strings"
	"unicode/utf8"
)

// Valid reports whether value is a non-empty, well-formed UTF-8 string that
// carries no surrounding whitespace and no NUL. It is deliberately strict:
// these values are compared for equality, embedded in URLs, and bound into
// authenticated tokens, so anything that could normalize to a different string
// later is rejected up front.
func Valid(value string) bool {
	return value != "" &&
		utf8.ValidString(value) &&
		strings.TrimSpace(value) == value &&
		!strings.ContainsRune(value, '\x00')
}
