package policy

import "errors"

// These sentinels are raised while compiling or re-validating a policy that a
// grant has widened, so they must be defined at this layer rather than in the
// grant package that sits above it. The grant package re-exports each one under
// its ErrGrant* name, so a single value satisfies errors.Is on both sides.
var (
	// ErrMalformed reports a grant binding that is structurally invalid.
	ErrMalformed = errors.New("sandbox: grant token malformed")
	// ErrTargetChanged reports that a granted filesystem target was replaced
	// between the grant being issued and the spawn being prepared.
	ErrTargetChanged = errors.New("sandbox: granted filesystem target changed")
	// ErrUnsupportedClass reports a grant whose class cannot be enforced by the
	// compiled policy — for example an exact path Landlock cannot express.
	ErrUnsupportedClass = errors.New("sandbox: grant class unsupported")
)
