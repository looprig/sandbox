package policy

// PathBinding pins a grant to a filesystem target by identity rather than by
// name. It records the canonical target and the complete platform identity
// captured when the grant was issued, so a reparse/symlink swap or a replaced
// directory between issue and spawn is detected and refused.

type PathBinding struct {
	CanonicalPath string
	ExistingPath  string
	Identity      string
}
