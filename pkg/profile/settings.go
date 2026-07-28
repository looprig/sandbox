package profile

// Settings is the normalized, read-only view of every authority value a
// Profile carries. It exists so packages outside this one can compile a
// Profile without reaching into its unexported fields, which keeps the Profile
// itself immutable: Settings is a copy, and mutating it cannot affect the
// Profile it came from.
type Settings struct {
	Version            uint16
	WorkspaceRoot      string
	WorkspaceRead      Access
	WorkspaceWrite     Access
	HostRead           Access
	HostWrite          Access
	Network            Access
	Command            Access
	Home               Home
	Isolation          Isolation
	AdditionalRoots    []RootAccess
	AckUnconfined      bool
	RequiredGuarantees uint64
	Fingerprint        string
}

// Settings returns the normalized authority of a validated Profile. An
// unconstructed or invalid Profile reports the zero Settings, whose Version is
// zero and which callers must reject as unsupported.
func (p *Profile) Settings() Settings {
	if p.Validate() != nil {
		return Settings{}
	}
	roots := make([]RootAccess, len(p.additionalRoots))
	copy(roots, p.additionalRoots)
	return Settings{
		Version:            p.version,
		WorkspaceRoot:      p.workspaceRoot,
		WorkspaceRead:      p.workspaceRead,
		WorkspaceWrite:     p.workspaceWrite,
		HostRead:           p.hostRead,
		HostWrite:          p.hostWrite,
		Network:            p.network,
		Command:            p.command,
		Home:               p.home,
		Isolation:          p.isolation,
		AdditionalRoots:    roots,
		AckUnconfined:      p.ackUnconfined,
		RequiredGuarantees: p.requiredGuarantees,
		Fingerprint:        p.fingerprint,
	}
}
