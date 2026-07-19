package sandbox

// ReportEntry records how one requested feature was compiled by a backend.
type ReportEntry struct {
	Feature string
	Status  string
	Detail  string
}

// CompileReport records enforced, narrowed, and unavailable features.
type CompileReport struct {
	Entries []ReportEntry
}

const (
	LevelNone uint8 = iota
	LevelDegraded
	LevelFull
)

// Guarantees reports properties actually enforced by the selected backend.
type Guarantees struct {
	ProcessBoundary bool
	WriteBoundary   bool
	ReadBoundary    bool
	EnvScrub        bool
	NetworkBoundary bool
	AddressNetwork  bool
	ResourceLimits  bool
	TargetNetwork   bool
}

const (
	GuaranteeProcessBoundary uint64 = 1 << iota
	GuaranteeWriteBoundary
	GuaranteeReadBoundary
	GuaranteeEnvScrub
	GuaranteeNetworkBoundary
	GuaranteeAddressNetwork
	GuaranteeResourceLimits
	GuaranteeTargetNetwork
)

func guaranteesFromBits(bits uint64) Guarantees {
	return Guarantees{
		ProcessBoundary: bits&GuaranteeProcessBoundary != 0,
		WriteBoundary:   bits&GuaranteeWriteBoundary != 0,
		ReadBoundary:    bits&GuaranteeReadBoundary != 0,
		EnvScrub:        bits&GuaranteeEnvScrub != 0,
		NetworkBoundary: bits&GuaranteeNetworkBoundary != 0,
		AddressNetwork:  bits&GuaranteeAddressNetwork != 0,
		ResourceLimits:  bits&GuaranteeResourceLimits != 0,
		TargetNetwork:   bits&GuaranteeTargetNetwork != 0,
	}
}

func (g Guarantees) bits() uint64 {
	var bits uint64
	if g.ProcessBoundary {
		bits |= GuaranteeProcessBoundary
	}
	if g.WriteBoundary {
		bits |= GuaranteeWriteBoundary
	}
	if g.ReadBoundary {
		bits |= GuaranteeReadBoundary
	}
	if g.EnvScrub {
		bits |= GuaranteeEnvScrub
	}
	if g.NetworkBoundary {
		bits |= GuaranteeNetworkBoundary
	}
	if g.AddressNetwork {
		bits |= GuaranteeAddressNetwork
	}
	if g.ResourceLimits {
		bits |= GuaranteeResourceLimits
	}
	if g.TargetNetwork {
		bits |= GuaranteeTargetNetwork
	}
	return bits
}
