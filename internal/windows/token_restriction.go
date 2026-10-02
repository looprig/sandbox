package windows

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"
)

// CreateRestrictedToken flags. They are declared here rather than in the
// Windows-only token code so the tier-to-flag mapping is testable on every
// host.
const (
	disableMaxPrivilege = 0x00000001
	luaToken            = 0x00000004
	writeRestricted     = 0x00000008
)

// tokenRestriction names which of the two Windows restriction contracts a
// token must carry. The two tiers use different contracts on purpose, and a
// token minted for one must never pass validation for the other.
type tokenRestriction uint8

const (
	// tokenRestrictionWriteOnly is the restricted tier's token (design §9.1):
	// WRITE_RESTRICTED, so the restricting-SID list participates only in write
	// access checks. That tier never claims ReadBoundary.
	tokenRestrictionWriteOnly tokenRestriction = iota + 1
	// tokenRestrictionFull is the elevated broker's token (design §9.2): the
	// second, restricting-SID access check runs for reads as well as writes.
	// Without it every deny-read ACE the broker projects is inert, so the
	// elevated tier's ReadBoundary claim depends on this exact contract.
	tokenRestrictionFull
)

// createFlags returns the CreateRestrictedToken flag set for the contract.
//
// The full contract keeps LUA_TOKEN. The sandbox accounts are non-admin local
// accounts, so LUA_TOKEN has no group or privilege effect beyond what
// DISABLE_MAX_PRIVILEGE and the explicit dangerous-group list already remove;
// it is retained because DISABLE_MAX_PRIVILEGE|LUA_TOKEN with Restricted Code
// is the exact flag set the runtime-baseline spike
// (docs/spikes/windows-restricted-runtime.md) proves launchable. Changing it
// would invalidate that evidence for no security gain.
func (restriction tokenRestriction) createFlags() (uint32, error) {
	switch restriction {
	case tokenRestrictionWriteOnly:
		return disableMaxPrivilege | luaToken | writeRestricted, nil
	case tokenRestrictionFull:
		return disableMaxPrivilege | luaToken, nil
	default:
		return 0, errors.New("windows sandbox: unspecified token restriction")
	}
}

// verify checks a token's observed WRITE_RESTRICTED state against the
// contract. It is symmetric so the two tiers' tokens can never be swapped.
func (restriction tokenRestriction) verify(observedWriteRestricted bool) error {
	switch restriction {
	case tokenRestrictionWriteOnly:
		if !observedWriteRestricted {
			return errors.New("windows sandbox: restricted-tier token is not write-restricted")
		}
		return nil
	case tokenRestrictionFull:
		if observedWriteRestricted {
			return errors.New("windows sandbox: elevated token is write-restricted; reads would bypass the restricting SIDs")
		}
		return nil
	default:
		return errors.New("windows sandbox: unspecified token restriction")
	}
}

// TokenAccessInformation (TOKEN_INFORMATION_CLASS 22) and the TOKEN_*
// flags reported in TOKEN_ACCESS_INFORMATION.Flags.
const (
	tokenAccessInformationClass = 22
	tokenFlagWriteRestricted    = 0x0008
	tokenFlagIsRestricted       = 0x0010
)

// tokenAccessInformationLayout mirrors TOKEN_ACCESS_INFORMATION closely
// enough to locate Flags with unsafe.Offsetof. Every member before Flags is a
// pointer, a 4-byte-aligned LUID or a DWORD, so the Go layout matches the
// Windows ABI on both 32-bit and 64-bit targets. The buffer is never cast to
// this type; only the offset is used.
type tokenAccessInformationLayout struct {
	SidHash            uintptr
	RestrictedSidHash  uintptr
	Privileges         uintptr
	AuthenticationID   [2]uint32
	TokenType          uint32
	ImpersonationLevel uint32
	MandatoryPolicy    uint32
	Flags              uint32
	AppContainerNumber uint32
	PackageSid         uintptr
	CapabilitiesHash   uintptr
	TrustLevelSid      uintptr
	SecurityAttributes uintptr
}

// tokenAccessInformationWriteRestricted decodes the WRITE_RESTRICTED bit from
// a raw GetTokenInformation(TokenAccessInformation) buffer. IsRestricted is
// true for both restriction contracts, so this bit is the only readable
// distinction between them.
func tokenAccessInformationWriteRestricted(info []byte) (bool, error) {
	offset := unsafe.Offsetof(tokenAccessInformationLayout{}.Flags)
	if uintptr(len(info)) < offset+4 {
		return false, fmt.Errorf("windows sandbox: token access information is %d bytes, want at least %d", len(info), offset+4)
	}
	return binary.LittleEndian.Uint32(info[offset:])&tokenFlagWriteRestricted != 0, nil
}
