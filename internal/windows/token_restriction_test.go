package windows

import (
	"encoding/binary"
	"strings"
	"testing"
	"unsafe"
)

func TestTokenRestrictionFlagSetsAreDistinct(t *testing.T) {
	restricted, err := tokenRestrictionWriteOnly.createFlags()
	if err != nil {
		t.Fatal(err)
	}
	if restricted != disableMaxPrivilege|luaToken|writeRestricted {
		t.Fatalf("restricted-tier flags = %#x, want DISABLE_MAX_PRIVILEGE|LUA_TOKEN|WRITE_RESTRICTED", restricted)
	}
	full, err := tokenRestrictionFull.createFlags()
	if err != nil {
		t.Fatal(err)
	}
	if full != disableMaxPrivilege|luaToken {
		t.Fatalf("elevated broker flags = %#x, want DISABLE_MAX_PRIVILEGE|LUA_TOKEN", full)
	}
	if full&writeRestricted != 0 {
		t.Fatal("elevated broker flag set carries WRITE_RESTRICTED")
	}
	if _, err := tokenRestriction(0).createFlags(); err == nil {
		t.Fatal("unspecified token restriction produced a flag set")
	}
}

func TestTokenRestrictionRefusesTheOtherTiersToken(t *testing.T) {
	if err := tokenRestrictionFull.verify(true); err == nil || !strings.Contains(err.Error(), "write-restricted") {
		t.Fatalf("full restriction accepted a write-restricted token: %v", err)
	}
	if err := tokenRestrictionFull.verify(false); err != nil {
		t.Fatalf("full restriction refused a fully restricted token: %v", err)
	}
	if err := tokenRestrictionWriteOnly.verify(false); err == nil {
		t.Fatal("restricted tier accepted a fully restricted token in place of its write-restricted one")
	}
	if err := tokenRestrictionWriteOnly.verify(true); err != nil {
		t.Fatalf("restricted tier refused its write-restricted token: %v", err)
	}
	if err := tokenRestriction(0).verify(false); err == nil {
		t.Fatal("unspecified token restriction verified a token")
	}
}

func TestTokenAccessInformationFlagsOffsetMatchesWindowsABI(t *testing.T) {
	// SidHash, RestrictedSidHash and Privileges are pointers; AuthenticationId
	// is a 4-byte-aligned LUID; TokenType, ImpersonationLevel and
	// MandatoryPolicy are DWORD-sized. Flags therefore sits at 44 on both
	// amd64 and arm64 and at 32 on 32-bit Windows.
	want := uintptr(44)
	if unsafe.Sizeof(uintptr(0)) == 4 {
		want = 32
	}
	if got := unsafe.Offsetof(tokenAccessInformationLayout{}.Flags); got != want {
		t.Fatalf("TOKEN_ACCESS_INFORMATION.Flags offset = %d, want %d", got, want)
	}
}

func TestTokenAccessInformationWriteRestrictedDecoding(t *testing.T) {
	offset := unsafe.Offsetof(tokenAccessInformationLayout{}.Flags)
	info := make([]byte, unsafe.Sizeof(tokenAccessInformationLayout{}))
	binary.LittleEndian.PutUint32(info[offset:], tokenFlagIsRestricted|tokenFlagWriteRestricted)
	if got, err := tokenAccessInformationWriteRestricted(info); err != nil || !got {
		t.Fatalf("write-restricted flags decoded as %v, %v", got, err)
	}
	binary.LittleEndian.PutUint32(info[offset:], tokenFlagIsRestricted)
	if got, err := tokenAccessInformationWriteRestricted(info); err != nil || got {
		t.Fatalf("fully restricted flags decoded as %v, %v", got, err)
	}
	// Bytes outside the Flags field must not be read as the flag.
	clear(info)
	info[offset-1], info[offset+4] = 0xff, 0xff
	if got, err := tokenAccessInformationWriteRestricted(info); err != nil || got {
		t.Fatalf("neighbouring fields decoded as WRITE_RESTRICTED: %v, %v", got, err)
	}
	if _, err := tokenAccessInformationWriteRestricted(info[:offset+3]); err == nil {
		t.Fatal("short TOKEN_ACCESS_INFORMATION accepted")
	}
}
