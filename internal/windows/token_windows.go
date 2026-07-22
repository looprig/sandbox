//go:build windows

package windows

import (
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	xwindows "golang.org/x/sys/windows"
)

const (
	disableMaxPrivilege = 0x00000001
	luaToken            = 0x00000004
	writeRestricted     = 0x00000008

	restrictedTokenFlags = disableMaxPrivilege | luaToken | writeRestricted
)

var createRestrictedTokenProc = xwindows.NewLazySystemDLL("advapi32.dll").NewProc("CreateRestrictedToken")

var dangerousGroupSIDStrings = []string{
	"S-1-5-32-544", // Administrators
	"S-1-5-32-547", // Power Users
	"S-1-5-32-548", // Account Operators
	"S-1-5-32-549", // Server Operators
	"S-1-5-32-550", // Print Operators
	"S-1-5-32-551", // Backup Operators
	"S-1-5-32-552", // Replicators
	"S-1-5-32-555", // Remote Desktop Users
	"S-1-5-32-556", // Network Configuration Operators
	"S-1-5-32-569", // Cryptographic Operators
	"S-1-5-32-578", // Hyper-V Administrators
	"S-1-5-32-579", // Access Control Assistance Operators
	"S-1-5-32-580", // Remote Management Users
}

type restrictedTokenCreator interface {
	Create(source xwindows.Token, flags uint32, disabled, restricting []xwindows.SIDAndAttributes) (xwindows.Token, error)
}

type win32RestrictedTokenCreator struct{}

// CreateRestrictedToken derives a least-authority primary token from source.
// It does not take ownership of source. The caller owns the returned token.
//
// Dangerous source groups are disabled, maximum privileges are removed, and
// restrictingSIDs participate only in write access checks. The token's
// integrity level is deliberately preserved. Source must grant TOKEN_DUPLICATE
// and TOKEN_QUERY.
func CreateRestrictedToken(source xwindows.Token, restrictingSIDs []SID) (xwindows.Token, error) {
	if source == 0 {
		return 0, errors.New("windows sandbox: source token is invalid")
	}
	if len(restrictingSIDs) == 0 {
		return 0, errors.New("windows sandbox: at least one restricting SID is required")
	}
	parsedRestrictingSIDs, err := parseRestrictingSIDs(restrictingSIDs)
	if err != nil {
		return 0, err
	}

	sourceType, err := tokenUint32Information(source, xwindows.TokenType)
	if err != nil {
		return 0, fmt.Errorf("windows sandbox: read source token type: %w", err)
	}
	if sourceType != xwindows.TokenPrimary {
		return 0, errors.New("windows sandbox: source token is not primary")
	}
	sourceRestricted, err := source.IsRestricted()
	if err != nil {
		return 0, fmt.Errorf("windows sandbox: read source restricted-token status: %w", err)
	}
	if sourceRestricted {
		return 0, errors.New("windows sandbox: source token is already restricted")
	}
	sourceIntegrity, err := tokenIntegritySID(source)
	if err != nil {
		return 0, fmt.Errorf("windows sandbox: read source integrity: %w", err)
	}
	sourceGroups, err := source.GetTokenGroups()
	if err != nil {
		return 0, fmt.Errorf("windows sandbox: read source groups: %w", err)
	}
	sourcePrivileges, err := tokenPrivilegeList(source)
	if err != nil {
		return 0, fmt.Errorf("windows sandbox: read source privileges: %w", err)
	}
	if err := ensureRestrictingSIDsAreNew(sourceGroups.AllGroups(), parsedRestrictingSIDs); err != nil {
		return 0, err
	}

	dangerousSIDs, err := dangerousGroupSIDs()
	if err != nil {
		return 0, err
	}
	disabledGroups := make([]xwindows.SIDAndAttributes, 0, len(dangerousSIDs))
	for _, sid := range dangerousSIDs {
		if groupIsEnabledForAllow(sourceGroups.AllGroups(), sid) {
			disabledGroups = append(disabledGroups, xwindows.SIDAndAttributes{Sid: sid})
		}
	}
	restrictingGroups := make([]xwindows.SIDAndAttributes, len(parsedRestrictingSIDs))
	for index, sid := range parsedRestrictingSIDs {
		restrictingGroups[index] = xwindows.SIDAndAttributes{Sid: sid}
	}

	token, err := issueRestrictedToken(win32RestrictedTokenCreator{}, source, disabledGroups, restrictingGroups)
	runtime.KeepAlive(sourceGroups)
	runtime.KeepAlive(parsedRestrictingSIDs)
	if err != nil {
		return 0, err
	}
	if err := validateRestrictedToken(token, sourceIntegrity, disabledGroups, sourcePrivileges, parsedRestrictingSIDs); err != nil {
		token.Close()
		return 0, err
	}
	return token, nil
}

func issueRestrictedToken(creator restrictedTokenCreator, source xwindows.Token, disabled, restricting []xwindows.SIDAndAttributes) (xwindows.Token, error) {
	return creator.Create(source, restrictedTokenFlags, disabled, restricting)
}

func (win32RestrictedTokenCreator) Create(source xwindows.Token, flags uint32, disabled, restricting []xwindows.SIDAndAttributes) (xwindows.Token, error) {
	var disabledPtr, restrictingPtr uintptr
	if len(disabled) != 0 {
		disabledPtr = uintptr(unsafe.Pointer(&disabled[0]))
	}
	if len(restricting) != 0 {
		restrictingPtr = uintptr(unsafe.Pointer(&restricting[0]))
	}
	var token xwindows.Token
	result, _, callErr := createRestrictedTokenProc.Call(
		uintptr(source),
		uintptr(flags),
		uintptr(len(disabled)), disabledPtr,
		0, 0,
		uintptr(len(restricting)), restrictingPtr,
		uintptr(unsafe.Pointer(&token)),
	)
	runtime.KeepAlive(disabled)
	runtime.KeepAlive(restricting)
	if result == 0 {
		return 0, fmt.Errorf("windows sandbox: CreateRestrictedToken: %w", callErr)
	}
	return token, nil
}

func dangerousGroupSIDs() ([]*xwindows.SID, error) {
	sids := make([]*xwindows.SID, len(dangerousGroupSIDStrings))
	for index, text := range dangerousGroupSIDStrings {
		sid, err := xwindows.StringToSid(text)
		if err != nil {
			return nil, fmt.Errorf("windows sandbox: parse dangerous group SID %q: %w", text, err)
		}
		sids[index] = sid
	}
	return sids, nil
}

func parseRestrictingSIDs(sids []SID) ([]*xwindows.SID, error) {
	parsed := make([]*xwindows.SID, len(sids))
	for index, sid := range sids {
		if !sid.isRestrictedTierCapability() {
			return nil, fmt.Errorf("windows sandbox: restricting SID %d is not an executor or one-shot capability SID", index)
		}
		windowsSID, err := xwindows.StringToSid(sid.String())
		if err != nil || !windowsSID.IsValid() {
			return nil, fmt.Errorf("windows sandbox: restricting SID %d is invalid", index)
		}
		parsed[index] = windowsSID
		for prior := 0; prior < index; prior++ {
			if xwindows.EqualSid(windowsSID, parsed[prior]) {
				return nil, fmt.Errorf("windows sandbox: restricting SID %d is duplicated", index)
			}
		}
	}
	return parsed, nil
}

func ensureRestrictingSIDsAreNew(groups []xwindows.SIDAndAttributes, sids []*xwindows.SID) error {
	for _, sid := range sids {
		if sidInGroups(groups, sid) {
			return fmt.Errorf("windows sandbox: restricting SID %s is already a normal token group", sid)
		}
	}
	return nil
}

func validateRestrictedToken(token xwindows.Token, sourceIntegrity *xwindows.SID, disabledGroups []xwindows.SIDAndAttributes, sourcePrivileges []xwindows.LUIDAndAttributes, restrictingSIDs []*xwindows.SID) error {
	restricted, err := token.IsRestricted()
	if err != nil {
		return fmt.Errorf("windows sandbox: read restricted-token status: %w", err)
	}
	if !restricted {
		return errors.New("windows sandbox: Windows returned a token that is not restricted")
	}
	tokenType, err := tokenUint32Information(token, xwindows.TokenType)
	if err != nil {
		return fmt.Errorf("windows sandbox: read restricted token type: %w", err)
	}
	if tokenType != xwindows.TokenPrimary {
		return errors.New("windows sandbox: Windows returned a non-primary restricted token")
	}
	integrity, err := tokenIntegritySID(token)
	if err != nil {
		return fmt.Errorf("windows sandbox: read restricted integrity: %w", err)
	}
	if !xwindows.EqualSid(sourceIntegrity, integrity) {
		return errors.New("windows sandbox: restricted token integrity changed")
	}

	restrictedGroupInfo, err := readTokenGroups(token, xwindows.TokenRestrictedSids)
	if err != nil {
		return fmt.Errorf("windows sandbox: read restricting SID list: %w", err)
	}
	defer runtime.KeepAlive(restrictedGroupInfo.buffer)
	restrictedGroups := restrictedGroupInfo.groups
	if len(restrictedGroups) != len(restrictingSIDs) {
		return fmt.Errorf("windows sandbox: restricting SID count is %d, want %d", len(restrictedGroups), len(restrictingSIDs))
	}
	for _, sid := range restrictingSIDs {
		if !sidInGroups(restrictedGroups, sid) {
			return fmt.Errorf("windows sandbox: restricting SID %s is absent from result", sid)
		}
	}
	normalGroups, err := token.GetTokenGroups()
	if err != nil {
		return fmt.Errorf("windows sandbox: read restricted groups: %w", err)
	}
	for _, sid := range restrictingSIDs {
		if sidInGroups(normalGroups.AllGroups(), sid) {
			return fmt.Errorf("windows sandbox: restricting SID %s became a normal group", sid)
		}
	}
	attributes := make(map[string]uint32, normalGroups.GroupCount)
	for _, group := range normalGroups.AllGroups() {
		attributes[group.Sid.String()] = group.Attributes
	}
	for _, group := range disabledGroups {
		if attributes[group.Sid.String()]&xwindows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			return fmt.Errorf("windows sandbox: dangerous group %s was not disabled", group.Sid)
		}
	}
	if err := validateRemovedPrivileges(token, sourcePrivileges); err != nil {
		return err
	}
	return nil
}

func validateRemovedPrivileges(token xwindows.Token, source []xwindows.LUIDAndAttributes) error {
	remaining, err := tokenPrivilegeList(token)
	if err != nil {
		return fmt.Errorf("windows sandbox: read restricted privileges: %w", err)
	}
	remainingByLUID := make(map[xwindows.LUID]uint32, len(remaining))
	for _, privilege := range remaining {
		remainingByLUID[privilege.Luid] = privilege.Attributes
	}
	var traverse xwindows.LUID
	if err := xwindows.LookupPrivilegeValue(nil, xwindows.StringToUTF16Ptr("SeChangeNotifyPrivilege"), &traverse); err != nil {
		return fmt.Errorf("windows sandbox: look up traversal privilege: %w", err)
	}
	for _, privilege := range source {
		if privilege.Luid == traverse {
			continue
		}
		if _, present := remainingByLUID[privilege.Luid]; present {
			return fmt.Errorf("windows sandbox: privilege %08x:%08x was not removed", uint32(privilege.Luid.HighPart), privilege.Luid.LowPart)
		}
	}
	return nil
}

func readTokenInformation(token xwindows.Token, class uint32) ([]byte, error) {
	var needed uint32
	err := xwindows.GetTokenInformation(token, class, nil, 0, &needed)
	if err != nil && err != xwindows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}
	if needed == 0 {
		return nil, errors.New("empty token information")
	}
	buffer := make([]byte, needed)
	if err := xwindows.GetTokenInformation(token, class, &buffer[0], uint32(len(buffer)), &needed); err != nil {
		return nil, err
	}
	return buffer, nil
}

func tokenUint32Information(token xwindows.Token, class uint32) (uint32, error) {
	info, err := readTokenInformation(token, class)
	if err != nil {
		return 0, err
	}
	if len(info) < int(unsafe.Sizeof(uint32(0))) {
		return 0, errors.New("short token information")
	}
	return *(*uint32)(unsafe.Pointer(&info[0])), nil
}

type tokenGroupInformation struct {
	buffer []byte
	groups []xwindows.SIDAndAttributes
}

func readTokenGroups(token xwindows.Token, class uint32) (tokenGroupInformation, error) {
	info, err := readTokenInformation(token, class)
	if err != nil {
		return tokenGroupInformation{}, err
	}
	groups := (*xwindows.Tokengroups)(unsafe.Pointer(&info[0])).AllGroups()
	return tokenGroupInformation{buffer: info, groups: groups}, nil
}

func tokenPrivilegeList(token xwindows.Token) ([]xwindows.LUIDAndAttributes, error) {
	info, err := readTokenInformation(token, xwindows.TokenPrivileges)
	if err != nil {
		return nil, err
	}
	privileges := (*xwindows.Tokenprivileges)(unsafe.Pointer(&info[0])).AllPrivileges()
	return append([]xwindows.LUIDAndAttributes(nil), privileges...), nil
}

func tokenIntegritySID(token xwindows.Token) (*xwindows.SID, error) {
	info, err := readTokenInformation(token, xwindows.TokenIntegrityLevel)
	if err != nil {
		return nil, err
	}
	label := (*xwindows.Tokenmandatorylabel)(unsafe.Pointer(&info[0]))
	return label.Label.Sid.Copy()
}

func sidInGroups(groups []xwindows.SIDAndAttributes, sid *xwindows.SID) bool {
	for _, group := range groups {
		if xwindows.EqualSid(group.Sid, sid) {
			return true
		}
	}
	return false
}

func groupIsEnabledForAllow(groups []xwindows.SIDAndAttributes, sid *xwindows.SID) bool {
	for _, group := range groups {
		if xwindows.EqualSid(group.Sid, sid) {
			return group.Attributes&xwindows.SE_GROUP_USE_FOR_DENY_ONLY == 0
		}
	}
	return false
}
