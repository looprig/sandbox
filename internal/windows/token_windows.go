//go:build windows

package windows

import (
	"errors"
	"fmt"
	"runtime"
	"strings"
	"unsafe"

	xwindows "golang.org/x/sys/windows"
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
// restrictingSIDs participate only in write access checks (WRITE_RESTRICTED:
// this is the restricted tier's token, never the elevated broker's). The
// token's integrity level is deliberately preserved. Source must grant
// TOKEN_DUPLICATE and TOKEN_QUERY.
//
// The restricting list Windows receives is restrictingSIDs plus ONE further
// SID this function adds itself: source's own logon SID (S-1-5-5-X-Y, see
// tokenLogonSID). restrictingSIDs stay module trustees only — the logon SID
// never passes through parseRestrictingSIDs, the SID type, the trustee
// collision checks or any ACL projection — so it can never become an ACE
// trustee or be counted as a projection SID.
func CreateRestrictedToken(source xwindows.Token, restrictingSIDs []SID) (xwindows.Token, error) {
	return createRestrictedTokenWith(win32RestrictedTokenCreator{}, source, restrictingSIDs)
}

func createRestrictedTokenWith(creator restrictedTokenCreator, source xwindows.Token, restrictingSIDs []SID) (xwindows.Token, error) {
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
	sourceUser, err := source.GetTokenUser()
	if err != nil {
		return 0, fmt.Errorf("windows sandbox: read source user: %w", err)
	}
	if err := ensureRestrictingSIDsAreNew(sourceUser.User.Sid, sourceGroups.AllGroups(), parsedRestrictingSIDs); err != nil {
		return 0, err
	}
	logonSID, err := tokenLogonSID(sourceGroups.AllGroups())
	if err != nil {
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
	restrictingGroups := make([]xwindows.SIDAndAttributes, 0, len(parsedRestrictingSIDs)+1)
	for _, sid := range parsedRestrictingSIDs {
		restrictingGroups = append(restrictingGroups, xwindows.SIDAndAttributes{Sid: sid})
	}
	restrictingGroups = append(restrictingGroups, xwindows.SIDAndAttributes{Sid: logonSID})

	token, err := issueRestrictedToken(creator, source, tokenRestrictionWriteOnly, disabledGroups, restrictingGroups)
	runtime.KeepAlive(sourceGroups)
	runtime.KeepAlive(parsedRestrictingSIDs)
	if err != nil {
		return 0, err
	}
	if err := validateRestrictedToken(token, tokenRestrictionWriteOnly, sourceIntegrity, disabledGroups, sourcePrivileges, parsedRestrictingSIDs, logonSID); err != nil {
		token.Close()
		return 0, err
	}
	return token, nil
}

// issueRestrictedToken is the single CreateRestrictedToken call site for both
// tiers. The restriction contract is an explicit argument, never a shared
// default: the restricted tier needs WRITE_RESTRICTED and the elevated broker
// must not carry it (see tokenRestriction).
func issueRestrictedToken(creator restrictedTokenCreator, source xwindows.Token, restriction tokenRestriction, disabled, restricting []xwindows.SIDAndAttributes) (xwindows.Token, error) {
	flags, err := restriction.createFlags()
	if err != nil {
		return 0, err
	}
	return creator.Create(source, flags, disabled, restricting)
}

// tokenWriteRestricted reports whether Windows applies the token's
// restricting SIDs to write access checks only. IsRestricted is true for both
// contracts, so it cannot make this distinction.
func tokenWriteRestricted(token xwindows.Token) (bool, error) {
	info, err := readTokenInformation(token, tokenAccessInformationClass)
	if err != nil {
		return false, err
	}
	return tokenAccessInformationWriteRestricted(info)
}

// requireTokenRestriction reads the token's restriction contract back from
// Windows and refuses a token minted for the other tier.
func requireTokenRestriction(token xwindows.Token, restriction tokenRestriction) error {
	observed, err := tokenWriteRestricted(token)
	if err != nil {
		return fmt.Errorf("windows sandbox: read token restriction flags: %w", err)
	}
	return restriction.verify(observed)
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
		if !sid.isRestrictedTierTrustee() {
			return nil, fmt.Errorf("windows sandbox: restricting SID %d is not an executor or one-shot module trustee SID", index)
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

func ensureRestrictingSIDsAreNew(user *xwindows.SID, groups []xwindows.SIDAndAttributes, sids []*xwindows.SID) error {
	for _, sid := range sids {
		if user != nil && xwindows.EqualSid(user, sid) {
			return fmt.Errorf("windows sandbox: restricting SID %s is already the token user", sid)
		}
		if sidInGroups(groups, sid) {
			return fmt.Errorf("windows sandbox: restricting SID %s is already a normal token group", sid)
		}
	}
	return nil
}

// logonSIDPrefix is the authority and first sub-authority every logon SID
// carries: SECURITY_NT_AUTHORITY (5), SECURITY_LOGON_IDS_RID (5), followed by
// the two halves of the logon session's identifier.
const logonSIDPrefix = "S-1-5-5-"

// tokenLogonSID returns a copy of the one logon SID among groups: the group
// whose attributes carry SE_GROUP_LOGON_ID, which must read S-1-5-5-X-Y.
//
// The logon SID permits the restricting-list check for session objects whose
// DACL grants it access, including the interactive window station and desktop.
// It is not sufficient to initialize an implicit console host: hosted run
// 37042438148 still returned STATUS_DLL_INIT_FAILED with CREATE_NO_WINDOW,
// both with and without this SID. Pipe-backed spawns therefore use
// DETACHED_PROCESS; terminal requests use a separately created ConPTY.
//
// What it widens. The logon SID gates writes only (WRITE_RESTRICTED), so the
// child additionally passes the restricted write check exactly where an
// object's DACL grants the logon SID a write-class right: the logon
// session's own window station and desktop, and per-session objects created
// for it. A token's default DACL grants the logon SID only GENERIC_READ |
// GENERIC_EXECUTE, so the processes, pipes and other objects the user's own
// programs create are not among them, and files almost never name a logon
// SID. Workspace writes remain governed by the executor/grant ACL projection.
//
// A token with no logon SID — a service or batch session that was given
// none — fails closed: such a session has no interactive window station the
// SID could open, and guessing another restricting SID instead would widen
// writes without a reason. More than one is refused as ambiguous.
func tokenLogonSID(groups []xwindows.SIDAndAttributes) (*xwindows.SID, error) {
	var found *xwindows.SID
	for _, group := range groups {
		if group.Attributes&xwindows.SE_GROUP_LOGON_ID != xwindows.SE_GROUP_LOGON_ID {
			continue
		}
		if group.Sid == nil || !group.Sid.IsValid() || !strings.HasPrefix(group.Sid.String(), logonSIDPrefix) {
			return nil, fmt.Errorf("windows sandbox: source token's SE_GROUP_LOGON_ID group %v is not a logon SID (%sX-Y)", group.Sid, logonSIDPrefix)
		}
		if found != nil {
			return nil, fmt.Errorf("windows sandbox: source token carries more than one logon SID (%s and %s); the restricted tier needs exactly one for window-station/desktop access", found, group.Sid)
		}
		copied, err := group.Sid.Copy()
		if err != nil {
			return nil, fmt.Errorf("windows sandbox: copy source logon SID: %w", err)
		}
		found = copied
	}
	if found == nil {
		return nil, errors.New("windows sandbox: source token carries no logon SID (S-1-5-5-X-Y); the restricted tier adds it to the restricting SIDs so its children can open the session's window station and desktop, and a session without one (a service or batch logon) cannot run restricted-tier children")
	}
	return found, nil
}

// ensureModuleTrusteesAbsentFromCurrentToken prevents ACL projection from
// granting authority to a principal already carried by the host token. It must
// run before any ACE is applied; CreateRestrictedToken repeats the check at
// spawn time to cover a changed source token as well.
func ensureModuleTrusteesAbsentFromCurrentToken(sids []SID) error {
	parsed, err := parseRestrictingSIDs(sids)
	if err != nil {
		return err
	}
	var source xwindows.Token
	if err := xwindows.OpenProcessToken(xwindows.CurrentProcess(), xwindows.TOKEN_QUERY, &source); err != nil {
		return fmt.Errorf("windows sandbox: open source token for trustee collision check: %w", err)
	}
	defer source.Close()
	user, err := source.GetTokenUser()
	if err != nil {
		return fmt.Errorf("windows sandbox: read source user for trustee collision check: %w", err)
	}
	groups, err := source.GetTokenGroups()
	if err != nil {
		return fmt.Errorf("windows sandbox: read source groups for trustee collision check: %w", err)
	}
	return ensureRestrictingSIDsAreNew(user.User.Sid, groups.AllGroups(), parsed)
}

// validateRestrictedToken reads the issued token back. restrictingSIDs are
// the module trustees, which must be restricting SIDs and never normal
// groups; logonSID, when non-nil (the restricted tier only), is the source's
// logon SID, which must also be a restricting SID — and is, by construction,
// a normal group too, which is why it is checked apart from the trustees.
// The restricting list must hold exactly these and nothing else.
func validateRestrictedToken(token xwindows.Token, restriction tokenRestriction, sourceIntegrity *xwindows.SID, disabledGroups []xwindows.SIDAndAttributes, sourcePrivileges []xwindows.LUIDAndAttributes, restrictingSIDs []*xwindows.SID, logonSID *xwindows.SID) error {
	restricted, err := token.IsRestricted()
	if err != nil {
		return fmt.Errorf("windows sandbox: read restricted-token status: %w", err)
	}
	if !restricted {
		return errors.New("windows sandbox: Windows returned a token that is not restricted")
	}
	if err := requireTokenRestriction(token, restriction); err != nil {
		return err
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
	want := len(restrictingSIDs)
	if logonSID != nil {
		want++
	}
	if len(restrictedGroups) != want {
		return fmt.Errorf("windows sandbox: restricting SID count is %d, want %d (%d module trustees, logon SID expected %t)", len(restrictedGroups), want, len(restrictingSIDs), logonSID != nil)
	}
	for _, sid := range restrictingSIDs {
		if !sidInGroups(restrictedGroups, sid) {
			return fmt.Errorf("windows sandbox: restricting SID %s is absent from result", sid)
		}
	}
	if logonSID != nil && !sidInGroups(restrictedGroups, logonSID) {
		return fmt.Errorf("windows sandbox: logon SID %s is absent from the restricting SIDs", logonSID)
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
