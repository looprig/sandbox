//go:build windows

package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"slices"
	"strings"
	"syscall"
	"unsafe"

	win "golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

const accountPasswordAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+"

const (
	windowsLocalAccountNameLimit = 20
	windowsUsersGroup            = `S-1-5-32-545`
	serviceLogonRight            = "SeServiceLogonRight"
	interactiveLogonRight        = "SeDenyInteractiveLogonRight"
	remoteInteractiveLogonRight  = "SeDenyRemoteInteractiveLogonRight"
	networkLogonRight            = "SeDenyNetworkLogonRight"
)

var (
	errAccountNotFound          = errors.New("sandbox: Windows account not found")
	errAccountOwnershipMismatch = errors.New("sandbox: Windows account ownership mismatch")
)

type installationPrincipalNames struct {
	Offline string
	Online  string
	Service string
}

func deriveInstallationPrincipalNames(installationID string) (installationPrincipalNames, error) {
	if strings.TrimSpace(installationID) == "" {
		return installationPrincipalNames{}, errors.New("sandbox: Windows installation identity is required")
	}
	digest := sha256.Sum256([]byte(installationID))
	suffix := hex.EncodeToString(digest[:])[:12]
	return installationPrincipalNames{
		Offline: "lsb-o-" + suffix,
		Online:  "lsb-n-" + suffix,
		Service: "lsb-svc-" + suffix,
	}, nil
}

type sandboxAccountPolicy struct {
	PasswordNeverExpires bool
	HiddenFromUI         bool
	Groups               []string
	Rights               []string
	DenyRights           []string
}

func requiredSandboxAccountPolicy() sandboxAccountPolicy {
	return sandboxAccountPolicy{
		PasswordNeverExpires: true,
		HiddenFromUI:         true,
		Groups:               []string{windowsUsersGroup},
		Rights:               []string{serviceLogonRight},
		DenyRights:           []string{interactiveLogonRight, remoteInteractiveLogonRight, networkLogonRight},
	}
}

func (policy sandboxAccountPolicy) equal(other sandboxAccountPolicy) bool {
	return policy.PasswordNeverExpires == other.PasswordNeverExpires &&
		policy.HiddenFromUI == other.HiddenFromUI &&
		equalStringSets(policy.Groups, other.Groups) &&
		equalStringSets(policy.Rights, other.Rights) &&
		equalStringSets(policy.DenyRights, other.DenyRights)
}

func equalStringSets(left, right []string) bool {
	left, right = append([]string(nil), left...), append([]string(nil), right...)
	slices.Sort(left)
	slices.Sort(right)
	return slices.Equal(left, right)
}

type sandboxAccountRecord struct {
	Name   string
	SID    string
	Owned  bool
	Policy sandboxAccountPolicy
}

// accountAPI is deliberately transactional at the policy boundary. The real
// NetAPI/LSA adapter must either apply the complete record or return an error;
// callers never infer ownership merely from a matching account name.
type accountAPI interface {
	Lookup(name string) (sandboxAccountRecord, error)
	Create(record sandboxAccountRecord, password []byte) (sandboxAccountRecord, error)
	ApplyPolicy(record sandboxAccountRecord) error
	SetPassword(name string, password []byte) error
	Delete(name string) error
}

func reconcileSandboxAccount(api accountAPI, name string, password []byte, rotate bool) (sandboxAccountRecord, error) {
	defer zeroBytes(password)
	policy := requiredSandboxAccountPolicy()
	record, err := api.Lookup(name)
	if errors.Is(err, errAccountNotFound) {
		if len(password) == 0 {
			return sandboxAccountRecord{}, errors.New("sandbox: empty Windows account credential")
		}
		return api.Create(sandboxAccountRecord{Name: name, Owned: true, Policy: policy}, password)
	}
	if err != nil {
		return sandboxAccountRecord{}, err
	}
	if !record.Owned || record.Name != name || record.SID == "" {
		return sandboxAccountRecord{}, errAccountOwnershipMismatch
	}
	if !record.Policy.equal(policy) {
		record.Policy = policy
		if err := api.ApplyPolicy(record); err != nil {
			return sandboxAccountRecord{}, err
		}
	}
	if rotate {
		if len(password) == 0 {
			return sandboxAccountRecord{}, errors.New("sandbox: empty Windows account credential")
		}
		if err := api.SetPassword(name, password); err != nil {
			return sandboxAccountRecord{}, err
		}
	}
	return record, nil
}

func removeSandboxAccount(api accountAPI, name, manifestSID string) error {
	if name == "" || manifestSID == "" {
		return errAccountOwnershipMismatch
	}
	record, err := api.Lookup(name)
	if errors.Is(err, errAccountNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !record.Owned || record.Name != name || record.SID != manifestSID {
		return errAccountOwnershipMismatch
	}
	return api.Delete(name)
}

func zeroBytes(data []byte) {
	for index := range data {
		data[index] = 0
	}
}

func newAccountPassword(random io.Reader, length int) ([]byte, error) {
	if random == nil || length < 32 {
		return nil, errors.New("sandbox: Windows account password length is too small")
	}
	password := make([]byte, length)
	randomByte := []byte{0}
	// Rejection sampling avoids modulo bias while keeping the result directly
	// consumable as a mutable buffer that can be wiped after NetUserSetInfo.
	limit := byte(256 - (256 % len(accountPasswordAlphabet)))
	for index := range password {
		for {
			if _, err := io.ReadFull(random, randomByte); err != nil {
				zeroBytes(password)
				return nil, err
			}
			if randomByte[0] < limit {
				password[index] = accountPasswordAlphabet[int(randomByte[0])%len(accountPasswordAlphabet)]
				break
			}
		}
	}
	return password, nil
}

type nativeAccountState struct {
	SID    string
	Policy sandboxAccountPolicy
}

type accountNative interface {
	Lookup(name string) (nativeAccountState, error)
	Create(name string, password []byte) error
	SetPassword(name string, password []byte) error
	SetPolicy(name, sid string, policy sandboxAccountPolicy) error
	Delete(name, sid string) error
}

type netLSAAccountAPI struct {
	native   accountNative
	ownedSID map[string]string
}

func (api netLSAAccountAPI) Lookup(name string) (sandboxAccountRecord, error) {
	state, err := api.native.Lookup(name)
	if err != nil {
		return sandboxAccountRecord{}, err
	}
	return sandboxAccountRecord{Name: name, SID: state.SID, Policy: state.Policy, Owned: api.ownedSID[name] != "" && api.ownedSID[name] == state.SID}, nil
}

func (api netLSAAccountAPI) Create(record sandboxAccountRecord, password []byte) (sandboxAccountRecord, error) {
	if api.ownedSID[record.Name] != "" {
		return sandboxAccountRecord{}, errAccountOwnershipMismatch
	}
	if err := api.native.Create(record.Name, password); err != nil {
		return sandboxAccountRecord{}, err
	}
	state, err := api.native.Lookup(record.Name)
	if err != nil || state.SID == "" {
		return sandboxAccountRecord{}, errors.Join(errors.New("sandbox: created Windows account failed SID read-back"), err)
	}
	if err := api.native.SetPolicy(record.Name, state.SID, record.Policy); err != nil {
		return sandboxAccountRecord{}, errors.Join(err, api.native.Delete(record.Name, state.SID))
	}
	state, err = api.native.Lookup(record.Name)
	if err != nil || state.SID == "" || !state.Policy.equal(record.Policy) {
		return sandboxAccountRecord{}, errors.Join(errors.New("sandbox: created Windows account policy failed read-back"), err, api.native.Delete(record.Name, state.SID))
	}
	api.ownedSID[record.Name] = state.SID
	return sandboxAccountRecord{Name: record.Name, SID: state.SID, Owned: true, Policy: state.Policy}, nil
}

func (api netLSAAccountAPI) ApplyPolicy(record sandboxAccountRecord) error {
	if api.ownedSID[record.Name] != record.SID {
		return errAccountOwnershipMismatch
	}
	if err := api.native.SetPolicy(record.Name, record.SID, record.Policy); err != nil {
		return err
	}
	state, err := api.native.Lookup(record.Name)
	if err != nil {
		return err
	}
	if state.SID != record.SID || !state.Policy.equal(record.Policy) {
		return errors.New("sandbox: Windows account policy failed read-back")
	}
	return nil
}

func (api netLSAAccountAPI) SetPassword(name string, password []byte) error {
	if api.ownedSID[name] == "" {
		return errAccountOwnershipMismatch
	}
	return api.native.SetPassword(name, password)
}

func (api netLSAAccountAPI) Delete(name string) error {
	sid := api.ownedSID[name]
	if sid == "" {
		return errAccountOwnershipMismatch
	}
	return api.native.Delete(name, sid)
}

const (
	userPrivUser                       = 1
	ufScript                           = 0x0001
	ufNormalAccount                    = 0x0200
	ufDontExpirePassword               = 0x10000
	nerrUserNotFound     syscall.Errno = 2221
	maxPreferredLength                 = 0xffffffff
	policyLookupNames                  = 0x00000800
)

type userInfo1 struct {
	Name, Password    *uint16
	PasswordAge, Priv uint32
	HomeDir, Comment  *uint16
	Flags             uint32
	ScriptPath        *uint16
}
type userInfo1003 struct{ Password *uint16 }
type userInfo1008 struct{ Flags uint32 }
type localGroupUsersInfo0 struct{ Name *uint16 }
type localGroupMembersInfo0 struct{ SID *win.SID }
type lsaObjectAttributes struct {
	Length                                       uint32
	RootDirectory                                uintptr
	ObjectName                                   uintptr
	Attributes                                   uint32
	SecurityDescriptor, SecurityQualityOfService uintptr
}
type lsaUnicodeString struct {
	Length, MaximumLength uint16
	Buffer                *uint16
}

var (
	modNetAPI                     = win.NewLazySystemDLL("netapi32.dll")
	procNetUserAdd                = modNetAPI.NewProc("NetUserAdd")
	procNetUserDel                = modNetAPI.NewProc("NetUserDel")
	procNetUserSetInfo            = modNetAPI.NewProc("NetUserSetInfo")
	procNetUserGetLocalGroups     = modNetAPI.NewProc("NetUserGetLocalGroups")
	procNetLocalGroupAddMembers   = modNetAPI.NewProc("NetLocalGroupAddMembers")
	procNetLocalGroupDelMembers   = modNetAPI.NewProc("NetLocalGroupDelMembers")
	modAdvapiAccount              = win.NewLazySystemDLL("advapi32.dll")
	procLsaOpenPolicy             = modAdvapiAccount.NewProc("LsaOpenPolicy")
	procLsaClose                  = modAdvapiAccount.NewProc("LsaClose")
	procLsaFreeMemory             = modAdvapiAccount.NewProc("LsaFreeMemory")
	procLsaAddAccountRights       = modAdvapiAccount.NewProc("LsaAddAccountRights")
	procLsaRemoveAccountRights    = modAdvapiAccount.NewProc("LsaRemoveAccountRights")
	procLsaEnumerateAccountRights = modAdvapiAccount.NewProc("LsaEnumerateAccountRights")
	procLsaNtStatusToWinError     = modAdvapiAccount.NewProc("LsaNtStatusToWinError")
)

type realAccountNative struct{}

func (realAccountNative) Lookup(name string) (nativeAccountState, error) {
	namePtr, err := win.UTF16PtrFromString(name)
	if err != nil {
		return nativeAccountState{}, err
	}
	var buffer *byte
	if err := win.NetUserGetInfo(nil, namePtr, 1, &buffer); err != nil {
		if errors.Is(err, nerrUserNotFound) {
			return nativeAccountState{}, errAccountNotFound
		}
		return nativeAccountState{}, err
	}
	defer win.NetApiBufferFree(buffer)
	info := (*userInfo1)(unsafe.Pointer(buffer))
	sid, _, _, err := win.LookupSID("", name)
	if err != nil {
		return nativeAccountState{}, err
	}
	groups, err := enumerateLocalGroups(namePtr)
	if err != nil {
		return nativeAccountState{}, err
	}
	rights, err := enumerateAccountRights(sid)
	if err != nil {
		return nativeAccountState{}, err
	}
	hidden, err := accountHidden(name)
	if err != nil {
		return nativeAccountState{}, err
	}
	policy := sandboxAccountPolicy{PasswordNeverExpires: info.Flags&ufDontExpirePassword != 0, HiddenFromUI: hidden, Groups: groups}
	for _, right := range rights {
		if strings.HasPrefix(right, "SeDeny") {
			policy.DenyRights = append(policy.DenyRights, right)
		} else {
			policy.Rights = append(policy.Rights, right)
		}
	}
	return nativeAccountState{SID: sid.String(), Policy: policy}, nil
}

func (realAccountNative) Create(name string, password []byte) error {
	name16, err := win.UTF16FromString(name)
	if err != nil {
		return err
	}
	password16 := passwordUTF16(password)
	defer zeroUTF16(password16)
	info := userInfo1{Name: &name16[0], Password: &password16[0], Priv: userPrivUser, Flags: ufScript | ufNormalAccount | ufDontExpirePassword}
	status, _, _ := procNetUserAdd.Call(0, 1, uintptr(unsafe.Pointer(&info)), 0)
	if status != 0 {
		return syscall.Errno(status)
	}
	return nil
}

func (realAccountNative) SetPassword(name string, password []byte) error {
	namePtr, err := win.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	password16 := passwordUTF16(password)
	defer zeroUTF16(password16)
	info := userInfo1003{Password: &password16[0]}
	status, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(namePtr)), 1003, uintptr(unsafe.Pointer(&info)), 0)
	if status != 0 {
		return syscall.Errno(status)
	}
	return nil
}

func (realAccountNative) SetPolicy(name, sidText string, policy sandboxAccountPolicy) error {
	if !policy.equal(requiredSandboxAccountPolicy()) {
		return errors.New("sandbox: unsafe Windows account policy")
	}
	namePtr, err := win.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var buffer *byte
	if err := win.NetUserGetInfo(nil, namePtr, 1, &buffer); err != nil {
		return err
	}
	flags := (*userInfo1)(unsafe.Pointer(buffer)).Flags
	win.NetApiBufferFree(buffer)
	info := userInfo1008{Flags: flags | ufDontExpirePassword | ufNormalAccount}
	status, _, _ := procNetUserSetInfo.Call(0, uintptr(unsafe.Pointer(namePtr)), 1008, uintptr(unsafe.Pointer(&info)), 0)
	if status != 0 {
		return syscall.Errno(status)
	}
	if err := setLocalGroupsExact(name, policy.Groups); err != nil {
		return err
	}
	sid, err := win.StringToSid(sidText)
	if err != nil {
		return err
	}
	if err := setAccountRightsExact(sid, append(append([]string{}, policy.Rights...), policy.DenyRights...)); err != nil {
		return err
	}
	return setAccountHidden(name, policy.HiddenFromUI)
}

func (realAccountNative) Delete(name, sidText string) error {
	sid, err := win.StringToSid(sidText)
	if err != nil {
		return err
	}
	if err := setAccountRightsExact(sid, nil); err != nil {
		return err
	}
	_ = setAccountHidden(name, false)
	namePtr, err := win.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	status, _, _ := procNetUserDel.Call(0, uintptr(unsafe.Pointer(namePtr)))
	if status == uintptr(nerrUserNotFound) {
		return nil
	}
	if status != 0 {
		return syscall.Errno(status)
	}
	return nil
}

func passwordUTF16(password []byte) []uint16 {
	result := make([]uint16, len(password)+1)
	for i, b := range password {
		result[i] = uint16(b)
	}
	return result
}
func zeroUTF16(data []uint16) {
	for i := range data {
		data[i] = 0
	}
}

func enumerateLocalGroups(name *uint16) ([]string, error) {
	var buffer *byte
	var read, total uint32
	status, _, _ := procNetUserGetLocalGroups.Call(0, uintptr(unsafe.Pointer(name)), 0, 0, uintptr(unsafe.Pointer(&buffer)), maxPreferredLength, uintptr(unsafe.Pointer(&read)), uintptr(unsafe.Pointer(&total)))
	if status != 0 {
		return nil, syscall.Errno(status)
	}
	if buffer != nil {
		defer win.NetApiBufferFree(buffer)
	}
	entries := unsafe.Slice((*localGroupUsersInfo0)(unsafe.Pointer(buffer)), int(read))
	result := make([]string, len(entries))
	for i, entry := range entries {
		groupSID, _, _, lookupErr := win.LookupSID("", win.UTF16PtrToString(entry.Name))
		if lookupErr != nil {
			return nil, lookupErr
		}
		result[i] = groupSID.String()
	}
	return result, nil
}

func setLocalGroupsExact(name string, want []string) error {
	namePtr, _ := win.UTF16PtrFromString(name)
	current, err := enumerateLocalGroups(namePtr)
	if err != nil {
		return err
	}
	wanted := make(map[string]bool, len(want))
	for _, group := range want {
		wanted[strings.ToLower(group)] = true
	}
	accountSID, _, _, err := win.LookupSID("", name)
	if err != nil {
		return err
	}
	memberInfo := localGroupMembersInfo0{SID: accountSID}
	for _, group := range current {
		if !wanted[strings.ToLower(group)] {
			groupSID, err := win.StringToSid(group)
			if err != nil {
				return err
			}
			groupName, _, _, err := groupSID.LookupAccount("")
			if err != nil {
				return err
			}
			groupPtr, _ := win.UTF16PtrFromString(groupName)
			status, _, _ := procNetLocalGroupDelMembers.Call(0, uintptr(unsafe.Pointer(groupPtr)), 0, uintptr(unsafe.Pointer(&memberInfo)), 1)
			if status != 0 {
				return syscall.Errno(status)
			}
		}
	}
	currentSet := map[string]bool{}
	for _, group := range current {
		currentSet[strings.ToLower(group)] = true
	}
	for _, group := range want {
		if !currentSet[strings.ToLower(group)] {
			groupSID, err := win.StringToSid(group)
			if err != nil {
				return err
			}
			groupName, _, _, err := groupSID.LookupAccount("")
			if err != nil {
				return err
			}
			groupPtr, _ := win.UTF16PtrFromString(groupName)
			status, _, _ := procNetLocalGroupAddMembers.Call(0, uintptr(unsafe.Pointer(groupPtr)), 0, uintptr(unsafe.Pointer(&memberInfo)), 1)
			if status != 0 {
				return syscall.Errno(status)
			}
		}
	}
	return nil
}

func openLSAPolicy() (win.Handle, error) {
	attributes := lsaObjectAttributes{Length: uint32(unsafe.Sizeof(lsaObjectAttributes{}))}
	var handle win.Handle
	status, _, _ := procLsaOpenPolicy.Call(0, uintptr(unsafe.Pointer(&attributes)), policyLookupNames, uintptr(unsafe.Pointer(&handle)))
	return handle, lsaStatusError(status)
}
func lsaStatusError(status uintptr) error {
	if status == 0 {
		return nil
	}
	code, _, _ := procLsaNtStatusToWinError.Call(status)
	return syscall.Errno(code)
}
func lsaString(value string) (lsaUnicodeString, []uint16, error) {
	data, err := win.UTF16FromString(value)
	if err != nil {
		return lsaUnicodeString{}, nil, err
	}
	return lsaUnicodeString{Length: uint16((len(data) - 1) * 2), MaximumLength: uint16(len(data) * 2), Buffer: &data[0]}, data, nil
}

func enumerateAccountRights(sid *win.SID) ([]string, error) {
	handle, err := openLSAPolicy()
	if err != nil {
		return nil, err
	}
	defer procLsaClose.Call(uintptr(handle))
	var rights *lsaUnicodeString
	var count uint32
	status, _, _ := procLsaEnumerateAccountRights.Call(uintptr(handle), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&rights)), uintptr(unsafe.Pointer(&count)))
	if status != 0 {
		code := lsaStatusError(status)
		if errors.Is(code, syscall.Errno(2)) {
			return nil, nil
		}
		return nil, code
	}
	defer procLsaFreeMemory.Call(uintptr(unsafe.Pointer(rights)))
	entries := unsafe.Slice(rights, int(count))
	result := make([]string, len(entries))
	for i, entry := range entries {
		result[i] = win.UTF16PtrToString(entry.Buffer)[:entry.Length/2]
	}
	return result, nil
}

func setAccountRightsExact(sid *win.SID, want []string) error {
	handle, err := openLSAPolicy()
	if err != nil {
		return err
	}
	defer procLsaClose.Call(uintptr(handle))
	current, err := enumerateAccountRights(sid)
	if err != nil {
		return err
	}
	wanted := map[string]bool{}
	for _, right := range want {
		wanted[right] = true
	}
	for _, right := range current {
		if !wanted[right] {
			value, keep, err := lsaString(right)
			if err != nil {
				return err
			}
			status, _, _ := procLsaRemoveAccountRights.Call(uintptr(handle), uintptr(unsafe.Pointer(sid)), 0, uintptr(unsafe.Pointer(&value)), 1)
			_ = keep
			if err := lsaStatusError(status); err != nil {
				return err
			}
		}
	}
	currentSet := map[string]bool{}
	for _, right := range current {
		currentSet[right] = true
	}
	for _, right := range want {
		if !currentSet[right] {
			value, keep, err := lsaString(right)
			if err != nil {
				return err
			}
			status, _, _ := procLsaAddAccountRights.Call(uintptr(handle), uintptr(unsafe.Pointer(sid)), uintptr(unsafe.Pointer(&value)), 1)
			_ = keep
			if err := lsaStatusError(status); err != nil {
				return err
			}
		}
	}
	return nil
}

const hiddenAccountsRegistryPath = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`

func setAccountHidden(name string, hidden bool) error {
	key, _, err := registry.CreateKey(registry.LOCAL_MACHINE, hiddenAccountsRegistryPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer key.Close()
	if hidden {
		return key.SetDWordValue(name, 0)
	}
	err = key.DeleteValue(name)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return nil
	}
	return err
}
func accountHidden(name string) (bool, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, hiddenAccountsRegistryPath, registry.QUERY_VALUE)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer key.Close()
	value, _, err := key.GetIntegerValue(name)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return false, nil
	}
	return err == nil && value == 0, err
}
