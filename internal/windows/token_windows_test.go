//go:build windows

package windows

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unsafe"

	xwindows "golang.org/x/sys/windows"
)

func TestCreateRestrictedTokenShape(t *testing.T) {
	var source xwindows.Token
	if err := xwindows.OpenProcessToken(xwindows.CurrentProcess(), xwindows.TOKEN_DUPLICATE|xwindows.TOKEN_ASSIGN_PRIMARY|xwindows.TOKEN_QUERY|xwindows.TOKEN_ADJUST_PRIVILEGES, &source); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer source.Close()

	executor, err := ExecutorSID("test-installation", "test-executor")
	if err != nil {
		t.Fatal(err)
	}
	grant, err := ExecutorSID("test-installation", "test-grant")
	if err != nil {
		t.Fatal(err)
	}
	token, err := CreateRestrictedToken(source, []SID{executor, grant})
	sourceRestricted, restrictedErr := source.IsRestricted()
	if restrictedErr != nil {
		t.Fatalf("query source token: %v", restrictedErr)
	}
	if sourceRestricted {
		if err == nil || token != 0 {
			if token != 0 {
				token.Close()
			}
			t.Fatal("already-restricted source did not fail closed")
		}
		t.Fatalf("live token-shape prerequisite unavailable: current process token is already restricted; constructor correctly failed closed: %v", err)
	}
	if err != nil {
		t.Fatalf("create restricted token: %v", err)
	}
	defer token.Close()
	executorSID := mustTestSID(t, executor.String())
	grantSID := mustTestSID(t, grant.String())

	restricted, err := token.IsRestricted()
	if err != nil {
		t.Fatalf("query restricted status: %v", err)
	}
	if !restricted {
		t.Fatal("created token is not restricted")
	}

	if writeOnly, err := tokenWriteRestricted(token); err != nil || !writeOnly {
		t.Fatalf("restricted-tier token write-restricted = %v, %v; want true", writeOnly, err)
	}
	assertTokenType(t, token, xwindows.TokenPrimary)
	assertIntegrityUnchanged(t, source, token)
	assertOnlyRestrictingSIDs(t, token, executorSID, grantSID, mustSourceLogonSID(t, source))
	assertSIDsNotNormalGroups(t, token, executorSID, grantSID)
	assertDangerousGroupsDisabled(t, source, token)
	assertSafeRuntimeGroupPreserved(t, source, token)
	assertPrivilegesRemoved(t, source, token)
}

func TestRestrictedTokenCallUsesExactFlagsAndLists(t *testing.T) {
	disabledSID := mustTestSID(t, "S-1-5-32-544")
	restrictingSID := mustTestSID(t, "S-1-5-21-314159-265358-979323-1001")
	disabled := []xwindows.SIDAndAttributes{{Sid: disabledSID}}
	restricting := []xwindows.SIDAndAttributes{{Sid: restrictingSID}}
	for _, test := range []struct {
		name        string
		restriction tokenRestriction
		want        uint32
	}{
		{"restricted tier", tokenRestrictionWriteOnly, disableMaxPrivilege | luaToken | writeRestricted},
		{"elevated broker", tokenRestrictionFull, disableMaxPrivilege | luaToken},
	} {
		t.Run(test.name, func(t *testing.T) {
			fake := &recordingRestrictedTokenCreator{returnToken: xwindows.Token(42)}
			got, err := issueRestrictedToken(fake, xwindows.Token(7), test.restriction, disabled, restricting)
			if err != nil {
				t.Fatalf("issue restricted token: %v", err)
			}
			if got != 42 || fake.source != 7 {
				t.Fatalf("token/source = %d/%d, want 42/7", got, fake.source)
			}
			if fake.flags != test.want {
				t.Fatalf("flags = %#x, want %#x", fake.flags, test.want)
			}
			if len(fake.disabled) != 1 || !xwindows.EqualSid(fake.disabled[0].Sid, disabledSID) {
				t.Fatalf("disabled groups = %#v, want Administrators", fake.disabled)
			}
			if len(fake.restricting) != 1 || !xwindows.EqualSid(fake.restricting[0].Sid, restrictingSID) {
				t.Fatalf("restricting groups = %#v, want executor SID", fake.restricting)
			}
		})
	}
	fake := &recordingRestrictedTokenCreator{returnToken: xwindows.Token(42)}
	if _, err := issueRestrictedToken(fake, xwindows.Token(7), tokenRestriction(0), disabled, restricting); err == nil || fake.calls != 0 {
		t.Fatalf("unspecified restriction reached CreateRestrictedToken: calls=%d err=%v", fake.calls, err)
	}
}

// TestTierConstructorsPassTheirOwnRestrictionFlags drives both production
// constructors up to the CreateRestrictedToken call. The recording creator
// fails the call so no fabricated handle is ever validated or closed.
func TestTierConstructorsPassTheirOwnRestrictionFlags(t *testing.T) {
	var source xwindows.Token
	if err := xwindows.OpenProcessToken(xwindows.CurrentProcess(), xwindows.TOKEN_DUPLICATE|xwindows.TOKEN_QUERY, &source); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer source.Close()
	if restricted, err := source.IsRestricted(); err != nil || restricted {
		t.Fatalf("token-flag prerequisite unavailable: current process token restricted=%v err=%v", restricted, err)
	}
	executor, err := ExecutorSID("tier-flags-installation", "tier-flags-executor")
	if err != nil {
		t.Fatal(err)
	}
	installation, err := InstallationSID("tier-flags-installation")
	if err != nil {
		t.Fatal(err)
	}
	injected := errors.New("injected CreateRestrictedToken failure")

	restricted := &recordingRestrictedTokenCreator{err: injected}
	if token, err := createRestrictedTokenWith(restricted, source, []SID{executor}); !errors.Is(err, injected) || token != 0 {
		t.Fatalf("restricted-tier constructor = %d, %v; want injected failure", token, err)
	}
	if restricted.calls != 1 || restricted.flags != disableMaxPrivilege|luaToken|writeRestricted {
		t.Fatalf("restricted-tier flags = %#x (calls %d), want DISABLE_MAX_PRIVILEGE|LUA_TOKEN|WRITE_RESTRICTED", restricted.flags, restricted.calls)
	}
	// The restricted tier's list is the executor followed by the source's
	// logon SID, which appears exactly once (window-station/desktop access,
	// see tokenLogonSID); the broker's list never carries it.
	logon := mustSourceLogonSID(t, source)
	executorSID := mustTestSID(t, executor.String())
	if len(restricted.restricting) != 2 || !xwindows.EqualSid(restricted.restricting[0].Sid, executorSID) || countSID(restricted.restricting, logon) != 1 {
		t.Fatalf("restricted-tier restricting SIDs = %v, want [%s %s] with the logon SID exactly once", sidList(restricted.restricting), executorSID, logon)
	}

	broker := &recordingRestrictedTokenCreator{err: injected}
	if token, err := createBrokerRestrictedTokenWith(broker, source, []SID{restrictedCodeSID(), installation, executor}); !errors.Is(err, injected) || token != 0 {
		t.Fatalf("broker constructor = %d, %v; want injected failure", token, err)
	}
	if broker.calls != 1 || broker.flags != disableMaxPrivilege|luaToken {
		t.Fatalf("broker flags = %#x (calls %d), want DISABLE_MAX_PRIVILEGE|LUA_TOKEN", broker.flags, broker.calls)
	}
	if broker.flags&writeRestricted != 0 {
		t.Fatal("elevated broker token requested WRITE_RESTRICTED")
	}
	if len(broker.restricting) != 3 || countSID(broker.restricting, logon) != 0 {
		t.Fatalf("broker restricting SIDs = %v, want its three trustees and no logon SID", sidList(broker.restricting))
	}
}

// TestRestrictedTokenValidatorRequiresTheLogonSID drives the read-back
// validator against two real tokens issued from this process's token: one
// whose restricting list omits the logon SID (refused: the restricted tier's
// children could not open their desktop) and one that carries it (accepted).
func TestRestrictedTokenValidatorRequiresTheLogonSID(t *testing.T) {
	var source xwindows.Token
	if err := xwindows.OpenProcessToken(xwindows.CurrentProcess(), xwindows.TOKEN_DUPLICATE|xwindows.TOKEN_QUERY, &source); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer source.Close()
	if restricted, err := source.IsRestricted(); err != nil || restricted {
		t.Fatalf("token prerequisite unavailable: current process token restricted=%v err=%v", restricted, err)
	}
	executor, err := ExecutorSID("logon-validator-installation", "logon-validator-executor")
	if err != nil {
		t.Fatal(err)
	}
	executorSID := mustTestSID(t, executor.String())
	logon := mustSourceLogonSID(t, source)
	integrity, err := tokenIntegritySID(source)
	if err != nil {
		t.Fatal(err)
	}
	privileges, err := tokenPrivilegeList(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		restricting []xwindows.SIDAndAttributes
		wantErr     string
	}{
		{"without logon SID", []xwindows.SIDAndAttributes{{Sid: executorSID}}, "restricting SID count is 1, want 2"},
		{"with logon SID", []xwindows.SIDAndAttributes{{Sid: executorSID}, {Sid: logon}}, ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			token, err := issueRestrictedToken(win32RestrictedTokenCreator{}, source, tokenRestrictionWriteOnly, nil, test.restricting)
			if err != nil {
				t.Fatal(err)
			}
			defer token.Close()
			err = validateRestrictedToken(token, tokenRestrictionWriteOnly, integrity, nil, privileges, []*xwindows.SID{executorSID}, logon)
			switch {
			case test.wantErr == "" && err != nil:
				t.Fatalf("validator refused a token carrying the logon SID: %v", err)
			case test.wantErr != "" && (err == nil || !strings.Contains(err.Error(), test.wantErr)):
				t.Fatalf("validator = %v, want an error containing %q", err, test.wantErr)
			}
		})
	}
}

func TestTokenLogonSIDSelectsExactlyOneLogonGroup(t *testing.T) {
	logon := mustTestSID(t, "S-1-5-5-0-123456")
	other := mustTestSID(t, "S-1-5-5-0-654321")
	users := mustTestSID(t, "S-1-5-32-545")
	logonAttributes := uint32(xwindows.SE_GROUP_LOGON_ID | xwindows.SE_GROUP_ENABLED | xwindows.SE_GROUP_MANDATORY)
	got, err := tokenLogonSID([]xwindows.SIDAndAttributes{{Sid: users, Attributes: xwindows.SE_GROUP_ENABLED}, {Sid: logon, Attributes: logonAttributes}})
	if err != nil || !xwindows.EqualSid(got, logon) {
		t.Fatalf("tokenLogonSID = %v, %v; want %s", got, err, logon)
	}
	for _, test := range []struct {
		name   string
		groups []xwindows.SIDAndAttributes
	}{
		{"none", []xwindows.SIDAndAttributes{{Sid: users, Attributes: xwindows.SE_GROUP_ENABLED}}},
		// S-1-5-5-X-Y text without the attribute is not the token's logon group.
		{"logon-shaped but unmarked", []xwindows.SIDAndAttributes{{Sid: logon, Attributes: xwindows.SE_GROUP_ENABLED}}},
		{"two", []xwindows.SIDAndAttributes{{Sid: logon, Attributes: logonAttributes}, {Sid: other, Attributes: logonAttributes}}},
		{"marked but not S-1-5-5", []xwindows.SIDAndAttributes{{Sid: users, Attributes: logonAttributes}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := tokenLogonSID(test.groups); err == nil {
				t.Fatalf("tokenLogonSID accepted %s: %s", test.name, got)
			}
		})
	}
}

// mustSourceLogonSID is source's logon SID, as tokenLogonSID reads it.
func mustSourceLogonSID(t *testing.T, source xwindows.Token) *xwindows.SID {
	t.Helper()
	groups, err := source.GetTokenGroups()
	if err != nil {
		t.Fatalf("read source groups: %v", err)
	}
	logon, err := tokenLogonSID(groups.AllGroups())
	if err != nil {
		t.Fatalf("source logon SID: %v", err)
	}
	return logon
}

func countSID(groups []xwindows.SIDAndAttributes, sid *xwindows.SID) int {
	count := 0
	for _, group := range groups {
		if xwindows.EqualSid(group.Sid, sid) {
			count++
		}
	}
	return count
}

func sidList(groups []xwindows.SIDAndAttributes) []string {
	list := make([]string, 0, len(groups))
	for _, group := range groups {
		list = append(list, group.Sid.String())
	}
	return list
}

// TestRestrictionContractReadBackAndValidators runs on any Windows host: both
// token shapes are derived from the unprivileged current-process token, and
// the elevated validators must refuse the write-restricted one.
func TestRestrictionContractReadBackAndValidators(t *testing.T) {
	var source xwindows.Token
	if err := xwindows.OpenProcessToken(xwindows.CurrentProcess(), xwindows.TOKEN_DUPLICATE|xwindows.TOKEN_QUERY, &source); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer source.Close()
	if restricted, err := source.IsRestricted(); err != nil || restricted {
		t.Fatalf("token-shape prerequisite unavailable: current process token restricted=%v err=%v", restricted, err)
	}
	executor, err := ExecutorSID("contract-installation", "contract-executor")
	if err != nil {
		t.Fatal(err)
	}
	installation, err := InstallationSID("contract-installation")
	if err != nil {
		t.Fatal(err)
	}

	writeOnly, err := CreateRestrictedToken(source, []SID{executor})
	if err != nil {
		t.Fatalf("create restricted-tier token: %v", err)
	}
	defer writeOnly.Close()
	full, err := createBrokerRestrictedToken(source, []SID{restrictedCodeSID(), installation, executor})
	if err != nil {
		t.Fatalf("create fully restricted broker token: %v", err)
	}
	defer full.Close()

	if got, err := tokenWriteRestricted(writeOnly); err != nil || !got {
		t.Fatalf("restricted-tier token write-restricted = %v, %v; want true", got, err)
	}
	if got, err := tokenWriteRestricted(full); err != nil || got {
		t.Fatalf("broker token write-restricted = %v, %v; want false", got, err)
	}
	if err := requireTokenRestriction(writeOnly, tokenRestrictionFull); err == nil {
		t.Fatal("full-restriction check accepted a WRITE_RESTRICTED token")
	}
	if err := requireTokenRestriction(full, tokenRestrictionWriteOnly); err == nil {
		t.Fatal("restricted-tier check accepted a fully restricted token")
	}

	api := nativeElevatedRunnerProcessAPI{}
	if err := api.VerifyToken(writeOnly); err == nil || !strings.Contains(err.Error(), "write-restricted") {
		t.Fatalf("runner VerifyToken accepted a WRITE_RESTRICTED token: %v", err)
	}
	if err := api.VerifyToken(full); err != nil {
		t.Fatalf("runner VerifyToken refused a fully restricted token: %v", err)
	}
	// validateBrokerTokenHandle checks the contract before the account, so a
	// write-restricted token is refused for that reason specifically.
	config := elevatedBrokerLeaseConfig{InstallationID: "contract-installation", OfflineSID: "S-1-5-21-1-2-3-1001", OnlineSID: "S-1-5-21-1-2-3-1002"}
	if _, err := validateBrokerTokenHandle(uint64(writeOnly), config, brokerAccountOffline); err == nil || !strings.Contains(err.Error(), "write-restricted") {
		t.Fatalf("client broker-token validation accepted a WRITE_RESTRICTED token: %v", err)
	}
}

func TestModuleTrusteeMatchesWindowsDerivation(t *testing.T) {
	const installationID = "windows-derivation-installation"
	const executorID = "windows-derivation-executor"
	want, err := ExecutorSID(installationID, executorID)
	if err != nil {
		t.Fatal(err)
	}
	name, err := xwindows.UTF16PtrFromString(moduleTrusteeName(executorSIDDomain, installationID, executorID))
	if err != nil {
		t.Fatal(err)
	}
	proc := xwindows.NewLazySystemDLL("kernelbase.dll").NewProc("DeriveCapabilitySidsFromName")
	var groupArray, capabilityArray **xwindows.SID
	var groupCount, capabilityCount uint32
	result, _, callErr := proc.Call(
		uintptr(unsafe.Pointer(name)),
		uintptr(unsafe.Pointer(&groupArray)), uintptr(unsafe.Pointer(&groupCount)),
		uintptr(unsafe.Pointer(&capabilityArray)), uintptr(unsafe.Pointer(&capabilityCount)),
	)
	if result == 0 {
		t.Fatalf("DeriveCapabilitySidsFromName: %v", callErr)
	}
	defer func() {
		for _, array := range []struct {
			ptr   **xwindows.SID
			count uint32
		}{{groupArray, groupCount}, {capabilityArray, capabilityCount}} {
			if array.ptr == nil {
				continue
			}
			for _, sid := range unsafe.Slice(array.ptr, int(array.count)) {
				_, _ = xwindows.LocalFree(xwindows.Handle(uintptr(unsafe.Pointer(sid))))
			}
			_, _ = xwindows.LocalFree(xwindows.Handle(uintptr(unsafe.Pointer(array.ptr))))
		}
	}()
	if groupCount != 1 || capabilityCount != 1 || groupArray == nil || capabilityArray == nil {
		t.Fatalf("derived group/capability counts = %d/%d, want 1/1", groupCount, capabilityCount)
	}
	groupSID := unsafe.Slice(groupArray, int(groupCount))[0]
	capabilitySID := unsafe.Slice(capabilityArray, int(capabilityCount))[0]
	if got := groupSID.String(); got != want.String() {
		t.Fatalf("Windows-derived group SID = %s, module trustee = %s", got, want)
	}
	if capabilitySID.String() == want.String() {
		t.Fatal("selected NT-authority group SID unexpectedly equals AppAuthority capability SID")
	}
	var source xwindows.Token
	if err := xwindows.OpenProcessToken(xwindows.CurrentProcess(), xwindows.TOKEN_DUPLICATE|xwindows.TOKEN_QUERY, &source); err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	token, err := CreateRestrictedToken(source, []SID{want})
	if err != nil {
		t.Fatalf("create token with Windows-derived module trustee: %v", err)
	}
	defer token.Close()
	assertOnlyRestrictingSIDs(t, token, groupSID, mustSourceLogonSID(t, source))
}

func TestRestrictingSIDCollisionChecksIncludeTokenUser(t *testing.T) {
	user := mustTestSID(t, "S-1-5-21-101-202-303-404")
	other := mustTestSID(t, "S-1-5-32-1-2-3-4-5-6-7-8")
	if err := ensureRestrictingSIDsAreNew(user, nil, []*xwindows.SID{user}); err == nil {
		t.Fatal("exact TokenUser collision accepted")
	}
	groups := []xwindows.SIDAndAttributes{{Sid: other}}
	if err := ensureRestrictingSIDsAreNew(user, groups, []*xwindows.SID{other}); err == nil {
		t.Fatal("exact TokenGroups collision accepted")
	}
	if err := ensureRestrictingSIDsAreNew(user, groups, []*xwindows.SID{mustTestSID(t, "S-1-5-32-8-7-6-5-4-3-2-1")}); err != nil {
		t.Fatalf("fresh restricting SID rejected: %v", err)
	}
}

func TestDangerousGroupSIDListIsPinned(t *testing.T) {
	want := []string{
		"S-1-5-32-544", "S-1-5-32-547", "S-1-5-32-548", "S-1-5-32-549",
		"S-1-5-32-550", "S-1-5-32-551", "S-1-5-32-552", "S-1-5-32-555",
		"S-1-5-32-556",
		"S-1-5-32-569", "S-1-5-32-578", "S-1-5-32-579", "S-1-5-32-580",
	}
	if fmt.Sprint(dangerousGroupSIDStrings) != fmt.Sprint(want) {
		t.Fatalf("dangerous group SID list = %v, want %v", dangerousGroupSIDStrings, want)
	}
}

type recordingRestrictedTokenCreator struct {
	returnToken xwindows.Token
	err         error
	calls       int
	source      xwindows.Token
	flags       uint32
	disabled    []xwindows.SIDAndAttributes
	restricting []xwindows.SIDAndAttributes
}

func (f *recordingRestrictedTokenCreator) Create(source xwindows.Token, flags uint32, disabled, restricting []xwindows.SIDAndAttributes) (xwindows.Token, error) {
	f.calls++
	f.source = source
	f.flags = flags
	f.disabled = append([]xwindows.SIDAndAttributes(nil), disabled...)
	f.restricting = append([]xwindows.SIDAndAttributes(nil), restricting...)
	if f.err != nil {
		return 0, f.err
	}
	return f.returnToken, nil
}

func TestCreateRestrictedTokenRejectsInvalidInput(t *testing.T) {
	var source xwindows.Token
	if err := xwindows.OpenProcessToken(xwindows.CurrentProcess(), xwindows.TOKEN_DUPLICATE|xwindows.TOKEN_QUERY, &source); err != nil {
		t.Fatalf("open process token: %v", err)
	}
	defer source.Close()

	if token, err := CreateRestrictedToken(source, nil); err == nil {
		token.Close()
		t.Fatal("empty restricting SID list accepted")
	}
	sid, _ := ExecutorSID("test-installation", "test-executor")
	if token, err := CreateRestrictedToken(source, []SID{sid, sid}); err == nil {
		token.Close()
		t.Fatal("duplicate restricting SID accepted")
	}
	if token, err := CreateRestrictedToken(source, []SID{{text: "not-a-sid", kind: sidKindExecutor}}); err == nil {
		token.Close()
		t.Fatal("malformed restricting SID accepted")
	}
	installation, _ := InstallationSID("test-installation")
	if token, err := CreateRestrictedToken(source, []SID{installation}); err == nil {
		token.Close()
		t.Fatal("installation trustee SID accepted as an execution restriction")
	}
	for _, invalid := range []SID{
		{text: "S-1-5-12", kind: sidKindExecutor},
		{text: "S-1-15-2-1", kind: sidKindExecutor},
		{text: "S-1-5-32-1-2-3-4-5-6-7", kind: sidKindExecutor},
		{text: "S-1-15-3-1-2-3-4-5-6-7-8", kind: sidKindExecutor},
		{text: "S-1-15-3-1024-1-2-3-4-5-6-7", kind: sidKindExecutor},
		{text: "S-1-15-3-1024-1-2-3-4-5-6-7-not-a-word", kind: sidKindExecutor},
		{text: "S-1-15-3-1024-1-2-3-4-5-6-7-8"},
	} {
		t.Run(invalid.String(), func(t *testing.T) {
			if token, err := CreateRestrictedToken(source, []SID{invalid}); err == nil {
				token.Close()
				t.Fatalf("non-module trustee SID %q accepted", invalid)
			}
		})
	}
}

func TestCreateRestrictedTokenWithMinimalSourceAccess(t *testing.T) {
	var source xwindows.Token
	if err := xwindows.OpenProcessToken(xwindows.CurrentProcess(), xwindows.TOKEN_DUPLICATE|xwindows.TOKEN_QUERY, &source); err != nil {
		t.Fatalf("open minimally-accessible process token: %v", err)
	}
	defer source.Close()

	executor, err := ExecutorSID("minimal-access-installation", "minimal-access-executor")
	if err != nil {
		t.Fatal(err)
	}
	token, err := CreateRestrictedToken(source, []SID{executor})
	if restricted, queryErr := source.IsRestricted(); queryErr == nil && restricted {
		if token != 0 {
			token.Close()
		}
		t.Fatalf("live minimal-access prerequisite unavailable: current process token is already restricted; constructor failed closed: %v", err)
	}
	if err != nil {
		t.Fatalf("create token with TOKEN_DUPLICATE|TOKEN_QUERY source: %v", err)
	}
	token.Close()
}

func mustTestSID(t *testing.T, text string) *xwindows.SID {
	t.Helper()
	sid, err := xwindows.StringToSid(text)
	if err != nil {
		t.Fatalf("parse SID %q: %v", text, err)
	}
	return sid
}

func assertTokenType(t *testing.T, token xwindows.Token, want uint32) {
	t.Helper()
	info := mustTokenInformation(t, token, xwindows.TokenType)
	if got := *(*uint32)(unsafe.Pointer(&info[0])); got != want {
		t.Fatalf("token type = %d, want %d", got, want)
	}
}

func assertIntegrityUnchanged(t *testing.T, source, restricted xwindows.Token) {
	t.Helper()
	sourceInfo := mustTokenInformation(t, source, xwindows.TokenIntegrityLevel)
	restrictedInfo := mustTokenInformation(t, restricted, xwindows.TokenIntegrityLevel)
	sourceSID := (*xwindows.Tokenmandatorylabel)(unsafe.Pointer(&sourceInfo[0])).Label.Sid
	restrictedSID := (*xwindows.Tokenmandatorylabel)(unsafe.Pointer(&restrictedInfo[0])).Label.Sid
	if !xwindows.EqualSid(sourceSID, restrictedSID) {
		t.Fatalf("integrity changed from %s to %s", sourceSID, restrictedSID)
	}
}

func assertOnlyRestrictingSIDs(t *testing.T, token xwindows.Token, want ...*xwindows.SID) {
	t.Helper()
	info := mustTokenInformation(t, token, xwindows.TokenRestrictedSids)
	groups := (*xwindows.Tokengroups)(unsafe.Pointer(&info[0])).AllGroups()
	if len(groups) != len(want) {
		t.Fatalf("restricting SID count = %d, want %d", len(groups), len(want))
	}
	for _, sid := range want {
		if !containsSID(groups, sid) {
			t.Fatalf("restricting SID list does not contain %s", sid)
		}
	}
}

func assertSIDsNotNormalGroups(t *testing.T, token xwindows.Token, forbidden ...*xwindows.SID) {
	t.Helper()
	groups, err := token.GetTokenGroups()
	if err != nil {
		t.Fatalf("read token groups: %v", err)
	}
	for _, sid := range forbidden {
		if containsSID(groups.AllGroups(), sid) {
			t.Fatalf("restricting SID %s also appears in the normal group list", sid)
		}
	}
}

func assertDangerousGroupsDisabled(t *testing.T, source, restricted xwindows.Token) {
	t.Helper()
	sourceGroups, err := source.GetTokenGroups()
	if err != nil {
		t.Fatalf("read source groups: %v", err)
	}
	restrictedGroups, err := restricted.GetTokenGroups()
	if err != nil {
		t.Fatalf("read restricted groups: %v", err)
	}
	attributes := make(map[string]uint32)
	for _, group := range restrictedGroups.AllGroups() {
		attributes[group.Sid.String()] = group.Attributes
	}
	dangerous, err := dangerousGroupSIDs()
	if err != nil {
		t.Fatal(err)
	}
	for _, sid := range dangerous {
		if groupIsEnabledForAllow(sourceGroups.AllGroups(), sid) && attributes[sid.String()]&xwindows.SE_GROUP_USE_FOR_DENY_ONLY == 0 {
			t.Fatalf("dangerous group %s was not made deny-only", sid)
		}
	}
}

func assertSafeRuntimeGroupPreserved(t *testing.T, source, restricted xwindows.Token) {
	t.Helper()
	everyone := mustTestSID(t, "S-1-1-0")
	sourceGroups, err := source.GetTokenGroups()
	if err != nil {
		t.Fatalf("read source groups: %v", err)
	}
	if !groupIsEnabledForAllow(sourceGroups.AllGroups(), everyone) {
		t.Fatal("source token does not expose the Everyone runtime group")
	}
	restrictedGroups, err := restricted.GetTokenGroups()
	if err != nil {
		t.Fatalf("read restricted groups: %v", err)
	}
	if !groupIsEnabledForAllow(restrictedGroups.AllGroups(), everyone) {
		t.Fatal("safe Everyone runtime group was disabled")
	}
}

func assertPrivilegesRemoved(t *testing.T, source, restricted xwindows.Token) {
	t.Helper()
	sourcePrivileges := tokenPrivileges(t, source)
	restrictedPrivileges := tokenPrivileges(t, restricted)
	remaining := make(map[string]uint32, len(restrictedPrivileges))
	for _, privilege := range restrictedPrivileges {
		remaining[luidKey(privilege.Luid)] = privilege.Attributes
	}

	var traverse xwindows.LUID
	if err := xwindows.LookupPrivilegeValue(nil, xwindows.StringToUTF16Ptr("SeChangeNotifyPrivilege"), &traverse); err != nil {
		t.Fatalf("look up traversal privilege: %v", err)
	}
	var removed *xwindows.LUID
	for _, privilege := range sourcePrivileges {
		if luidKey(privilege.Luid) == luidKey(traverse) {
			continue
		}
		if _, ok := remaining[luidKey(privilege.Luid)]; ok {
			t.Fatalf("privilege %s was not removed", luidKey(privilege.Luid))
		}
		if removed == nil {
			copy := privilege.Luid
			removed = &copy
		}
	}
	if removed == nil {
		t.Fatal("source token has no removable privilege to exercise")
	}

	state := xwindows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]xwindows.LUIDAndAttributes{{
			Luid:       *removed,
			Attributes: xwindows.SE_PRIVILEGE_ENABLED,
		}},
	}
	if err := xwindows.AdjustTokenPrivileges(restricted, false, &state, uint32(unsafe.Sizeof(state)), nil, nil); err != nil && !errors.Is(err, xwindows.ERROR_NOT_ALL_ASSIGNED) {
		t.Fatalf("probe removed privilege: %v", err)
	}
	for _, privilege := range tokenPrivileges(t, restricted) {
		if luidKey(privilege.Luid) == luidKey(*removed) && privilege.Attributes&xwindows.SE_PRIVILEGE_ENABLED != 0 {
			t.Fatalf("removed privilege %s could be re-enabled", luidKey(*removed))
		}
	}
}

func tokenPrivileges(t *testing.T, token xwindows.Token) []xwindows.LUIDAndAttributes {
	t.Helper()
	info := mustTokenInformation(t, token, xwindows.TokenPrivileges)
	privileges := (*xwindows.Tokenprivileges)(unsafe.Pointer(&info[0])).AllPrivileges()
	return append([]xwindows.LUIDAndAttributes(nil), privileges...)
}

func mustTokenInformation(t *testing.T, token xwindows.Token, class uint32) []byte {
	t.Helper()
	info, err := readTokenInformation(token, class)
	if err != nil {
		t.Fatalf("GetTokenInformation(%d): %v", class, err)
	}
	return info
}

func containsSID(groups []xwindows.SIDAndAttributes, want *xwindows.SID) bool {
	for _, group := range groups {
		if xwindows.EqualSid(group.Sid, want) {
			return true
		}
	}
	return false
}

func luidKey(luid xwindows.LUID) string {
	return fmt.Sprintf("%08x:%08x", uint32(luid.HighPart), luid.LowPart)
}
