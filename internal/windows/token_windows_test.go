//go:build windows

package windows

import (
	"errors"
	"fmt"
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

	assertTokenType(t, token, xwindows.TokenPrimary)
	assertIntegrityUnchanged(t, source, token)
	assertOnlyRestrictingSIDs(t, token, executorSID, grantSID)
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
	fake := &recordingRestrictedTokenCreator{returnToken: xwindows.Token(42)}

	got, err := issueRestrictedToken(fake, xwindows.Token(7), disabled, restricting)
	if err != nil {
		t.Fatalf("issue restricted token: %v", err)
	}
	if got != 42 || fake.source != 7 {
		t.Fatalf("token/source = %d/%d, want 42/7", got, fake.source)
	}
	if fake.flags != disableMaxPrivilege|luaToken|writeRestricted {
		t.Fatalf("flags = %#x, want DISABLE_MAX_PRIVILEGE|LUA_TOKEN|WRITE_RESTRICTED", fake.flags)
	}
	if len(fake.disabled) != 1 || !xwindows.EqualSid(fake.disabled[0].Sid, disabledSID) {
		t.Fatalf("disabled groups = %#v, want Administrators", fake.disabled)
	}
	if len(fake.restricting) != 1 || !xwindows.EqualSid(fake.restricting[0].Sid, restrictingSID) {
		t.Fatalf("restricting groups = %#v, want executor SID", fake.restricting)
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
	source      xwindows.Token
	flags       uint32
	disabled    []xwindows.SIDAndAttributes
	restricting []xwindows.SIDAndAttributes
}

func (f *recordingRestrictedTokenCreator) Create(source xwindows.Token, flags uint32, disabled, restricting []xwindows.SIDAndAttributes) (xwindows.Token, error) {
	f.source = source
	f.flags = flags
	f.disabled = append([]xwindows.SIDAndAttributes(nil), disabled...)
	f.restricting = append([]xwindows.SIDAndAttributes(nil), restricting...)
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
		t.Fatal("installation capability SID accepted as an execution restriction")
	}
	for _, invalid := range []SID{
		{text: "S-1-5-12", kind: sidKindExecutor},
		{text: "S-1-15-2-1", kind: sidKindExecutor},
		{text: "S-1-5-21-314159-265358-979323", kind: sidKindExecutor},
		{text: "S-1-15-3-1-2-3-4-5-6-7-8", kind: sidKindExecutor},
		{text: "S-1-15-3-1024-1-2-3-4-5-6-7", kind: sidKindExecutor},
		{text: "S-1-15-3-1024-1-2-3-4-5-6-7-not-a-word", kind: sidKindExecutor},
		{text: "S-1-15-3-1024-1-2-3-4-5-6-7-8"},
	} {
		t.Run(invalid.String(), func(t *testing.T) {
			if token, err := CreateRestrictedToken(source, []SID{invalid}); err == nil {
				token.Close()
				t.Fatalf("non-module capability SID %q accepted", invalid)
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
