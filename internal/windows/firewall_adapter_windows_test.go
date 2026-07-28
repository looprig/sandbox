//go:build windows

package windows

import (
	"errors"
	"reflect"
	"testing"
)

func TestWindowsFirewallPolicyConvertsExactINetFwRule3Record(t *testing.T) {
	want, err := offlineFirewallRules("installation", "S-1-5-21-1-2-3-1001", []uint16{9001})
	if err != nil {
		t.Fatal(err)
	}
	api := &fakeNetFwAutomation{modifyState: netFwModifyStateOK, rules: make(map[string]netFwRuleRecord)}
	policy := windowsFirewallPolicy{api: api}
	if err := policy.Put(want[2]); err != nil {
		t.Fatal(err)
	}
	record := api.rules[want[2].name]
	if record.LocalUserAuthorizedList != "D:(A;;CC;;;S-1-5-21-1-2-3-1001)" {
		t.Fatalf("local-user scope = %q", record.LocalUserAuthorizedList)
	}
	// Simulate harmless API ordering differences; semantic widening is not
	// normalized away because only token order and whitespace are canonicalized.
	record.RemoteAddresses = " ::1/128, 127.0.0.0/8 "
	api.rules[record.Name] = record
	got, found, err := policy.Get(record.Name)
	if err != nil || !found {
		t.Fatalf("Get = %#v, %v, %v", got, found, err)
	}
	if !reflect.DeepEqual(got, want[2]) {
		t.Fatalf("converted rule = %#v, want %#v", got, want[2])
	}
}

func TestWindowsFirewallPolicyFailsClosedOnMalformedAccountScope(t *testing.T) {
	api := &fakeNetFwAutomation{rules: map[string]netFwRuleRecord{"rule": {Name: "rule", LocalUserAuthorizedList: "D:(A;;CC;;;S-1-5-18)(A;;CC;;;S-1-5-32-544)"}}}
	policy := windowsFirewallPolicy{api: api}
	if _, _, err := policy.Get("rule"); err == nil {
		t.Fatal("multiple firewall principals accepted")
	}
}

func TestWindowsFirewallPolicyUsesLocalModifyState(t *testing.T) {
	api := &fakeNetFwAutomation{modifyState: 1}
	effective, err := (windowsFirewallPolicy{api: api}).LocalRulesEffective()
	if err != nil || effective {
		t.Fatalf("effective = %v, err = %v", effective, err)
	}
	api.modifyErr = errors.New("injected state error")
	if _, err := (windowsFirewallPolicy{api: api}).LocalRulesEffective(); err == nil {
		t.Fatal("modify-state error discarded")
	}
}

type fakeNetFwAutomation struct {
	modifyState int32
	modifyErr   error
	rules       map[string]netFwRuleRecord
}

func (a *fakeNetFwAutomation) LocalPolicyModifyState() (int32, error) {
	return a.modifyState, a.modifyErr
}

func (a *fakeNetFwAutomation) ReadRule(name string) (netFwRuleRecord, bool, error) {
	rule, ok := a.rules[name]
	return rule, ok, nil
}

func (a *fakeNetFwAutomation) WriteRule(rule netFwRuleRecord) error {
	if a.rules == nil {
		a.rules = make(map[string]netFwRuleRecord)
	}
	a.rules[rule.Name] = rule
	return nil
}

func (a *fakeNetFwAutomation) DeleteRule(name string) error {
	delete(a.rules, name)
	return nil
}
