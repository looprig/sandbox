//go:build windows

package windows

import (
	"errors"
	"reflect"
	"testing"
)

func TestOfflineFirewallRulesAreExactAndDeterministic(t *testing.T) {
	rules, err := offlineFirewallRules("installation-a", "S-1-5-21-1-2-3-1001", []uint16{9002, 9001})
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 3 {
		t.Fatalf("rule count = %d, want 3", len(rules))
	}
	want := []offlineFirewallRule{
		{
			name: rules[0].name, group: rules[0].group, enabled: true,
			profiles: firewallAllProfiles, direction: firewallOutbound,
			action: firewallBlock, protocol: firewallProtocolAny,
			localAddresses: firewallAny, remoteAddresses: firewallNonLoopbackAddresses,
			localPorts: firewallNotApplicable, remotePorts: firewallNotApplicable,
			accountSID: "S-1-5-21-1-2-3-1001",
		},
		{
			name: rules[1].name, group: rules[1].group, enabled: true,
			profiles: firewallAllProfiles, direction: firewallOutbound,
			action: firewallBlock, protocol: firewallProtocolUDP,
			localAddresses: firewallAny, remoteAddresses: firewallLoopbackAddresses,
			localPorts: firewallAny, remotePorts: firewallAny,
			accountSID: "S-1-5-21-1-2-3-1001",
		},
		{
			name: rules[2].name, group: rules[2].group, enabled: true,
			profiles: firewallAllProfiles, direction: firewallOutbound,
			action: firewallBlock, protocol: firewallProtocolTCP,
			localAddresses: firewallAny, remoteAddresses: firewallLoopbackAddresses,
			localPorts: firewallAny, remotePorts: "1-9000,9003-65535",
			accountSID: "S-1-5-21-1-2-3-1001",
		},
	}
	if !reflect.DeepEqual(rules, want) {
		t.Fatalf("rules = %#v, want %#v", rules, want)
	}

	reordered, err := offlineFirewallRules("installation-a", "S-1-5-21-1-2-3-1001", []uint16{9001, 9002})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(rules, reordered) {
		t.Fatal("rule model depends on input port order")
	}
	other, err := offlineFirewallRules("installation-b", "S-1-5-21-1-2-3-1001", []uint16{9001, 9002})
	if err != nil {
		t.Fatal(err)
	}
	if rules[0].name == other[0].name || rules[0].group == other[0].group {
		t.Fatal("different installation identities share firewall identity")
	}
}

func TestFirewallReadbackComparesEverySecurityField(t *testing.T) {
	want, err := offlineFirewallRules("installation", "S-1-5-21-1-2-3-1001", []uint16{9001})
	if err != nil {
		t.Fatal(err)
	}
	base := want[2]
	mutations := map[string]func(*offlineFirewallRule){
		"name":             func(r *offlineFirewallRule) { r.name += "-changed" },
		"group":            func(r *offlineFirewallRule) { r.group += "-changed" },
		"enabled":          func(r *offlineFirewallRule) { r.enabled = false },
		"profiles":         func(r *offlineFirewallRule) { r.profiles = firewallDomainProfile },
		"direction":        func(r *offlineFirewallRule) { r.direction = firewallInbound },
		"action":           func(r *offlineFirewallRule) { r.action = firewallAllow },
		"protocol":         func(r *offlineFirewallRule) { r.protocol = firewallProtocolUDP },
		"local addresses":  func(r *offlineFirewallRule) { r.localAddresses = firewallLoopbackAddresses },
		"remote addresses": func(r *offlineFirewallRule) { r.remoteAddresses = firewallAny },
		"local ports":      func(r *offlineFirewallRule) { r.localPorts = "80" },
		"remote ports":     func(r *offlineFirewallRule) { r.remotePorts = firewallAny },
		"account SID":      func(r *offlineFirewallRule) { r.accountSID = "S-1-5-21-1-2-3-1002" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			got := base
			mutate(&got)
			if err := compareOfflineFirewallRule(base, got); err == nil {
				t.Fatal("changed rule accepted")
			}
		})
	}
	if err := compareOfflineFirewallRule(base, base); err != nil {
		t.Fatalf("exact rule rejected: %v", err)
	}
}

func TestInstallFirewallStagesBroadTCPBeforeNarrowingAndRollsBack(t *testing.T) {
	policy := &fakeFirewallPolicy{effective: true, rules: make(map[string]offlineFirewallRule), failPut: 4}
	err := installOfflineFirewall(policy, "installation", "S-1-5-21-1-2-3-1001", []uint16{9001})
	if err == nil {
		t.Fatal("install unexpectedly succeeded")
	}
	if len(policy.rules) != 0 {
		t.Fatalf("partial rules remain: %#v", policy.rules)
	}
	if len(policy.puts) < 3 || policy.puts[2].protocol != firewallProtocolTCP || policy.puts[2].remotePorts != firewallAny {
		t.Fatalf("TCP fail-closed staging missing: %#v", policy.puts)
	}

	policy = &fakeFirewallPolicy{effective: true, rules: make(map[string]offlineFirewallRule)}
	if err := installOfflineFirewall(policy, "installation", "S-1-5-21-1-2-3-1001", []uint16{9001}); err != nil {
		t.Fatal(err)
	}
	if got := policy.puts[len(policy.puts)-1]; got.protocol != firewallProtocolTCP || got.remotePorts != "1-9000,9002-65535" {
		t.Fatalf("final TCP rule = %#v", got)
	}

	policy = &fakeFirewallPolicy{effective: true, rules: make(map[string]offlineFirewallRule), corruptGet: 1}
	if err := installOfflineFirewall(policy, "installation", "S-1-5-21-1-2-3-1001", []uint16{9001}); err == nil {
		t.Fatal("read-back mismatch accepted")
	}
	if len(policy.rules) != 0 {
		t.Fatalf("read-back mismatch was not rolled back: %#v", policy.rules)
	}
}

func TestFirewallTCPComplementCoversBoundaryPorts(t *testing.T) {
	tests := []struct {
		allowed []uint16
		want    string
	}{
		{[]uint16{1}, "2-65535"},
		{[]uint16{65535}, "1-65534"},
		{[]uint16{1, 2, 65534, 65535}, "3-65533"},
	}
	for _, test := range tests {
		ports := append([]uint16(nil), test.allowed...)
		if got := complementPortRanges(ports); got != test.want {
			t.Errorf("complementPortRanges(%v) = %q, want %q", ports, got, test.want)
		}
	}
}

func TestInspectFirewallTreatsPolicyOverrideAndMutationAsUnhealthy(t *testing.T) {
	want, err := offlineFirewallRules("installation", "S-1-5-21-1-2-3-1001", []uint16{9001})
	if err != nil {
		t.Fatal(err)
	}
	policy := &fakeFirewallPolicy{effective: true, rules: ruleMap(want)}
	effective, unchanged, err := inspectOfflineFirewall(policy, want)
	if err != nil || !effective || !unchanged {
		t.Fatalf("healthy inspection = %v, %v, %v", effective, unchanged, err)
	}
	policy.effective = false
	effective, unchanged, err = inspectOfflineFirewall(policy, want)
	if err != nil || effective || unchanged {
		t.Fatalf("overridden inspection = %v, %v, %v", effective, unchanged, err)
	}
	policy.effective = true
	changed := want[0]
	changed.enabled = false
	policy.rules[changed.name] = changed
	effective, unchanged, err = inspectOfflineFirewall(policy, want)
	if err != nil || !effective || unchanged {
		t.Fatalf("changed inspection = %v, %v, %v", effective, unchanged, err)
	}
}

func TestRemoveFirewallDeletesOnlyOwnedIdentities(t *testing.T) {
	want, err := offlineFirewallRules("installation", "S-1-5-21-1-2-3-1001", []uint16{9001})
	if err != nil {
		t.Fatal(err)
	}
	policy := &fakeFirewallPolicy{effective: true, rules: ruleMap(want)}
	foreign := want[1]
	foreign.group = "foreign"
	policy.rules[foreign.name] = foreign
	if err := removeOfflineFirewall(policy, want); err != nil {
		t.Fatal(err)
	}
	if len(policy.rules) != 1 || policy.rules[foreign.name].group != "foreign" {
		t.Fatalf("remove touched foreign identity: %#v", policy.rules)
	}
}

type fakeFirewallPolicy struct {
	effective  bool
	rules      map[string]offlineFirewallRule
	puts       []offlineFirewallRule
	putCount   int
	failPut    int
	corruptGet int
}

func (p *fakeFirewallPolicy) LocalRulesEffective() (bool, error) { return p.effective, nil }
func (p *fakeFirewallPolicy) Get(name string) (offlineFirewallRule, bool, error) {
	r, ok := p.rules[name]
	if p.corruptGet > 0 && p.putCount >= p.corruptGet {
		r.enabled = !r.enabled
	}
	return r, ok, nil
}
func (p *fakeFirewallPolicy) Put(rule offlineFirewallRule) error {
	p.putCount++
	p.puts = append(p.puts, rule)
	if p.failPut == p.putCount {
		return errors.New("injected put failure")
	}
	p.rules[rule.name] = rule
	return nil
}
func (p *fakeFirewallPolicy) Remove(name string) error { delete(p.rules, name); return nil }

func ruleMap(rules []offlineFirewallRule) map[string]offlineFirewallRule {
	result := make(map[string]offlineFirewallRule, len(rules))
	for _, rule := range rules {
		result[rule.name] = rule
	}
	return result
}
