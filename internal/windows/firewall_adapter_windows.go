//go:build windows

package windows

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

const netFwModifyStateOK int32 = 0

type netFwRuleRecord struct {
	Name, Grouping                  string
	Enabled                         bool
	Profiles, Direction, Action     int32
	Protocol                        int32
	LocalAddresses, RemoteAddresses string
	LocalPorts, RemotePorts         string
	LocalUserAuthorizedList         string
}

// netFwAutomation is the minimal ABI-shaped boundary for INetFwPolicy2,
// INetFwRules, and INetFwRule3. The policy adapter below is complete and is
// tested without mutating the host. A raw IDispatch transport is deliberately
// not improvised here: Phase 4 permits only x/sys/windows, which exposes COM
// apartment setup but not a safe Automation/VARIANT invocation layer.
type netFwAutomation interface {
	LocalPolicyModifyState() (int32, error)
	ReadRule(string) (netFwRuleRecord, bool, error)
	WriteRule(netFwRuleRecord) error
	DeleteRule(string) error
}

type windowsFirewallPolicy struct{ api netFwAutomation }

func (p windowsFirewallPolicy) LocalRulesEffective() (bool, error) {
	state, err := p.api.LocalPolicyModifyState()
	return state == netFwModifyStateOK, err
}

func (p windowsFirewallPolicy) Get(name string) (offlineFirewallRule, bool, error) {
	record, found, err := p.api.ReadRule(name)
	if err != nil || !found {
		return offlineFirewallRule{}, found, err
	}
	sid, err := firewallSIDFromSDDL(record.LocalUserAuthorizedList)
	if err != nil {
		return offlineFirewallRule{}, false, fmt.Errorf("read Windows firewall account scope: %w", err)
	}
	return offlineFirewallRule{
		name: record.Name, group: record.Grouping, enabled: record.Enabled,
		profiles: firewallProfiles(record.Profiles), direction: firewallDirection(record.Direction),
		action: firewallAction(record.Action), protocol: firewallProtocol(record.Protocol),
		localAddresses: canonicalFirewallSet(record.LocalAddresses), remoteAddresses: canonicalFirewallSet(record.RemoteAddresses),
		localPorts: canonicalFirewallSet(record.LocalPorts), remotePorts: canonicalFirewallSet(record.RemotePorts),
		accountSID: sid,
	}, true, nil
}

func (p windowsFirewallPolicy) Put(rule offlineFirewallRule) error {
	return p.api.WriteRule(netFwRuleRecord{
		Name: rule.name, Grouping: rule.group, Enabled: rule.enabled,
		Profiles: int32(rule.profiles), Direction: int32(rule.direction), Action: int32(rule.action), Protocol: int32(rule.protocol),
		LocalAddresses: canonicalFirewallSet(rule.localAddresses), RemoteAddresses: canonicalFirewallSet(rule.remoteAddresses),
		LocalPorts: canonicalFirewallSet(rule.localPorts), RemotePorts: canonicalFirewallSet(rule.remotePorts),
		LocalUserAuthorizedList: firewallSDDLForSID(rule.accountSID),
	})
}

func (p windowsFirewallPolicy) Remove(name string) error { return p.api.DeleteRule(name) }

func canonicalFirewallSet(value string) string {
	if value == "" {
		return ""
	}
	parts := strings.Split(value, ",")
	for index := range parts {
		parts[index] = strings.TrimSpace(parts[index])
	}
	slices.Sort(parts)
	return strings.Join(parts, ",")
}

func firewallSDDLForSID(sid string) string { return "D:(A;;CC;;;" + sid + ")" }

func firewallSIDFromSDDL(sddl string) (string, error) {
	const prefix, suffix = "D:(A;;CC;;;", ")"
	if !strings.HasPrefix(sddl, prefix) || !strings.HasSuffix(sddl, suffix) || strings.Count(sddl, "(") != 1 {
		return "", errors.New("firewall local-user scope is not one exact allow principal")
	}
	sid := strings.TrimSuffix(strings.TrimPrefix(sddl, prefix), suffix)
	if sid == "" || strings.ContainsAny(sid, "();") {
		return "", errors.New("firewall local-user scope contains an invalid SID")
	}
	return sid, nil
}
