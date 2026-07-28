//go:build windows

package windows

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	win "golang.org/x/sys/windows"
)

type firewallProfiles uint8
type firewallDirection uint8
type firewallAction uint8
type firewallProtocol uint16

const (
	firewallDomainProfile  firewallProfiles = 1
	firewallPrivateProfile firewallProfiles = 2
	firewallPublicProfile  firewallProfiles = 4
	firewallAllProfiles    firewallProfiles = firewallDomainProfile | firewallPrivateProfile | firewallPublicProfile

	firewallInbound  firewallDirection = 1
	firewallOutbound firewallDirection = 2

	firewallBlock firewallAction = 0
	firewallAllow firewallAction = 1

	firewallProtocolTCP firewallProtocol = 6
	firewallProtocolUDP firewallProtocol = 17
	firewallProtocolAny firewallProtocol = 256

	firewallAny                  = "*"
	firewallNotApplicable        = ""
	firewallLoopbackAddresses    = "127.0.0.0/8,::1/128"
	firewallNonLoopbackAddresses = "0.0.0.0-126.255.255.255,128.0.0.0-255.255.255.255,::/128,::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"
)

var errFirewallPolicyOverridden = errors.New("sandbox: local Windows firewall rules are ineffective")

// offlineFirewallRule is deliberately a scalar value. In particular, address
// and port sets are canonical strings rather than mutable slices, so the model
// passed across the policy boundary cannot be widened after validation.
type offlineFirewallRule struct {
	name, group                     string
	enabled                         bool
	profiles                        firewallProfiles
	direction                       firewallDirection
	action                          firewallAction
	protocol                        firewallProtocol
	localAddresses, remoteAddresses string
	localPorts, remotePorts         string
	accountSID                      string
}

// offlineFirewallPolicy is the narrow boundary implemented by the documented
// Windows Firewall API adapter. Tests use an in-memory implementation and do
// not modify workstation firewall state.
type offlineFirewallPolicy interface {
	LocalRulesEffective() (bool, error)
	Get(name string) (offlineFirewallRule, bool, error)
	Put(offlineFirewallRule) error
	Remove(name string) error
}

func offlineFirewallRules(installationID, accountSID string, proxyPorts []uint16) ([]offlineFirewallRule, error) {
	if strings.TrimSpace(installationID) == "" {
		return nil, errors.New("sandbox: Windows installation identity is required")
	}
	if _, err := win.StringToSid(accountSID); err != nil {
		return nil, fmt.Errorf("sandbox: invalid offline account SID: %w", err)
	}
	if err := validateProxyPorts(proxyPorts); err != nil {
		return nil, err
	}
	ports := append([]uint16(nil), proxyPorts...)
	slices.Sort(ports)
	blockedPorts := complementPortRanges(ports)
	digest := sha256.Sum256([]byte(installationID))
	suffix := hex.EncodeToString(digest[:12])
	group := "Looprig Sandbox " + suffix
	base := offlineFirewallRule{
		group: group, enabled: true, profiles: firewallAllProfiles,
		direction: firewallOutbound, action: firewallBlock,
		localAddresses: firewallAny, localPorts: firewallAny,
		accountSID: accountSID,
	}
	nonLoopback := base
	nonLoopback.name = group + " Offline Non-Loopback"
	nonLoopback.protocol = firewallProtocolAny
	nonLoopback.remoteAddresses = firewallNonLoopbackAddresses
	// Windows Firewall accepts port sets only for TCP and UDP rules.
	nonLoopback.localPorts = firewallNotApplicable
	nonLoopback.remotePorts = firewallNotApplicable
	udp := base
	udp.name = group + " Offline Loopback UDP"
	udp.protocol = firewallProtocolUDP
	udp.remoteAddresses = firewallLoopbackAddresses
	udp.remotePorts = firewallAny
	tcp := base
	tcp.name = group + " Offline Loopback TCP"
	tcp.protocol = firewallProtocolTCP
	tcp.remoteAddresses = firewallLoopbackAddresses
	tcp.remotePorts = blockedPorts
	return []offlineFirewallRule{nonLoopback, udp, tcp}, nil
}

func complementPortRanges(allowed []uint16) string {
	parts := make([]string, 0, len(allowed)+1)
	start := uint32(1)
	for _, port := range allowed {
		end := uint32(port) - 1
		if start <= end {
			parts = append(parts, formatPortRange(start, end))
		}
		start = uint32(port) + 1
	}
	if start <= 65535 {
		parts = append(parts, formatPortRange(start, 65535))
	}
	return strings.Join(parts, ",")
}

func formatPortRange(first, last uint32) string {
	if first == last {
		return fmt.Sprint(first)
	}
	return fmt.Sprintf("%d-%d", first, last)
}

func compareOfflineFirewallRule(want, got offlineFirewallRule) error {
	if want != got {
		return fmt.Errorf("sandbox: Windows firewall rule %q differs from the installed model", want.name)
	}
	return nil
}

type firewallRuleSnapshot struct {
	rule    offlineFirewallRule
	existed bool
}

func installOfflineFirewall(policy offlineFirewallPolicy, installationID, accountSID string, proxyPorts []uint16) (retErr error) {
	rules, err := offlineFirewallRules(installationID, accountSID, proxyPorts)
	if err != nil {
		return err
	}
	effective, err := policy.LocalRulesEffective()
	if err != nil {
		return fmt.Errorf("inspect Windows firewall policy source: %w", err)
	}
	if !effective {
		return errFirewallPolicyOverridden
	}
	snapshots := make(map[string]firewallRuleSnapshot, len(rules))
	for _, rule := range rules {
		previous, ok, getErr := policy.Get(rule.name)
		if getErr != nil {
			return fmt.Errorf("read Windows firewall rule %q: %w", rule.name, getErr)
		}
		snapshots[rule.name] = firewallRuleSnapshot{rule: previous, existed: ok}
	}
	changed := make([]string, 0, len(rules)+1)
	changedSet := make(map[string]struct{}, len(rules))
	defer func() {
		if retErr == nil {
			return
		}
		for i := len(changed) - 1; i >= 0; i-- {
			name := changed[i]
			snapshot := snapshots[name]
			var rollbackErr error
			if snapshot.existed {
				rollbackErr = policy.Put(snapshot.rule)
			} else {
				rollbackErr = policy.Remove(name)
			}
			if rollbackErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("rollback Windows firewall rule %q: %w", name, rollbackErr))
			}
		}
	}()
	apply := func(rule offlineFirewallRule) error {
		if err := policy.Put(rule); err != nil {
			return fmt.Errorf("install Windows firewall rule %q: %w", rule.name, err)
		}
		if _, ok := changedSet[rule.name]; !ok {
			changed = append(changed, rule.name)
			changedSet[rule.name] = struct{}{}
		}
		installed, ok, err := policy.Get(rule.name)
		if err != nil {
			return fmt.Errorf("read back Windows firewall rule %q: %w", rule.name, err)
		}
		if !ok {
			return fmt.Errorf("sandbox: installed Windows firewall rule %q is missing", rule.name)
		}
		return compareOfflineFirewallRule(rule, installed)
	}

	staged := append([]offlineFirewallRule(nil), rules...)
	staged[len(staged)-1].remotePorts = firewallAny
	for _, rule := range staged {
		if err := apply(rule); err != nil {
			return err
		}
	}
	if err := apply(rules[len(rules)-1]); err != nil {
		return err
	}
	return nil
}

func inspectOfflineFirewall(policy offlineFirewallPolicy, want []offlineFirewallRule) (effective, unchanged bool, err error) {
	effective, err = policy.LocalRulesEffective()
	if err != nil || !effective {
		return effective, false, err
	}
	for _, expected := range want {
		installed, ok, getErr := policy.Get(expected.name)
		if getErr != nil {
			return true, false, getErr
		}
		if !ok || compareOfflineFirewallRule(expected, installed) != nil {
			return true, false, nil
		}
	}
	return true, true, nil
}

func removeOfflineFirewall(policy offlineFirewallPolicy, owned []offlineFirewallRule) error {
	var result error
	for _, identity := range owned {
		installed, ok, err := policy.Get(identity.name)
		if err != nil {
			result = errors.Join(result, fmt.Errorf("read Windows firewall rule %q: %w", identity.name, err))
			continue
		}
		if !ok || installed.name != identity.name || installed.group != identity.group || installed.accountSID != identity.accountSID {
			continue
		}
		if err := policy.Remove(identity.name); err != nil {
			result = errors.Join(result, fmt.Errorf("remove Windows firewall rule %q: %w", identity.name, err))
		}
	}
	return result
}
