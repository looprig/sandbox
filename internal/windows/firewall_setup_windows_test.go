//go:build windows

package windows

import (
	"context"
	"testing"
)

func TestFirewallSetupInspectorComposesHealthAndPortOwners(t *testing.T) {
	manifest := setupManifest{InstallationID: "installation", ProxyPorts: []uint16{9001}}
	want, err := offlineFirewallRules(manifest.InstallationID, "S-1-5-21-1-2-3-1001", manifest.ProxyPorts)
	if err != nil {
		t.Fatal(err)
	}
	base := staticSetupInspector{readiness: setupDependencyReadiness{service: true, accounts: true, credentials: true, runtimeBaseline: true}}
	policy := &fakeFirewallPolicy{effective: true, rules: ruleMap(want)}
	inspector := firewallSetupDependencyInspector{
		base: base, accounts: staticOfflineSIDSource{sid: "S-1-5-21-1-2-3-1001", found: true},
		policy: policy, owners: mappedPortOwner{owners: map[uint16]uint32{9001: 42}},
	}
	got, err := inspector.Inspect(context.Background(), validatedSetup{config: SetupConfig{InstallationID: "installation"}}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if !got.service || !got.accounts || !got.credentials || !got.runtimeBaseline || !got.firewallEffective || !got.firewallUnchanged || got.portPID[9001] != 42 {
		t.Fatalf("composed readiness = %#v", got)
	}
}

func TestFirewallSetupInspectorFailsClosedWithoutAccount(t *testing.T) {
	manifest := setupManifest{InstallationID: "installation", ProxyPorts: []uint16{9001}}
	inspector := firewallSetupDependencyInspector{
		base: staticSetupInspector{}, accounts: staticOfflineSIDSource{},
		policy: &fakeFirewallPolicy{effective: true}, owners: mappedPortOwner{owners: map[uint16]uint32{}},
	}
	got, err := inspector.Inspect(context.Background(), validatedSetup{}, manifest)
	if err != nil {
		t.Fatal(err)
	}
	if got.firewallEffective || got.firewallUnchanged {
		t.Fatalf("missing account reported healthy: %#v", got)
	}
}

type staticSetupInspector struct{ readiness setupDependencyReadiness }

func (s staticSetupInspector) Inspect(context.Context, validatedSetup, setupManifest) (setupDependencyReadiness, error) {
	return s.readiness, nil
}

type staticOfflineSIDSource struct {
	sid   string
	found bool
}

func (s staticOfflineSIDSource) OfflineAccountSID(context.Context, validatedSetup, setupManifest) (string, bool, error) {
	return s.sid, s.found, nil
}
