//go:build windows

package windows

import (
	"context"
	"errors"
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

func TestBrokerLeaseRecoveryInspectorReportsQuarantineFromRunningBroker(t *testing.T) {
	manifest := setupManifest{InstallationID: "installation", HostPath: `C:\ProgramData\Looprig\slots\1\sandbox-host.exe`}
	running := staticSetupInspector{readiness: setupDependencyReadiness{service: true, accounts: true}}
	probed := 0
	probe := func(pending bool, err error) func(context.Context, setupManifest) (bool, error) {
		return func(_ context.Context, got setupManifest) (bool, error) {
			probed++
			if got.InstallationID != manifest.InstallationID {
				t.Fatalf("probe manifest = %#v", got)
			}
			return pending, err
		}
	}
	readiness, err := (brokerLeaseRecoverySetupInspector{base: running, probe: probe(true, nil)}).Inspect(context.Background(), validatedSetup{}, manifest)
	if err != nil || !readiness.leaseRecovery || !readiness.service || !readiness.accounts {
		t.Fatalf("quarantine readiness = %#v, %v", readiness, err)
	}
	readiness, err = (brokerLeaseRecoverySetupInspector{base: running, probe: probe(false, nil)}).Inspect(context.Background(), validatedSetup{}, manifest)
	if err != nil || readiness.leaseRecovery {
		t.Fatalf("healthy broker readiness = %#v, %v", readiness, err)
	}
	readiness, err = (brokerLeaseRecoverySetupInspector{base: running, probe: probe(true, errors.New("pipe busy"))}).Inspect(context.Background(), validatedSetup{}, manifest)
	if err != nil || readiness.leaseRecovery || !readiness.service {
		t.Fatalf("probe failure readiness = %#v, %v", readiness, err)
	}
	stopped := staticSetupInspector{readiness: setupDependencyReadiness{accounts: true}}
	before := probed
	if _, err := (brokerLeaseRecoverySetupInspector{base: stopped, probe: probe(true, nil)}).Inspect(context.Background(), validatedSetup{}, manifest); err != nil || probed != before {
		t.Fatalf("stopped service was probed (%d -> %d): %v", before, probed, err)
	}
}
