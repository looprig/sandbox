//go:build windows

package windows

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

type removalOrder struct{ steps []string }

type orderedRemovalServices struct {
	*fakeServiceAPI
	order   *removalOrder
	stopErr error
}

func (api *orderedRemovalServices) Stop(name string) error {
	api.order.steps = append(api.order.steps, "service-stop")
	if api.stopErr != nil {
		return api.stopErr
	}
	return api.fakeServiceAPI.Stop(name)
}
func (api *orderedRemovalServices) Delete(name string) error {
	api.order.steps = append(api.order.steps, "service-delete")
	return api.fakeServiceAPI.Delete(name)
}

type orderedRemovalFirewall struct {
	*fakeFirewallPolicy
	order *removalOrder
}

func (policy *orderedRemovalFirewall) Remove(name string) error {
	if len(policy.order.steps) == 0 || policy.order.steps[len(policy.order.steps)-1] != "firewall-remove" {
		policy.order.steps = append(policy.order.steps, "firewall-remove")
	}
	return policy.fakeFirewallPolicy.Remove(name)
}

type removalFixture struct {
	setup      validatedSetup
	manifest   setupManifest
	order      *removalOrder
	services   *orderedRemovalServices
	firewall   *orderedRemovalFirewall
	accounts   *mappedSetupAccounts
	removedDir string
}

func newRemovalFixture(t *testing.T) *removalFixture {
	t.Helper()
	root := t.TempDir()
	manifest := setupManifest{
		InstallationID: "remove-ordered", OwnerSID: "S-1-5-21-owner",
		HostPath:   filepath.Join(root, "slots", strings.Repeat("e5", 16), "sandbox-host.exe"),
		OfflineSID: "S-1-5-21-1-2-3-1001", OnlineSID: "S-1-5-21-1-2-3-1002",
		ServiceIdentity: "owned-service", ProxyPorts: []uint16{41001},
	}
	names, err := deriveInstallationPrincipalNames(manifest.InstallationID)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := offlineFirewallRules(manifest.InstallationID, manifest.OfflineSID, manifest.ProxyPorts)
	if err != nil {
		t.Fatal(err)
	}
	installed := make(map[string]offlineFirewallRule, len(rules))
	for _, rule := range rules {
		installed[rule.name] = rule
	}
	order := &removalOrder{}
	return &removalFixture{
		setup: validatedSetup{
			config: SetupConfig{InstallationID: manifest.InstallationID}, stateRoot: root, ownerSID: manifest.OwnerSID,
		},
		manifest: manifest,
		order:    order,
		services: &orderedRemovalServices{order: order, fakeServiceAPI: &fakeServiceAPI{record: brokerServiceRecord{
			Spec: brokerServiceSpecModel{Name: names.Service}, Identity: manifest.ServiceIdentity, Owned: true,
		}}},
		firewall: &orderedRemovalFirewall{order: order, fakeFirewallPolicy: &fakeFirewallPolicy{effective: true, rules: installed}},
		accounts: &mappedSetupAccounts{records: map[string]sandboxAccountRecord{
			names.Offline: {Name: names.Offline, SID: manifest.OfflineSID, Owned: true},
			names.Online:  {Name: names.Online, SID: manifest.OnlineSID, Owned: true},
		}},
	}
}

func (fixture *removalFixture) remove(leases func(validatedSetup) ([]SetupProblem, error)) error {
	return removeInstalledSetup(context.Background(), fixture.setup, fixture.manifest, setupRemovalMechanisms{
		accounts: fixture.accounts, services: fixture.services, credentials: &fakeCredentialStore{},
		firewall:          fixture.firewall,
		validateArtifacts: func(validatedSetup, setupManifest) error { return nil },
		leases: func(setup validatedSetup) ([]SetupProblem, error) {
			fixture.order.steps = append(fixture.order.steps, "leases")
			return leases(setup)
		},
		removeDir: func(path string) error {
			fixture.order.steps = append(fixture.order.steps, "remove-root")
			fixture.removedDir = path
			return nil
		},
	})
}

// TestRemoveInstalledSetupStopsBrokerBeforeLeasesAndFirewall pins M14's
// removal order: the broker stops first, its leases are reconciled next, and
// only then do the firewall rules, the service and the state root go.
func TestRemoveInstalledSetupStopsBrokerBeforeLeasesAndFirewall(t *testing.T) {
	fixture := newRemovalFixture(t)
	if err := fixture.remove(func(validatedSetup) ([]SetupProblem, error) { return nil, nil }); err != nil {
		t.Fatal(err)
	}
	want := []string{"service-stop", "leases", "firewall-remove", "service-stop", "service-delete", "remove-root"}
	if !slices.Equal(fixture.order.steps, want) {
		t.Fatalf("removal order = %v, want %v", fixture.order.steps, want)
	}
	if fixture.removedDir != fixture.setup.stateRoot {
		t.Fatalf("removed %q, want the state root", fixture.removedDir)
	}
}

// TestRemoveInstalledSetupStopFailureTouchesNothing: a broker that will not
// stop aborts removal before any rule, lease, account or file is touched.
func TestRemoveInstalledSetupStopFailureTouchesNothing(t *testing.T) {
	fixture := newRemovalFixture(t)
	fixture.services.stopErr = errors.New("service will not stop")
	err := fixture.remove(func(validatedSetup) ([]SetupProblem, error) {
		t.Fatal("leases reconciled while the broker may still be running")
		return nil, nil
	})
	if err == nil || !slices.Equal(fixture.order.steps, []string{"service-stop"}) {
		t.Fatalf("stop failure = %v order %v", err, fixture.order.steps)
	}
	if len(fixture.firewall.rules) == 0 || len(fixture.accounts.records) != 2 {
		t.Fatal("a failed stop still removed firewall rules or accounts")
	}
}

// TestRemoveInstalledSetupReportsResidueAndKeepsTheJournal: an unreconciled
// lease is reported (path and code), every other owned object is still
// removed, and the state root holding the journal is kept for a retry.
func TestRemoveInstalledSetupReportsResidueAndKeepsTheJournal(t *testing.T) {
	for name, leases := range map[string]func(validatedSetup) ([]SetupProblem, error){
		"stuck object": func(validatedSetup) ([]SetupProblem, error) {
			return []SetupProblem{{Code: SetupProblemLeaseRecoveryPending, Resource: "broker-lease", Path: `C:\work\stuck.txt`}}, nil
		},
		"unreadable journal": func(validatedSetup) ([]SetupProblem, error) {
			return nil, errors.New("corrupt journal")
		},
	} {
		t.Run(name, func(t *testing.T) {
			fixture := newRemovalFixture(t)
			err := fixture.remove(leases)
			var residue *SetupResidueError
			if !errors.As(err, &residue) || len(residue.Problems) != 1 || residue.Problems[0].Code != SetupProblemLeaseRecoveryPending || residue.Problems[0].Path == "" {
				t.Fatalf("removal error = %v, want a residue report naming a path", err)
			}
			if slices.Contains(fixture.order.steps, "remove-root") {
				t.Fatal("a journal with unreleased leases was deleted")
			}
			if len(fixture.firewall.rules) != 0 || len(fixture.accounts.records) != 0 || fixture.services.deleted == "" {
				t.Fatal("residue stopped removal of the installation's other objects")
			}
		})
	}
}

func TestRemoveInstalledSetupRequiresALeaseReconciler(t *testing.T) {
	fixture := newRemovalFixture(t)
	err := removeInstalledSetup(context.Background(), fixture.setup, fixture.manifest, setupRemovalMechanisms{
		accounts: fixture.accounts, services: fixture.services, credentials: &fakeCredentialStore{},
		firewall: fixture.firewall, removeDir: func(string) error { return nil },
		validateArtifacts: func(validatedSetup, setupManifest) error { return nil },
	})
	if err == nil || len(fixture.order.steps) != 0 {
		t.Fatalf("removal without a lease reconciler = %v order %v", err, fixture.order.steps)
	}
}

// TestReconcileJournaledBrokerLeasesRollsBackReleasesAndReportsResidue drives
// the removal reconciler over the broker's own journal: every unreleased lease
// is rolled back and recorded Released; a lease whose rollback fails is
// reported per object and stays journaled for a retry.
func TestReconcileJournaledBrokerLeasesRollsBackReleasesAndReportsResidue(t *testing.T) {
	broker, connection, acl, store, _, reference := newBrokerTestRig(t)
	brokerAcquire(t, broker, connection, reference)
	identity := connection.authorized[reference.Handle].Identity
	journal, err := newBrokerLeaseJournal(store)
	if err != nil {
		t.Fatal(err)
	}
	acl.rollbackErr = errors.New("access denied")
	problems, err := reconcileJournaledBrokerLeases(journal, acl)
	if err != nil {
		t.Fatal(err)
	}
	if len(problems) != 1 || problems[0].Code != SetupProblemLeaseRecoveryPending || problems[0].Path != reference.Path {
		t.Fatalf("residue = %#v, want the stuck object", problems)
	}
	if recovered, err := journal.recover(); err != nil || len(recovered) != 1 {
		t.Fatalf("stuck lease left the journal: %v %v", recovered, err)
	}
	acl.rollbackErr = nil
	problems, err = reconcileJournaledBrokerLeases(journal, acl)
	if err != nil || len(problems) != 0 {
		t.Fatalf("retry = %#v %v", problems, err)
	}
	if recovered, err := journal.recover(); err != nil || len(recovered) != 0 || len(acl.aces[identity]) != 0 {
		t.Fatalf("after reconcile: recovered %v err %v aces %x", recovered, err, acl.aces[identity])
	}
}
