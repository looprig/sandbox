//go:build windows

package windows

import (
	"context"
	"errors"
)

type offlineAccountSIDSource interface {
	OfflineAccountSID(context.Context, validatedSetup, setupManifest) (sid string, found bool, err error)
}

// firewallSetupDependencyInspector decorates the Task 15/runtime inspector. It
// owns only firewall and port health, preserving the other readiness fields.
type firewallSetupDependencyInspector struct {
	base     setupDependencyInspector
	accounts offlineAccountSIDSource
	policy   offlineFirewallPolicy
	owners   proxyPortOwner
}

func (i firewallSetupDependencyInspector) Inspect(ctx context.Context, setup validatedSetup, manifest setupManifest) (setupDependencyReadiness, error) {
	if i.base == nil || i.accounts == nil || i.policy == nil || i.owners == nil {
		return setupDependencyReadiness{}, errors.New("sandbox: incomplete Windows firewall setup inspector")
	}
	readiness, err := i.base.Inspect(ctx, setup, manifest)
	if err != nil {
		return setupDependencyReadiness{}, err
	}
	sid, found, err := i.accounts.OfflineAccountSID(ctx, setup, manifest)
	if err != nil {
		return setupDependencyReadiness{}, err
	}
	if found {
		rules, modelErr := offlineFirewallRules(manifest.InstallationID, sid, manifest.ProxyPorts)
		if modelErr != nil {
			return setupDependencyReadiness{}, modelErr
		}
		readiness.firewallEffective, readiness.firewallUnchanged, err = inspectOfflineFirewall(i.policy, rules)
		if err != nil {
			return setupDependencyReadiness{}, err
		}
	}
	readiness.portPID, err = inspectProxyPortOwners(manifest.ProxyPorts, i.owners)
	return readiness, err
}

type accountOfflineSIDSource struct{ accounts accountAPI }

func (s accountOfflineSIDSource) OfflineAccountSID(_ context.Context, setup validatedSetup, _ setupManifest) (string, bool, error) {
	if s.accounts == nil {
		return "", false, errors.New("sandbox: Windows account inspector is unavailable")
	}
	names, err := deriveInstallationPrincipalNames(setup.config.InstallationID)
	if err != nil {
		return "", false, err
	}
	record, err := s.accounts.Lookup(names.Offline)
	if errors.Is(err, errAccountNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !record.Owned || record.Name != names.Offline || record.SID == "" {
		return "", false, errAccountOwnershipMismatch
	}
	return record.SID, true, nil
}
