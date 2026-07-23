//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Initialize completes privileged dependency creation only after the protected
// generation is at its immutable final path. The LocalSystem service obtains
// all desired state from that generation's protected manifest and returns
// identity pins by atomically enriching the same manifest.
func (mechanisms *realHostInstallMechanisms) Initialize(ctx context.Context, setup validatedSetup, staged stagedHost, manifest setupManifest) (setupManifest, error) {
	desired, err := desiredBrokerState(manifest.InstallationID, staged.finalHost)
	if err != nil {
		return setupManifest{}, err
	}
	identity := serviceSpecIdentity(desired.Service)
	mechanisms.owned = manifest
	mechanisms.owned.ServiceIdentity = identity

	scm := realSCMFacade{}
	if _, lookupErr := scm.Lookup(brokerServiceSpecModel{Name: desired.Service.Name}); !errors.Is(lookupErr, errServiceNotFound) {
		if lookupErr == nil {
			return setupManifest{}, errServiceOwnershipMismatch
		}
		return setupManifest{}, lookupErr
	}
	if err := scm.Create(desired.Service); err != nil {
		return setupManifest{}, err
	}
	mechanisms.serviceCreated = true
	record, err := scm.Lookup(desired.Service)
	if err != nil || record.Identity != identity {
		return setupManifest{}, errors.Join(errors.New("sandbox: created Windows broker service failed exact read-back"), err)
	}
	if err := scm.Start(desired.Service.Name); err != nil {
		return setupManifest{}, err
	}

	generationManifest := filepath.Join(staged.finalDir, "manifest.json")
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		enriched, readErr := readInitializedGenerationManifest(generationManifest, manifest, identity)
		if readErr == nil {
			ready, inspectErr := inspectInitializedHostDependencies(ctx, setup, enriched)
			if inspectErr == nil && ready {
				mechanisms.owned = enriched
				return enriched, nil
			}
			if inspectErr != nil {
				return setupManifest{}, inspectErr
			}
		} else if !errors.Is(readErr, errInitializationPending) {
			return setupManifest{}, readErr
		}
		select {
		case <-ctx.Done():
			return setupManifest{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

var errInitializationPending = errors.New("sandbox: Windows broker initialization is pending")

func readInitializedGenerationManifest(path string, original setupManifest, serviceIdentity string) (setupManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return setupManifest{}, err
	}
	manifest, err := decodeSetupManifest(data)
	if err != nil {
		return setupManifest{}, err
	}
	if manifest.Version != original.Version || manifest.State != setupStateStaging ||
		manifest.InstallationID != original.InstallationID || manifest.OwnerSID != original.OwnerSID ||
		manifest.HostPath != original.HostPath || manifest.HostSHA256 != original.HostSHA256 ||
		manifest.Protocol != original.Protocol || !equalUint16Sets(manifest.ProxyPorts, original.ProxyPorts) {
		return setupManifest{}, errors.New("sandbox: initialized generation changed protected manifest identity")
	}
	if manifest.OfflineSID == "" || manifest.OnlineSID == "" || manifest.OfflineSID == manifest.OnlineSID ||
		manifest.ServiceIdentity != serviceIdentity {
		return setupManifest{}, errInitializationPending
	}
	return manifest, nil
}

func equalUint16Sets(left, right []uint16) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

type initializationEvidence struct{}

func (initializationEvidence) Approved(context.Context, validatedSetup, setupManifest) (bool, error) {
	return true, nil
}

func inspectInitializedHostDependencies(ctx context.Context, setup validatedSetup, manifest setupManifest) (bool, error) {
	inspector := manifestPinnedSetupInspector{
		evidence: initializationEvidence{},
		policy:   windowsFirewallPolicy{api: newNetFwAutomation()},
		owners:   windowsTCPPortOwner{tables: ipHelperTCPTableAPI{}},
	}
	readiness, err := inspector.Inspect(ctx, setup, manifest)
	if err != nil {
		return false, err
	}
	return readiness.service && readiness.accounts && readiness.credentials &&
		readiness.firewallEffective && readiness.firewallUnchanged &&
		readiness.runtimeBaseline && len(readiness.portPID) == 0, nil
}

func rollbackInstalledHostDependencies(manifest setupManifest, staged stagedHost, removeService bool) error {
	if manifest.InstallationID == "" || manifest.ServiceIdentity == "" {
		return nil
	}
	names, err := deriveInstallationPrincipalNames(manifest.InstallationID)
	if err != nil {
		return err
	}
	var result error
	if manifest.OfflineSID != "" {
		if rules, rulesErr := offlineFirewallRules(manifest.InstallationID, manifest.OfflineSID, manifest.ProxyPorts); rulesErr != nil {
			result = errors.Join(result, rulesErr)
		} else {
			result = errors.Join(result, removeOfflineFirewall(windowsFirewallPolicy{api: newNetFwAutomation()}, rules))
		}
	}
	accounts := netLSAAccountAPI{native: realAccountNative{}, ownedSID: map[string]string{
		names.Offline: manifest.OfflineSID,
		names.Online:  manifest.OnlineSID,
	}}
	if removeService {
		services := scmServiceAPI{scm: realSCMFacade{}, ownedIdentity: manifest.ServiceIdentity}
		result = errors.Join(result, removeBrokerService(services, names.Service, manifest.ServiceIdentity))
	}
	if manifest.OfflineSID != "" {
		result = errors.Join(result, removeSandboxAccount(accounts, names.Offline, manifest.OfflineSID))
	}
	if manifest.OnlineSID != "" {
		result = errors.Join(result, removeSandboxAccount(accounts, names.Online, manifest.OnlineSID))
	}
	store := atomicCredentialStore{root: filepath.Join(filepath.Dir(filepath.Dir(staged.finalDir)), "credentials"), files: realCredentialFileOps{}}
	result = errors.Join(result, store.RemoveProtected("offline"), store.RemoveProtected("online"))
	if result != nil {
		return fmt.Errorf("rollback Windows host dependencies: %w", result)
	}
	return nil
}
