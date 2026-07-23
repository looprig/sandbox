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

	evidence := mechanisms.runtimeEvidence
	if evidence == nil {
		evidence = unavailableApprovedRuntimeEvidence{}
	}
	approved, err := evidence.Approved(ctx, setup, manifest)
	if err != nil {
		return setupManifest{}, fmt.Errorf("inspect approved Windows runtime evidence: %w", err)
	}
	if !approved {
		return setupManifest{}, fmt.Errorf("%w: approved Windows runtime evidence is unavailable", ErrSetupStale)
	}

	scm := realSCMFacade{}
	created, previous, serviceErr := reconcileSetupService(scm, desired.Service, setup.prior)
	mechanisms.serviceCreated = created
	mechanisms.serviceUpdated = previous != nil
	mechanisms.previousService = previous
	if serviceErr != nil {
		return setupManifest{}, serviceErr
	}
	record, err := scm.Lookup(desired.Service)
	if err != nil || record.Identity != identity {
		return setupManifest{}, errors.Join(errors.New("sandbox: created Windows broker service failed exact read-back"), err)
	}

	generationManifest := filepath.Join(staged.finalDir, "manifest.json")
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		enriched, readErr := readInitializedGenerationManifest(generationManifest, manifest, identity)
		if readErr == nil {
			// Capture manifest-pinned ownership before any later read-back can
			// fail. Rollback must be able to remove every object the service
			// published, including after firewall/port/evidence failures.
			mechanisms.owned = enriched
			ready, inspectErr := initializedDependenciesReady(ctx, setup, enriched, manifestPinnedSetupInspector{
				evidence: evidence,
				policy:   windowsFirewallPolicy{api: newNetFwAutomation()},
				owners:   windowsTCPPortOwner{tables: ipHelperTCPTableAPI{}},
			})
			if inspectErr == nil && ready {
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

func initializedDependenciesReady(ctx context.Context, setup validatedSetup, manifest setupManifest, inspector setupDependencyInspector) (bool, error) {
	if inspector == nil {
		return false, errors.New("sandbox: Windows setup dependency inspector is unavailable")
	}
	readiness, err := inspector.Inspect(ctx, setup, manifest)
	if err != nil {
		return false, err
	}
	return readiness.service && readiness.accounts && readiness.credentials &&
		readiness.firewallEffective && readiness.firewallUnchanged &&
		readiness.runtimeBaseline && len(readiness.portPID) == 0, nil
}

func reconcileSetupService(api scmFacade, desired brokerServiceSpecModel, prior *setupManifest) (bool, *brokerServiceRecord, error) {
	record, err := api.Lookup(brokerServiceSpecModel{Name: desired.Name})
	if errors.Is(err, errServiceNotFound) {
		if err := api.Create(desired); err != nil {
			return false, nil, err
		}
		if err := api.Start(desired.Name); err != nil {
			return true, nil, err
		}
		return true, nil, nil
	}
	if err != nil {
		return false, nil, err
	}
	if prior == nil || prior.ServiceIdentity == "" || record.Identity != prior.ServiceIdentity ||
		record.Spec.Name != desired.Name {
		return false, nil, errServiceOwnershipMismatch
	}
	previous := record
	if err := api.Stop(desired.Name); err != nil {
		return false, nil, err
	}
	if err := api.Apply(desired); err != nil {
		return false, &previous, err
	}
	if err := api.Start(desired.Name); err != nil {
		return false, &previous, err
	}
	return false, &previous, nil
}

func restoreSetupService(api scmFacade, previous brokerServiceRecord) error {
	if previous.Identity == "" || previous.Spec.Name == "" ||
		serviceSpecIdentity(previous.Spec) != previous.Identity {
		return errServiceOwnershipMismatch
	}
	var result error
	result = errors.Join(result, api.Stop(previous.Spec.Name))
	result = errors.Join(result, api.Apply(previous.Spec))
	if previous.Running {
		result = errors.Join(result, api.Start(previous.Spec.Name))
	}
	return result
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
