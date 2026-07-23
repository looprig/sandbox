//go:build windows

package windows

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"

	win "golang.org/x/sys/windows"
)

// initializeInstalledBrokerDependencies is entered only by the LocalSystem
// service when its protected generation manifest is still staging. It accepts
// no caller-supplied names, SIDs, passwords, paths, or policy.
func initializeInstalledBrokerDependencies(config brokerRuntimeConfig) (err error) {
	if config.ManifestState != setupStateStaging || config.GenerationManifestPath == "" ||
		filepath.Clean(config.GenerationManifestPath) != filepath.Join(filepath.Dir(config.HostPath), "manifest.json") {
		return errors.New("sandbox: invalid Windows broker initialization generation")
	}
	desired, err := desiredBrokerState(config.InstallationID, config.HostPath)
	if err != nil {
		return err
	}
	serviceIdentity := serviceSpecIdentity(desired.Service)
	if config.ServiceIdentity != "" && config.ServiceIdentity != serviceIdentity {
		return errServiceOwnershipMismatch
	}
	service, err := (realSCMFacade{}).Lookup(desired.Service)
	if err != nil || service.Identity != serviceIdentity || !service.Running {
		return errors.Join(errors.New("sandbox: initializing Windows broker service failed exact read-back"), err)
	}
	if config.OfflineSID != "" || config.OnlineSID != "" || config.ServiceIdentity != "" {
		if config.OfflineSID == "" || config.OnlineSID == "" || config.ServiceIdentity != serviceIdentity {
			return errors.New("sandbox: partially initialized Windows broker manifest")
		}
		data, readErr := os.ReadFile(config.GenerationManifestPath)
		manifest, decodeErr := decodeSetupManifest(data)
		if readErr != nil || decodeErr != nil {
			return errors.Join(errors.New("sandbox: initialized Windows broker manifest is unreadable"), readErr, decodeErr)
		}
		setup := validatedSetup{
			config:    SetupConfig{InstallationID: config.InstallationID, StateRoot: config.StateRoot, ProxyPorts: append([]uint16(nil), config.ProxyPorts...)},
			stateRoot: config.StateRoot, ownerSID: config.OwnerSID,
		}
		ready, inspectErr := inspectInitializedHostDependencies(context.Background(), setup, manifest)
		if inspectErr != nil || !ready {
			return errors.Join(errors.New("sandbox: initialized Windows broker dependencies failed exact read-back"), inspectErr)
		}
		return nil
	}

	owned := map[string]string{
		desired.OfflineAccount: config.OfflineSID,
		desired.OnlineAccount:  config.OnlineSID,
	}
	accounts := netLSAAccountAPI{native: realAccountNative{}, ownedSID: owned}
	store := atomicCredentialStore{root: filepath.Join(config.StateRoot, "credentials"), files: realCredentialFileOps{}}
	runtime := brokerIdentityRuntime{accounts: accounts, protector: systemDPAPI{}, store: store, random: rand.Reader}
	published := false
	var installedRules []offlineFirewallRule
	defer func() {
		if published {
			return
		}
		if len(installedRules) != 0 {
			err = errors.Join(err, removeOfflineFirewall(windowsFirewallPolicy{api: newNetFwAutomation()}, installedRules))
		}
		for _, entry := range []struct{ name, sid string }{
			{desired.OfflineAccount, owned[desired.OfflineAccount]},
			{desired.OnlineAccount, owned[desired.OnlineAccount]},
		} {
			if entry.sid != "" {
				err = errors.Join(err, removeSandboxAccount(accounts, entry.name, entry.sid))
			}
		}
		err = errors.Join(err, store.RemoveProtected("offline"), store.RemoveProtected("online"))
	}()

	health, err := provisionBrokerIdentityState(runtime, desired, false)
	if err != nil {
		return err
	}
	if config.OfflineSID != "" && config.OfflineSID != health.OfflineSID ||
		config.OnlineSID != "" && config.OnlineSID != health.OnlineSID {
		return errAccountOwnershipMismatch
	}
	installedRules, err = offlineFirewallRules(config.InstallationID, health.OfflineSID, config.ProxyPorts)
	if err != nil {
		return err
	}
	if err = installOfflineFirewall(windowsFirewallPolicy{api: newNetFwAutomation()}, config.InstallationID, health.OfflineSID, config.ProxyPorts); err != nil {
		return err
	}

	data, err := os.ReadFile(config.GenerationManifestPath)
	if err != nil {
		return err
	}
	manifest, err := decodeSetupManifest(data)
	if err != nil || manifest.State != setupStateStaging || manifest.InstallationID != config.InstallationID ||
		!strings.EqualFold(filepath.Clean(manifest.HostPath), config.HostPath) {
		return errors.Join(errors.New("sandbox: protected staging manifest changed during initialization"), err)
	}
	manifest.OfflineSID = health.OfflineSID
	manifest.OnlineSID = health.OnlineSID
	manifest.ServiceIdentity = serviceIdentity
	if err = writeProtectedGenerationManifest(config.GenerationManifestPath, manifest); err != nil {
		return err
	}
	published = true
	return nil
}

func writeProtectedGenerationManifest(path string, manifest setupManifest) (err error) {
	data, err := encodeSetupManifest(manifest)
	if err != nil {
		return err
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return err
	}
	temporary := path + ".tmp-" + hex.EncodeToString(nonce[:])
	defer func() {
		if err != nil {
			_ = os.Remove(temporary)
		}
	}()
	file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := file.Write(data)
	syncErr := file.Sync()
	closeErr := file.Close()
	if err = errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	sandboxSID, err := InstallationSID(manifest.InstallationID)
	if err != nil {
		return err
	}
	if err = protectSetupPath(temporary, manifest.OwnerSID, sandboxSID.String(), false); err != nil {
		return err
	}
	if err = win.MoveFileEx(win.StringToUTF16Ptr(temporary), win.StringToUTF16Ptr(path), win.MOVEFILE_REPLACE_EXISTING|win.MOVEFILE_WRITE_THROUGH); err != nil {
		return err
	}
	return nil
}
