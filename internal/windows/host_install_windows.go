//go:build windows

package windows

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	win "golang.org/x/sys/windows"
)

const readyManifestName = "ready.json"

type stagedHost struct{ stagingDir, finalDir, finalHost, digest string }

// hostInstallMechanisms is intentionally smaller than setup. Later account,
// service and firewall phases can compose their own transactions around it.
type hostInstallMechanisms interface {
	Prepare(validatedSetup) error
	Stage(validatedSetup) (stagedHost, error)
	PersistStaging(validatedSetup, stagedHost, []byte) error
	SelfTest(context.Context, stagedHost) error
	Promote(validatedSetup, stagedHost) error
	Activate(validatedSetup, stagedHost, []byte) error
	Rollback(stagedHost) error
}

type hostDependencyInitializer interface {
	Initialize(context.Context, validatedSetup, stagedHost, setupManifest) (setupManifest, error)
}

func installHost(ctx context.Context, setup validatedSetup, mechanisms hostInstallMechanisms) (err error) {
	if err = mechanisms.Prepare(setup); err != nil {
		return fmt.Errorf("prepare protected Windows setup root: %w", err)
	}
	staged, err := mechanisms.Stage(setup)
	if err != nil {
		return errors.Join(fmt.Errorf("stage protected Windows host: %w", err), mechanisms.Rollback(staged))
	}
	activated := false
	defer func() {
		if !activated {
			err = errors.Join(err, mechanisms.Rollback(staged))
		}
	}()
	stagingManifest := setupManifest{Version: setupManifestVersion, State: setupStateStaging, InstallationID: setup.config.InstallationID, OwnerSID: setup.ownerSID, HostPath: staged.finalHost, HostSHA256: staged.digest, ProxyPorts: append([]uint16(nil), setup.config.ProxyPorts...), Protocol: brokerProtocolVersion}
	if setup.prior != nil {
		// A refresh carries only identities pinned by the protected ready
		// manifest. Names are never adopted as ownership. The service identity
		// changes because its protected binary path changes with the generation.
		stagingManifest.OfflineSID = setup.prior.OfflineSID
		stagingManifest.OnlineSID = setup.prior.OnlineSID
		if desired, desiredErr := desiredBrokerState(stagingManifest.InstallationID, staged.finalHost); desiredErr != nil {
			return desiredErr
		} else {
			stagingManifest.ServiceIdentity = serviceSpecIdentity(desired.Service)
		}
	}
	stagingData, err := encodeSetupManifest(stagingManifest)
	if err != nil {
		return err
	}
	if err = mechanisms.PersistStaging(setup, staged, stagingData); err != nil {
		return fmt.Errorf("persist staging Windows manifest: %w", err)
	}
	if err = mechanisms.SelfTest(ctx, staged); err != nil {
		return fmt.Errorf("self-test staged Windows host: %w", err)
	}
	if err = mechanisms.Promote(setup, staged); err != nil {
		return fmt.Errorf("promote protected Windows host generation: %w", err)
	}
	manifest := stagingManifest
	if initializer, ok := mechanisms.(hostDependencyInitializer); ok {
		manifest, err = initializer.Initialize(ctx, setup, staged, stagingManifest)
		if err != nil {
			return fmt.Errorf("initialize protected Windows host dependencies: %w", err)
		}
	}
	manifest.State = setupStateReady
	data, err := encodeSetupManifest(manifest)
	if err != nil {
		return err
	}
	if err = mechanisms.Activate(setup, staged, data); err != nil {
		return fmt.Errorf("activate protected Windows host: %w", err)
	}
	activated = true
	return nil
}

type realHostInstallMechanisms struct {
	owned           setupManifest
	serviceCreated  bool
	serviceUpdated  bool
	previousService *brokerServiceRecord
	runtimeEvidence approvedRuntimeEvidenceInspector
}

func (realHostInstallMechanisms) Prepare(setup validatedSetup) error {
	if err := os.MkdirAll(filepath.Join(setup.stateRoot, "slots"), 0700); err != nil {
		return err
	}
	return protectSetupPath(setup.stateRoot, setup.ownerSID, setup.sandboxSID, true)
}

func (realHostInstallMechanisms) Stage(setup validatedSetup) (stagedHost, error) {
	id := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, id); err != nil {
		return stagedHost{}, err
	}
	name := hex.EncodeToString(id)
	stage := filepath.Join(setup.stateRoot, ".staging-"+name)
	final := filepath.Join(setup.stateRoot, "slots", name)
	if err := os.Mkdir(stage, 0700); err != nil {
		return stagedHost{}, err
	}
	result := stagedHost{stagingDir: stage, finalDir: final, finalHost: filepath.Join(final, "sandbox-host.exe")}
	stageHost := filepath.Join(stage, "sandbox-host.exe")
	if err := copyExclusive(setup.sourceHost, stageHost); err != nil {
		return result, err
	}
	digest, err := hashFile(stageHost)
	if err != nil {
		return result, err
	}
	result.digest = digest
	if err := protectSetupPath(stage, setup.ownerSID, setup.sandboxSID, true); err != nil {
		return result, err
	}
	if err := protectSetupPath(stageHost, setup.ownerSID, setup.sandboxSID, false); err != nil {
		return result, err
	}
	return result, nil
}

func (realHostInstallMechanisms) PersistStaging(setup validatedSetup, staged stagedHost, manifest []byte) error {
	path := filepath.Join(staged.stagingDir, "manifest.json")
	if err := os.WriteFile(path, manifest, 0600); err != nil {
		return err
	}
	return protectSetupPath(path, setup.ownerSID, setup.sandboxSID, false)
}

func (realHostInstallMechanisms) SelfTest(ctx context.Context, staged stagedHost) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	digest, err := hashFile(filepath.Join(staged.stagingDir, "sandbox-host.exe"))
	if err != nil {
		return err
	}
	if digest != staged.digest {
		return errors.New("sandbox: staged Windows host changed before activation")
	}
	command := exec.CommandContext(ctx, filepath.Join(staged.stagingDir, "sandbox-host.exe"), "--self-test")
	if err := command.Run(); err != nil {
		return fmt.Errorf("run installed host self-test: %w", err)
	}
	return nil
}

func (realHostInstallMechanisms) Promote(_ validatedSetup, staged stagedHost) error {
	if err := os.Rename(staged.stagingDir, staged.finalDir); err != nil {
		return err
	}
	return nil
}

func (realHostInstallMechanisms) Activate(setup validatedSetup, staged stagedHost, manifest []byte) error {
	temporary := filepath.Join(setup.stateRoot, ".ready.tmp")
	if err := os.WriteFile(temporary, manifest, 0600); err != nil {
		return err
	}
	if err := protectSetupPath(temporary, setup.ownerSID, setup.sandboxSID, false); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	if err := win.MoveFileEx(win.StringToUTF16Ptr(temporary), win.StringToUTF16Ptr(filepath.Join(setup.stateRoot, readyManifestName)), win.MOVEFILE_REPLACE_EXISTING|win.MOVEFILE_WRITE_THROUGH); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return nil
}

func (mechanisms *realHostInstallMechanisms) Rollback(staged stagedHost) error {
	var result error
	if mechanisms.owned.InstallationID != "" && mechanisms.serviceCreated {
		result = errors.Join(result, rollbackInstalledHostDependencies(mechanisms.owned, staged, true))
	}
	if mechanisms.serviceUpdated && mechanisms.previousService != nil {
		result = errors.Join(result, restoreSetupService(realSCMFacade{}, *mechanisms.previousService))
	}
	if staged.stagingDir != "" {
		result = errors.Join(result, os.RemoveAll(staged.stagingDir))
	}
	// A final slot without a ready manifest is unreachable and safe to remove.
	if staged.finalDir != "" {
		result = errors.Join(result, os.RemoveAll(staged.finalDir))
	}
	return result
}

func copyExclusive(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	syncErr := out.Sync()
	closeErr := out.Close()
	return errors.Join(copyErr, syncErr, closeErr)
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func protectSetupPath(path, ownerSID, sandboxSID string, directory bool) error {
	inherit := ""
	if directory {
		inherit = "(CI)(OI)"
	}
	// SYSTEM, Administrators and the installing owner retain full control. The
	// sandbox trustee gets only generic read/execute, including descendants.
	sddl := fmt.Sprintf("O:%sG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;%s)(A;%s;GRGX;;;%s)", ownerSID, ownerSID, inherit, sandboxSID)
	sd, err := win.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, err := win.StringToSid(ownerSID)
	if err != nil {
		return err
	}
	return win.SetNamedSecurityInfo(path, win.SE_FILE_OBJECT, win.OWNER_SECURITY_INFORMATION|win.DACL_SECURITY_INFORMATION|win.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
}
