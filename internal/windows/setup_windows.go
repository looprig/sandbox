//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/looprig/sandbox/internal/enforce"
	win "golang.org/x/sys/windows"
)

func ValidateConfig(config Config) error {
	switch config.Mode {
	case Auto, RestrictedToken, Elevated:
		return nil
	default:
		return errors.New("sandbox: invalid Windows sandbox mode")
	}
}

func PlatformBackend(config Config, runtime *RestrictedRuntime) (enforce.Backend, error) {
	if err := ValidateConfig(config); err != nil {
		return nil, err
	}
	switch config.Mode {
	case Auto:
		restrictedConfig := config
		restrictedConfig.Mode = Auto
		return &autoBackend{
			elevated:   newElevatedBackend(config),
			restricted: newRestrictedBackend(restrictedConfig, runtime),
		}, nil
	case RestrictedToken:
		return newRestrictedBackend(config, runtime), nil
	case Elevated:
		return newElevatedBackend(config), nil
	default:
		panic("validated Windows mode became invalid")
	}
}

func Inspect(ctx context.Context, config SetupConfig) (SetupStatus, error) {
	return inspectSetup(ctx, config, pendingSetupDependencyInspector{})
}

type setupDependencyReadiness struct {
	service, accounts, credentials, firewallEffective, firewallUnchanged, runtimeBaseline bool
	portPID                                                                               map[uint16]uint32
}

type setupDependencyInspector interface {
	Inspect(context.Context, validatedSetup, setupManifest) (setupDependencyReadiness, error)
}

// Tasks 15, 16, and the runtime evidence gate replace these fail-closed
// answers with their narrow live inspectors. Absence is never treated as ready.
type pendingSetupDependencyInspector struct{}

func (pendingSetupDependencyInspector) Inspect(context.Context, validatedSetup, setupManifest) (setupDependencyReadiness, error) {
	return setupDependencyReadiness{}, nil
}

func inspectSetup(ctx context.Context, config SetupConfig, dependencies setupDependencyInspector) (SetupStatus, error) {
	validated, err := validateSetupConfig(config, false)
	if err != nil {
		return SetupStatus{}, err
	}
	data, err := os.ReadFile(filepath.Join(validated.stateRoot, readyManifestName))
	if err != nil {
		if os.IsNotExist(err) {
			return statusFromInspection(setupInspection{Requested: config}), nil
		}
		return SetupStatus{}, fmt.Errorf("read Windows setup manifest: %w", err)
	}
	manifest, decodeErr := decodeSetupManifest(data)
	facts := setupInspection{Manifest: &manifest, ManifestErr: decodeErr, Requested: config, OwnerSID: validated.ownerSID, Protocol: brokerProtocolVersion,
		ServiceReady: false, AccountsReady: false, CredentialsReady: false, FirewallEffective: false, FirewallUnchanged: false, RuntimeBaselineReady: false}
	if decodeErr == nil {
		if pathErr := validateInstalledHostPath(validated.stateRoot, manifest.HostPath); pathErr != nil {
			facts.ManifestErr = pathErr
		} else if reparseErr := rejectExistingSetupReparse(validated.stateRoot, manifest.HostPath); reparseErr != nil {
			facts.ManifestErr = reparseErr
		} else {
			facts.HostSHA256, _ = hashFile(manifest.HostPath)
			readiness, inspectErr := dependencies.Inspect(ctx, validated, manifest)
			if inspectErr != nil {
				return SetupStatus{}, fmt.Errorf("inspect Windows setup dependencies: %w", inspectErr)
			}
			facts.ServiceReady = readiness.service
			facts.AccountsReady = readiness.accounts
			facts.CredentialsReady = readiness.credentials
			facts.FirewallEffective = readiness.firewallEffective
			facts.FirewallUnchanged = readiness.firewallUnchanged
			facts.PortPID = readiness.portPID
			facts.RuntimeBaselineReady = readiness.runtimeBaseline
		}
	}
	select {
	case <-ctx.Done():
		return SetupStatus{}, ctx.Err()
	default:
	}
	return statusFromInspection(facts), nil
}

func validateInstalledHostPath(stateRoot, hostPath string) error {
	if !filepath.IsAbs(hostPath) || filepath.Clean(hostPath) != hostPath {
		return errors.New("sandbox: installed Windows host path is not canonical")
	}
	slotsRoot := filepath.Join(filepath.Clean(stateRoot), "slots")
	relative, err := filepath.Rel(slotsRoot, hostPath)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, `..\`) {
		return errors.New("sandbox: installed Windows host path escapes protected slots")
	}
	parts := strings.Split(relative, string(filepath.Separator))
	if len(parts) != 2 || parts[0] == "" || !strings.EqualFold(parts[1], "sandbox-host.exe") {
		return errors.New("sandbox: installed Windows host path is not a protected slot executable")
	}
	return nil
}

func Setup(ctx context.Context, config SetupConfig) error {
	validated, err := validateSetupConfig(config, true)
	if err != nil {
		return err
	}
	if err := installHost(ctx, validated, realHostInstallMechanisms{}); err != nil {
		return err
	}
	status, err := Inspect(ctx, config)
	if err != nil {
		return err
	}
	if !status.Ready {
		return ErrSetupStale
	}
	return nil
}

// initializeSetupIdentities is the Task 15 boundary between elevated setup and
// the LocalSystem broker. The request contains desired names/configuration but
// no password. Task 17 supplies the authenticated service client and calls this
// before a generation is promoted to ready.
func initializeSetupIdentities(ctx context.Context, setup validatedSetup, manifest setupManifest, initializer serviceInitializer) (brokerIdentityHealth, error) {
	if initializer == nil {
		return brokerIdentityHealth{}, errors.New("sandbox: Windows broker initializer is unavailable")
	}
	if manifest.InstallationID != setup.config.InstallationID || manifest.State != setupStateStaging {
		return brokerIdentityHealth{}, errors.New("sandbox: Windows identity initialization requires the owned staging generation")
	}
	if err := validateInstalledHostPath(setup.stateRoot, manifest.HostPath); err != nil {
		return brokerIdentityHealth{}, err
	}
	desired, err := desiredBrokerState(setup.config.InstallationID, manifest.HostPath)
	if err != nil {
		return brokerIdentityHealth{}, err
	}
	return initializeBrokerIdentities(ctx, initializer, desired)
}

type brokerRuntimeConfig struct {
	StateRoot, HostPath, InstallationID, OwnerSID string
	Protocol                                      uint16
	OfflineAccount, OnlineAccount                 string
	OfflineCredential, OnlineCredential           string
	PipeName, JournalPath                         string
}

func loadInstalledBrokerRuntimeConfig() (brokerRuntimeConfig, error) {
	executable, err := os.Executable()
	if err != nil {
		return brokerRuntimeConfig{}, err
	}
	return loadBrokerRuntimeConfigAt(executable, os.Getenv("ProgramData"))
}

func loadBrokerRuntimeConfigAt(executable, programData string) (brokerRuntimeConfig, error) {
	return loadBrokerRuntimeConfigWithVerifier(executable, programData, realBrokerInstallPathVerifier{})
}

type brokerInstallPathVerifier interface {
	Verify(path, ownerSID string) error
}
type realBrokerInstallPathVerifier struct{}

func (realBrokerInstallPathVerifier) Verify(path, ownerSID string) error {
	sd, err := win.GetNamedSecurityInfo(path, win.SE_FILE_OBJECT, win.OWNER_SECURITY_INFORMATION|win.DACL_SECURITY_INFORMATION)
	if err != nil || sd == nil {
		return errors.Join(errors.New("sandbox: installed broker security descriptor is unavailable"), err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	want, err := win.StringToSid(ownerSID)
	if err != nil {
		return err
	}
	control, _, err := sd.Control()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(want) || control&win.SE_DACL_PROTECTED == 0 {
		return errors.New("sandbox: installed broker object is not manifest-owner protected")
	}
	return nil
}

func loadBrokerRuntimeConfigWithVerifier(executable, programData string, verifier brokerInstallPathVerifier) (brokerRuntimeConfig, error) {
	executable, err := filepath.Abs(executable)
	if err != nil || !strings.EqualFold(filepath.Base(executable), "sandbox-host.exe") {
		return brokerRuntimeConfig{}, errors.New("sandbox: broker executable path is invalid")
	}
	generationDir, parent := filepath.Dir(executable), filepath.Dir(filepath.Dir(executable))
	var stateRoot, manifestPath string
	switch {
	case strings.EqualFold(filepath.Base(parent), "slots"):
		stateRoot, manifestPath = filepath.Dir(parent), filepath.Join(filepath.Dir(parent), readyManifestName)
	case strings.HasPrefix(strings.ToLower(filepath.Base(generationDir)), ".staging-"):
		stateRoot, manifestPath = filepath.Dir(generationDir), filepath.Join(generationDir, "manifest.json")
	default:
		return brokerRuntimeConfig{}, errors.New("sandbox: broker executable is outside an installation generation")
	}
	programData, err = filepath.Abs(programData)
	if err != nil || programData == "." {
		return brokerRuntimeConfig{}, errors.New("sandbox: ProgramData is unavailable")
	}
	relative, err := filepath.Rel(programData, stateRoot)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, `..\`) {
		return brokerRuntimeConfig{}, errors.New("sandbox: broker state root is outside ProgramData")
	}
	if err := rejectExistingSetupReparse(programData, stateRoot); err != nil {
		return brokerRuntimeConfig{}, err
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return brokerRuntimeConfig{}, err
	}
	manifest, err := decodeSetupManifest(data)
	if err != nil || (manifest.State != setupStateReady && manifest.State != setupStateStaging) {
		return brokerRuntimeConfig{}, errors.Join(errors.New("sandbox: broker manifest is not usable"), err)
	}
	if verifier == nil {
		return brokerRuntimeConfig{}, errors.New("sandbox: broker path verifier is unavailable")
	}
	if err := verifier.Verify(manifestPath, manifest.OwnerSID); err != nil {
		return brokerRuntimeConfig{}, err
	}
	if err := verifier.Verify(executable, manifest.OwnerSID); err != nil {
		return brokerRuntimeConfig{}, err
	}
	digest, err := hashFile(executable)
	if err != nil || !strings.EqualFold(digest, manifest.HostSHA256) {
		return brokerRuntimeConfig{}, errors.Join(errors.New("sandbox: broker executable hash does not match manifest"), err)
	}
	if manifest.State == setupStateReady && !strings.EqualFold(filepath.Clean(manifest.HostPath), filepath.Clean(executable)) {
		return brokerRuntimeConfig{}, errors.New("sandbox: ready manifest does not own broker executable")
	}
	names, err := deriveInstallationPrincipalNames(manifest.InstallationID)
	if err != nil {
		return brokerRuntimeConfig{}, err
	}
	credentials, suffix := filepath.Join(stateRoot, "credentials"), strings.TrimPrefix(names.Service, "lsb-svc-")
	return brokerRuntimeConfig{StateRoot: filepath.Clean(stateRoot), HostPath: filepath.Clean(executable), InstallationID: manifest.InstallationID, OwnerSID: manifest.OwnerSID, Protocol: manifest.Protocol,
		OfflineAccount: names.Offline, OnlineAccount: names.Online, OfflineCredential: filepath.Join(credentials, "offline.dpapi"), OnlineCredential: filepath.Join(credentials, "online.dpapi"),
		PipeName: `\\.\pipe\looprig-sandbox-` + suffix, JournalPath: filepath.Join(stateRoot, "broker-leases.journal")}, nil
}

func Remove(context.Context, SetupConfig) error { return enforce.ErrUnavailable }

type validatedSetup struct {
	config                                      SetupConfig
	stateRoot, sourceHost, ownerSID, sandboxSID string
}

func validateSetupConfig(config SetupConfig, requireElevation bool) (validatedSetup, error) {
	if requireElevation {
		token := win.GetCurrentProcessToken()
		if !token.IsElevated() {
			return validatedSetup{}, ErrElevationRequired
		}
	}
	if strings.TrimSpace(config.InstallationID) == "" {
		return validatedSetup{}, errors.New("sandbox: Windows installation identity is required")
	}
	if err := validateProxyPorts(config.ProxyPorts); err != nil {
		return validatedSetup{}, err
	}
	root, err := filepath.Abs(config.StateRoot)
	if err != nil || !filepath.IsAbs(root) {
		return validatedSetup{}, errors.New("sandbox: Windows state root must be absolute")
	}
	programData, err := filepath.Abs(os.Getenv("ProgramData"))
	if err != nil || programData == "." {
		return validatedSetup{}, errors.New("sandbox: ProgramData is unavailable")
	}
	rel, err := filepath.Rel(programData, root)
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, `..\`) {
		return validatedSetup{}, errors.New("sandbox: Windows state root must be beneath ProgramData")
	}
	if win.GetDriveType(win.StringToUTF16Ptr(filepath.VolumeName(root)+`\`)) != win.DRIVE_FIXED {
		return validatedSetup{}, errors.New("sandbox: Windows state root must be on a local fixed drive")
	}
	if err := rejectExistingSetupReparse(programData, root); err != nil {
		return validatedSetup{}, err
	}
	if requireElevation {
		info, statErr := os.Stat(config.HostBinary)
		if statErr != nil || !info.Mode().IsRegular() {
			return validatedSetup{}, errors.New("sandbox: Windows host binary must be a regular file")
		}
	}
	user, err := win.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return validatedSetup{}, fmt.Errorf("inspect Windows setup owner: %w", err)
	}
	installationSID, err := InstallationSID(config.InstallationID)
	if err != nil {
		return validatedSetup{}, err
	}
	return validatedSetup{config: config, stateRoot: filepath.Clean(root), sourceHost: filepath.Clean(config.HostBinary), ownerSID: user.User.Sid.String(), sandboxSID: installationSID.String()}, nil
}

func rejectExistingSetupReparse(programData, root string) error {
	relative, err := filepath.Rel(programData, root)
	if err != nil {
		return err
	}
	current := filepath.Clean(programData)
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		current = filepath.Join(current, component)
		attributes, err := win.GetFileAttributes(win.StringToUTF16Ptr(current))
		if errors.Is(err, win.ERROR_FILE_NOT_FOUND) || errors.Is(err, win.ERROR_PATH_NOT_FOUND) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("inspect Windows setup path: %w", err)
		}
		if attributes&win.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return errors.New("sandbox: Windows state root must not traverse a reparse point")
		}
	}
	return nil
}
