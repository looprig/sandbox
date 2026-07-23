//go:build windows

package windows

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"time"
	"unsafe"

	win "golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	localSystemAccount    = `LocalSystem`
	serviceStartAutomatic = "automatic"
	serviceSIDRestricted  = "restricted"
)

var (
	errServiceNotFound          = errors.New("sandbox: Windows service not found")
	errServiceOwnershipMismatch = errors.New("sandbox: Windows service ownership mismatch")
)

type serviceFailureActions struct {
	Restart            bool
	ResetPeriodSeconds uint32
	RestartDelayMillis uint32
}

type brokerServiceSpecModel struct {
	Name           string
	BinaryPath     string
	Account        string
	Start          string
	SIDType        string
	FailureActions serviceFailureActions
}

func brokerServiceSpec(name, binaryPath string) brokerServiceSpecModel {
	return brokerServiceSpecModel{
		Name:       name,
		BinaryPath: filepath.Clean(binaryPath),
		Account:    localSystemAccount,
		Start:      serviceStartAutomatic,
		SIDType:    serviceSIDRestricted,
		FailureActions: serviceFailureActions{
			Restart:            true,
			ResetPeriodSeconds: 86400,
			RestartDelayMillis: 1000,
		},
	}
}

type brokerServiceRecord struct {
	Spec     brokerServiceSpecModel
	Identity string
	Owned    bool
	Running  bool
}

type serviceAPI interface {
	Lookup(name string) (brokerServiceRecord, error)
	Create(spec brokerServiceSpecModel) (brokerServiceRecord, error)
	Apply(spec brokerServiceSpecModel) error
	Stop(name string) error
	Delete(name string) error
}

// brokerDesiredState is the non-secret initialization request Setup may send
// to the LocalSystem service. Password generation, account mutation, DPAPI and
// unrestricted logon tokens stay entirely inside that service process.
type brokerDesiredState struct {
	InstallationID string
	OfflineAccount string
	OnlineAccount  string
	Service        brokerServiceSpecModel
}

type brokerIdentityHealth struct {
	InstallationID       string
	OfflineAccount       string
	OfflineSID           string
	OnlineAccount        string
	OnlineSID            string
	CredentialsProtected bool
}

// serviceInitializer is implemented by the authenticated service client in
// the broker phase. Keeping this seam secret-free prevents Setup from growing
// credential authority while that transport is not yet available.
type serviceInitializer interface {
	EnsureService(context.Context, brokerServiceSpecModel) error
	Initialize(context.Context, brokerDesiredState) (brokerIdentityHealth, error)
}

func desiredBrokerState(installationID, hostPath string) (brokerDesiredState, error) {
	names, err := deriveInstallationPrincipalNames(installationID)
	if err != nil {
		return brokerDesiredState{}, err
	}
	service := brokerServiceSpec(names.Service, hostPath)
	if err := service.validate(); err != nil {
		return brokerDesiredState{}, err
	}
	return brokerDesiredState{InstallationID: installationID, OfflineAccount: names.Offline, OnlineAccount: names.Online, Service: service}, nil
}

func initializeBrokerIdentities(ctx context.Context, initializer serviceInitializer, desired brokerDesiredState) (brokerIdentityHealth, error) {
	if err := desired.Service.validate(); err != nil || desired.InstallationID == "" || desired.OfflineAccount == "" || desired.OnlineAccount == "" || desired.OfflineAccount == desired.OnlineAccount {
		return brokerIdentityHealth{}, errors.New("sandbox: invalid Windows broker desired state")
	}
	if err := initializer.EnsureService(ctx, desired.Service); err != nil {
		return brokerIdentityHealth{}, err
	}
	health, err := initializer.Initialize(ctx, desired)
	if err != nil {
		return brokerIdentityHealth{}, err
	}
	if health.InstallationID != desired.InstallationID || health.OfflineAccount != desired.OfflineAccount ||
		health.OnlineAccount != desired.OnlineAccount || health.OfflineSID == "" || health.OnlineSID == "" ||
		health.OfflineSID == health.OnlineSID || !health.CredentialsProtected {
		return brokerIdentityHealth{}, errors.New("sandbox: Windows broker identity health mismatch")
	}
	return health, nil
}

type brokerIdentityRuntime struct {
	accounts  accountAPI
	protector credentialProtector
	store     protectedCredentialStore
	random    io.Reader
}

// provisionBrokerIdentityState runs only inside the LocalSystem service. It
// generates each password once, gives mutable copies to NetAPI and DPAPI, and
// wipes every copy before proceeding to the next account.
func provisionBrokerIdentityState(runtime brokerIdentityRuntime, desired brokerDesiredState, refresh bool) (brokerIdentityHealth, error) {
	if runtime.accounts == nil || runtime.protector == nil || runtime.store == nil || runtime.random == nil {
		return brokerIdentityHealth{}, errors.New("sandbox: incomplete Windows broker identity runtime")
	}
	health := brokerIdentityHealth{InstallationID: desired.InstallationID, OfflineAccount: desired.OfflineAccount, OnlineAccount: desired.OnlineAccount}
	offline, offlineCreated, err := provisionOneBrokerAccount(runtime, desired.OfflineAccount, "offline", refresh)
	if err != nil {
		return brokerIdentityHealth{}, err
	}
	health.OfflineSID = offline.SID
	online, _, err := provisionOneBrokerAccount(runtime, desired.OnlineAccount, "online", refresh)
	if err != nil {
		if offlineCreated {
			_ = removeSandboxAccount(runtime.accounts, offline.Name, offline.SID)
		}
		return brokerIdentityHealth{}, err
	}
	health.OnlineSID = online.SID
	health.CredentialsProtected = true
	return health, nil
}

func provisionOneBrokerAccount(runtime brokerIdentityRuntime, accountName, credentialName string, refresh bool) (sandboxAccountRecord, bool, error) {
	existing, lookupErr := runtime.accounts.Lookup(accountName)
	create := errors.Is(lookupErr, errAccountNotFound)
	if lookupErr != nil && !create {
		return sandboxAccountRecord{}, false, lookupErr
	}
	if !create && !refresh {
		record, err := reconcileSandboxAccount(runtime.accounts, accountName, nil, false)
		if err != nil {
			return sandboxAccountRecord{}, false, err
		}
		protection, err := runtime.store.InspectProtection(credentialName)
		if err != nil || !protection.valid() {
			return sandboxAccountRecord{}, false, errors.Join(errors.New("sandbox: existing Windows credential state is not protected"), err)
		}
		return record, false, nil
	}
	password, err := newAccountPassword(runtime.random, 32)
	if err != nil {
		return sandboxAccountRecord{}, false, err
	}
	accountPassword := append([]byte(nil), password...)
	record, err := reconcileSandboxAccount(runtime.accounts, accountName, accountPassword, refresh)
	if err != nil {
		zeroBytes(password)
		return sandboxAccountRecord{}, false, err
	}
	if err := sealCredential(runtime.protector, runtime.store, credentialName, password); err != nil {
		if create {
			_ = removeSandboxAccount(runtime.accounts, record.Name, record.SID)
		}
		return sandboxAccountRecord{}, false, err
	}
	_ = existing
	return record, create, nil
}

type brokerOwnedIdentity struct{ OfflineName, OfflineSID, OnlineName, OnlineSID, ServiceName, ServiceIdentity string }

type protectedBrokerCredentialSource struct {
	config      brokerRuntimeConfig
	store       protectedCredentialStore
	unprotector credentialUnprotector
}

func (source protectedBrokerCredentialSource) LoadCredential(kind brokerAccountKind) (string, []byte, error) {
	if source.store == nil || source.unprotector == nil {
		return "", nil, errors.New("sandbox: broker credential source is unavailable")
	}
	var account, record string
	switch kind {
	case brokerAccountOffline:
		account, record = source.config.OfflineAccount, "offline"
	case brokerAccountOnline:
		account, record = source.config.OnlineAccount, "online"
	default:
		return "", nil, errors.New("sandbox: invalid broker account kind")
	}
	if account == "" {
		return "", nil, errors.New("sandbox: broker account is not configured")
	}
	password, err := openCredential(source.store, source.unprotector, record)
	if err != nil {
		return "", nil, err
	}
	return account, password, nil
}

func removeBrokerIdentityState(accounts accountAPI, services serviceAPI, owned brokerOwnedIdentity) error {
	// Stop/delete the service before deleting identities whose credentials it
	// owns. Every delete remains bound to an exact manifest identity.
	var result error
	result = errors.Join(result, removeBrokerService(services, owned.ServiceName, owned.ServiceIdentity))
	result = errors.Join(result, removeSandboxAccount(accounts, owned.OfflineName, owned.OfflineSID))
	result = errors.Join(result, removeSandboxAccount(accounts, owned.OnlineName, owned.OnlineSID))
	return result
}

func ensureBrokerService(api serviceAPI, spec brokerServiceSpecModel) (brokerServiceRecord, error) {
	if err := spec.validate(); err != nil {
		return brokerServiceRecord{}, err
	}
	record, err := api.Lookup(spec.Name)
	if errors.Is(err, errServiceNotFound) {
		return api.Create(spec)
	}
	if err != nil {
		return brokerServiceRecord{}, err
	}
	if !record.Owned || record.Identity == "" || record.Spec.Name != spec.Name {
		return brokerServiceRecord{}, errServiceOwnershipMismatch
	}
	if err := api.Apply(spec); err != nil {
		return brokerServiceRecord{}, err
	}
	record.Spec = spec
	return record, nil
}

func (spec brokerServiceSpecModel) validate() error {
	if spec.Name == "" || spec.BinaryPath == "" || !filepath.IsAbs(spec.BinaryPath) ||
		spec.Account != localSystemAccount || spec.Start != serviceStartAutomatic ||
		spec.SIDType != serviceSIDRestricted || !spec.FailureActions.Restart ||
		spec.FailureActions.ResetPeriodSeconds == 0 || spec.FailureActions.RestartDelayMillis == 0 {
		return errors.New("sandbox: unsafe Windows broker service configuration")
	}
	return nil
}

func removeBrokerService(api serviceAPI, name, manifestIdentity string) error {
	if name == "" || manifestIdentity == "" {
		return errServiceOwnershipMismatch
	}
	record, err := api.Lookup(name)
	if errors.Is(err, errServiceNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if !record.Owned || record.Spec.Name != name || record.Identity != manifestIdentity {
		return errServiceOwnershipMismatch
	}
	if err := api.Stop(name); err != nil {
		return err
	}
	return api.Delete(name)
}

type scmFacade interface {
	Lookup(brokerServiceSpecModel) (brokerServiceRecord, error)
	Create(brokerServiceSpecModel) error
	Apply(brokerServiceSpecModel) error
	Stop(string) error
	Delete(string) error
}

// scmServiceAPI binds mutable SCM names to a manifest-pinned configuration
// identity. A same-name service with different configuration is never adopted.
type scmServiceAPI struct {
	scm           scmFacade
	ownedIdentity string
}

func (api scmServiceAPI) Lookup(name string) (brokerServiceRecord, error) {
	if api.scm == nil || api.ownedIdentity == "" {
		return brokerServiceRecord{}, errServiceOwnershipMismatch
	}
	record, err := api.scm.Lookup(brokerServiceSpecModel{Name: name})
	if err != nil {
		return brokerServiceRecord{}, err
	}
	record.Owned = record.Identity == api.ownedIdentity
	return record, nil
}

func (api scmServiceAPI) Create(spec brokerServiceSpecModel) (brokerServiceRecord, error) {
	identity := serviceSpecIdentity(spec)
	if identity != api.ownedIdentity {
		return brokerServiceRecord{}, errServiceOwnershipMismatch
	}
	if err := api.scm.Create(spec); err != nil {
		return brokerServiceRecord{}, err
	}
	record, err := api.scm.Lookup(spec)
	if err != nil || record.Identity != identity {
		return brokerServiceRecord{}, errors.Join(errors.New("sandbox: created Windows service failed read-back"), err)
	}
	record.Owned = true
	return record, nil
}

func (api scmServiceAPI) Apply(spec brokerServiceSpecModel) error {
	if serviceSpecIdentity(spec) != api.ownedIdentity {
		return errServiceOwnershipMismatch
	}
	if err := api.scm.Apply(spec); err != nil {
		return err
	}
	record, err := api.scm.Lookup(spec)
	if err != nil {
		return err
	}
	if record.Identity != api.ownedIdentity {
		return errors.New("sandbox: updated Windows service failed read-back")
	}
	return nil
}

func (api scmServiceAPI) Stop(name string) error   { return api.scm.Stop(name) }
func (api scmServiceAPI) Delete(name string) error { return api.scm.Delete(name) }

func serviceSpecIdentity(spec brokerServiceSpecModel) string {
	data := strings.Join([]string{spec.Name, filepath.Clean(spec.BinaryPath), spec.Account, spec.Start, spec.SIDType,
		fmtUint32(spec.FailureActions.ResetPeriodSeconds), fmtUint32(spec.FailureActions.RestartDelayMillis)}, "\x00")
	digest := sha256.Sum256([]byte(data))
	return hex.EncodeToString(digest[:])
}

func fmtUint32(value uint32) string {
	const digits = "0123456789"
	if value == 0 {
		return "0"
	}
	var buffer [10]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = digits[value%10]
		value /= 10
	}
	return string(buffer[index:])
}

type realSCMFacade struct{}

func (realSCMFacade) Lookup(want brokerServiceSpecModel) (brokerServiceRecord, error) {
	manager, err := mgr.Connect()
	if err != nil {
		return brokerServiceRecord{}, err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(want.Name)
	if errors.Is(err, win.ERROR_SERVICE_DOES_NOT_EXIST) {
		return brokerServiceRecord{}, errServiceNotFound
	}
	if err != nil {
		return brokerServiceRecord{}, err
	}
	defer service.Close()
	config, err := service.Config()
	if err != nil {
		return brokerServiceRecord{}, err
	}
	actions, resetPeriod, err := queryRecoveryActions(service.Handle)
	if err != nil {
		return brokerServiceRecord{}, err
	}
	observed := brokerServiceSpecModel{Name: want.Name, BinaryPath: trimServiceCommand(config.BinaryPathName), Account: config.ServiceStartName,
		Start: serviceStartFromSCM(config.StartType), SIDType: serviceSIDFromSCM(config.SidType)}
	if len(actions) == 1 && actions[0].Type == mgr.ServiceRestart {
		observed.FailureActions = serviceFailureActions{Restart: true, RestartDelayMillis: uint32(actions[0].Delay / time.Millisecond)}
		observed.FailureActions.ResetPeriodSeconds = resetPeriod
	}
	status, err := service.Query()
	if err != nil {
		return brokerServiceRecord{}, err
	}
	return brokerServiceRecord{Spec: observed, Identity: serviceSpecIdentity(observed), Running: status.State == svc.Running}, nil
}

func (realSCMFacade) Create(spec brokerServiceSpecModel) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.CreateService(spec.Name, spec.BinaryPath, scmConfig(spec), "--service")
	if err != nil {
		return err
	}
	defer service.Close()
	return service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Duration(spec.FailureActions.RestartDelayMillis) * time.Millisecond}}, spec.FailureActions.ResetPeriodSeconds)
}

func (realSCMFacade) Apply(spec brokerServiceSpecModel) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(spec.Name)
	if err != nil {
		return err
	}
	defer service.Close()
	if err := service.UpdateConfig(scmConfig(spec)); err != nil {
		return err
	}
	return service.SetRecoveryActions([]mgr.RecoveryAction{{Type: mgr.ServiceRestart, Delay: time.Duration(spec.FailureActions.RestartDelayMillis) * time.Millisecond}}, spec.FailureActions.ResetPeriodSeconds)
}

func (realSCMFacade) Stop(name string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if errors.Is(err, win.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	status, err := service.Query()
	if err != nil {
		return err
	}
	if status.State == svc.Stopped {
		return nil
	}
	_, err = service.Control(svc.Stop)
	return err
}

func (realSCMFacade) Delete(name string) error {
	manager, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer manager.Disconnect()
	service, err := manager.OpenService(name)
	if errors.Is(err, win.ERROR_SERVICE_DOES_NOT_EXIST) {
		return nil
	}
	if err != nil {
		return err
	}
	defer service.Close()
	return service.Delete()
}

func scmConfig(spec brokerServiceSpecModel) mgr.Config {
	return mgr.Config{StartType: mgr.StartAutomatic, ErrorControl: mgr.ErrorNormal, ServiceStartName: localSystemAccount,
		SidType: win.SERVICE_SID_TYPE_RESTRICTED, DisplayName: "Looprig Sandbox Broker"}
}

func trimServiceCommand(command string) string {
	command = strings.TrimSpace(command)
	command = strings.TrimSuffix(command, " --service")
	return strings.Trim(command, `"`)
}

func serviceStartFromSCM(value uint32) string {
	if value == mgr.StartAutomatic {
		return serviceStartAutomatic
	}
	return "invalid"
}
func serviceSIDFromSCM(value uint32) string {
	if value == win.SERVICE_SID_TYPE_RESTRICTED {
		return serviceSIDRestricted
	}
	return "invalid"
}

func queryRecoveryActions(handle win.Handle) ([]mgr.RecoveryAction, uint32, error) {
	var needed uint32
	err := win.QueryServiceConfig2(handle, win.SERVICE_CONFIG_FAILURE_ACTIONS, nil, 0, &needed)
	if !errors.Is(err, win.ERROR_INSUFFICIENT_BUFFER) || needed == 0 {
		return nil, 0, err
	}
	buffer := make([]byte, needed)
	if err := win.QueryServiceConfig2(handle, win.SERVICE_CONFIG_FAILURE_ACTIONS, &buffer[0], uint32(len(buffer)), &needed); err != nil {
		return nil, 0, err
	}
	config := (*win.SERVICE_FAILURE_ACTIONS)(unsafe.Pointer(&buffer[0]))
	result := make([]mgr.RecoveryAction, int(config.ActionsCount))
	if config.ActionsCount > 0 && config.Actions == nil {
		return nil, 0, errors.New("sandbox: invalid Windows service recovery configuration")
	}
	for index, action := range unsafe.Slice(config.Actions, int(config.ActionsCount)) {
		result[index] = mgr.RecoveryAction{Type: int(action.Type), Delay: time.Duration(action.Delay) * time.Millisecond}
	}
	return result, config.ResetPeriod, nil
}
