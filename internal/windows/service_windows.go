//go:build windows

package windows

import (
	"context"
	"errors"
	"path/filepath"
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
