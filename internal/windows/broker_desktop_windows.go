//go:build windows

package windows

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	win "golang.org/x/sys/windows"
)

const brokerDesktopEntropyBytes = 32

var (
	errInvalidBrokerDesktopTrustees = errors.New("windows sandbox: invalid broker desktop trustees")
	brokerDesktopCreationMu         sync.Mutex
)

type brokerPrivateDesktopCreator interface {
	Create(privateDesktopSpec) (*privateDesktop, error)
}

type localSystemRequirement func() error

type localSystemBrokerDesktopManager struct {
	requireLocalSystem localSystemRequirement
	entropy            io.Reader
	desktops           brokerPrivateDesktopCreator
	offlineSID         string
	onlineSID          string
}

func newLocalSystemBrokerDesktopManager(
	requireLocalSystem localSystemRequirement,
	entropy io.Reader,
	desktops brokerPrivateDesktopCreator,
	offlineSID, onlineSID string,
) (*localSystemBrokerDesktopManager, error) {
	if requireLocalSystem == nil || desktops == nil {
		return nil, errors.New("windows sandbox: incomplete broker desktop dependencies")
	}
	if err := validateBrokerDesktopAccountSID(offlineSID); err != nil {
		return nil, err
	}
	if err := validateBrokerDesktopAccountSID(onlineSID); err != nil {
		return nil, err
	}
	if offlineSID == onlineSID {
		return nil, errInvalidBrokerDesktopTrustees
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return &localSystemBrokerDesktopManager{
		requireLocalSystem: requireLocalSystem,
		entropy:            entropy,
		desktops:           desktops,
		offlineSID:         offlineSID,
		onlineSID:          onlineSID,
	}, nil
}

func newWin32BrokerDesktopManager(config brokerRuntimeConfig) (brokerDesktopManager, error) {
	factory, err := newPrivateDesktopFactory(&nativePrivateDesktopAPI{})
	if err != nil {
		return nil, err
	}
	return newLocalSystemBrokerDesktopManager(
		requireLocalSystemBroker, rand.Reader, factory, config.OfflineSID, config.OnlineSID,
	)
}

func (manager *localSystemBrokerDesktopManager) Create(
	context brokerDesktopContext,
) (brokerManagedDesktop, error) {
	if manager == nil || manager.requireLocalSystem == nil || manager.entropy == nil || manager.desktops == nil {
		return brokerManagedDesktop{}, errors.New("windows sandbox: broker desktop manager is unavailable")
	}
	if err := manager.requireLocalSystem(); err != nil {
		return brokerManagedDesktop{}, fmt.Errorf("windows sandbox: create broker desktop: %w", err)
	}
	if context.LeaseID == (ACLLeaseID{}) || context.Binding.Nonce == ([brokerNonceSize]byte{}) ||
		context.Binding.PID == 0 || context.Binding.CreationTime == 0 || context.Binding.Process == nil ||
		context.Installation.kind != sidKindInstallation || !context.Installation.isModuleTrustee() ||
		!context.Restricting.isRestrictedTierTrustee() || context.Restricting == context.Installation {
		return brokerManagedDesktop{}, errInvalidBrokerDesktopTrustees
	}
	accountSID := manager.offlineSID
	switch context.Account {
	case brokerAccountOffline:
	case brokerAccountOnline:
		accountSID = manager.onlineSID
	default:
		return brokerManagedDesktop{}, errInvalidBrokerDesktopTrustees
	}
	descriptor, err := brokerDesktopSecurityDescriptor(accountSID, context.Installation)
	if err != nil {
		return brokerManagedDesktop{}, err
	}

	// Name generation is part of the creation transaction: injected readers
	// need not be concurrency-safe, and no second creation may interleave the
	// process window-station switch performed by the native primitive.
	brokerDesktopCreationMu.Lock()
	defer brokerDesktopCreationMu.Unlock()
	var nonce [brokerDesktopEntropyBytes]byte
	if _, err := io.ReadFull(manager.entropy, nonce[:]); err != nil {
		return brokerManagedDesktop{}, fmt.Errorf("windows sandbox: generate private desktop name: %w", err)
	}
	suffix := hex.EncodeToString(nonce[:])
	spec := privateDesktopSpec{
		WindowStation:      "looprig-broker-" + suffix,
		Desktop:            "desktop-" + suffix,
		SecurityDescriptor: descriptor,
	}

	// Creating a desktop temporarily changes the process window station. Keep
	// the whole station/desktop transaction serialized, including verification,
	// so no other broker construction can observe or interleave that state.
	desktop, err := manager.desktops.Create(spec)
	if err != nil {
		return brokerManagedDesktop{}, err
	}
	if desktop == nil {
		return brokerManagedDesktop{}, errors.New("windows sandbox: private desktop creator returned no object")
	}
	retained := &retainedBrokerDesktop{desktop: desktop}
	return brokerManagedDesktop{Name: desktop.Name, close: retained.Close}, nil
}

func brokerDesktopSecurityDescriptor(accountSIDText string, installationSID SID) (*win.SECURITY_DESCRIPTOR, error) {
	if err := validateBrokerDesktopAccountSID(accountSIDText); err != nil {
		return nil, err
	}
	accountSID, err := win.StringToSid(accountSIDText)
	if installationSID.kind != sidKindInstallation || !installationSID.isModuleTrustee() {
		return nil, errInvalidBrokerDesktopTrustees
	}
	restrictingSID, err := win.StringToSid(installationSID.String())
	if err != nil || restrictingSID == nil || !restrictingSID.IsValid() ||
		win.EqualSid(accountSID, restrictingSID) {
		return nil, errors.Join(errInvalidBrokerDesktopTrustees, err)
	}

	// A full restricted-token access check requires both the normal account SID
	// and a restricting SID to allow the requested access. SYSTEM is the exact
	// owner and the only service principal. In particular, neither the
	// installation owner nor BUILTIN\Administrators is admitted.
	sddl := fmt.Sprintf(
		"O:SYD:P(A;;GA;;;SY)(A;;GA;;;%s)(A;;GA;;;%s)",
		accountSID.String(),
		restrictingSID.String(),
	)
	descriptor, err := win.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("windows sandbox: construct broker desktop descriptor: %w", err)
	}
	if err := validateProtectedDesktopDescriptor(descriptor); err != nil {
		return nil, err
	}
	return descriptor, nil
}

func validateBrokerDesktopAccountSID(accountSIDText string) error {
	accountSID, err := win.StringToSid(accountSIDText)
	if err != nil || accountSID == nil || !accountSID.IsValid() ||
		accountSID.IsWellKnown(win.WinLocalSystemSid) ||
		accountSID.IsWellKnown(win.WinBuiltinAdministratorsSid) {
		return errors.Join(errInvalidBrokerDesktopTrustees, err)
	}
	return nil
}

type retainedBrokerDesktop struct {
	mu       sync.Mutex
	desktop  *privateDesktop
	closeErr error
	closed   bool
}

func (desktop *retainedBrokerDesktop) Close() error {
	if desktop == nil {
		return nil
	}
	desktop.mu.Lock()
	defer desktop.mu.Unlock()
	if desktop.closed {
		return desktop.closeErr
	}
	desktop.closed = true
	desktop.closeErr = desktop.desktop.Close()
	desktop.desktop = nil
	return desktop.closeErr
}
