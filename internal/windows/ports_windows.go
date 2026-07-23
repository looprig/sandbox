//go:build windows

package windows

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
)

var errInstallationAlreadyActive = errors.New("sandbox: Windows installation already has an active host")

type proxyPortInUseError struct {
	Port uint16
	PID  uint32
	Err  error
}

func (e *proxyPortInUseError) Error() string {
	if e.PID != 0 {
		return fmt.Sprintf("sandbox: proxy port %d is owned by process %d", e.Port, e.PID)
	}
	return fmt.Sprintf("sandbox: proxy port %d is already owned", e.Port)
}

func (e *proxyPortInUseError) Unwrap() error { return e.Err }

// A binder returns endpoints in deny-only guard mode. ActivateProxy performs a
// one-way transition for exactly one endpoint; all other endpoints continue to
// accept-and-reject traffic for the reservation lifetime.
type proxyPortBinding interface {
	Port() uint16
	ActivateProxy() error
	Close() error
}

type proxyPortBinder interface {
	// Bind reserves both IPv4 and IPv6 loopback for port with exclusive Windows
	// socket semantics and starts the returned composite endpoint as a guard.
	Bind(uint16) (proxyPortBinding, error)
}

type proxyPortOwner interface {
	// OwnerPID distinguishes an unowned port from an owned port whose PID cannot
	// be reported safely. In the latter case it returns owned=true and pid=0.
	OwnerPID(uint16) (pid uint32, owned bool, err error)
}

type installationLock interface{ Close() error }

type installationLocker interface {
	Acquire(installationID string) (installationLock, error)
}

type proxyPortReservation struct {
	mu       sync.Mutex
	lock     installationLock
	bindings []proxyPortBinding
	byPort   map[uint16]proxyPortBinding
	proxy    uint16
	closed   bool
}

func reserveProxyPorts(installationID string, ports []uint16, binder proxyPortBinder, locker installationLocker, owners proxyPortOwner) (*proxyPortReservation, error) {
	if strings.TrimSpace(installationID) == "" {
		return nil, errors.New("sandbox: Windows installation identity is required")
	}
	if err := validateProxyPorts(ports); err != nil {
		return nil, err
	}
	if binder == nil || locker == nil || owners == nil {
		return nil, errors.New("sandbox: incomplete Windows port reservation mechanisms")
	}
	ordered := append([]uint16(nil), ports...)
	slices.Sort(ordered)
	lock, err := locker.Acquire(installationID)
	if err != nil {
		return nil, err
	}
	reservation := &proxyPortReservation{lock: lock, byPort: make(map[uint16]proxyPortBinding, len(ordered))}
	for _, port := range ordered {
		binding, bindErr := binder.Bind(port)
		if bindErr != nil {
			rollbackErr := reservation.Close()
			pid, owned, ownerErr := owners.OwnerPID(port)
			if owned {
				return nil, errors.Join(&proxyPortInUseError{Port: port, PID: pid, Err: bindErr}, ownerErr, rollbackErr)
			}
			return nil, errors.Join(fmt.Errorf("reserve Windows proxy port %d: %w", port, bindErr), ownerErr, rollbackErr)
		}
		if binding == nil || binding.Port() != port {
			rollbackErr := reservation.Close()
			return nil, errors.Join(errors.New("sandbox: Windows port binder returned the wrong endpoint"), rollbackErr)
		}
		reservation.bindings = append(reservation.bindings, binding)
		reservation.byPort[port] = binding
	}
	return reservation, nil
}

func inspectProxyPortOwners(ports []uint16, owners proxyPortOwner) (map[uint16]uint32, error) {
	if err := validateProxyPorts(ports); err != nil {
		return nil, err
	}
	if owners == nil {
		return nil, errors.New("sandbox: Windows port owner inspector is unavailable")
	}
	result := make(map[uint16]uint32)
	for _, port := range ports {
		pid, owned, err := owners.OwnerPID(port)
		if err != nil {
			return nil, fmt.Errorf("inspect Windows proxy port %d owner: %w", port, err)
		}
		if owned {
			result[port] = pid
		}
	}
	return result, nil
}

func (r *proxyPortReservation) ClaimProxy(port uint16) (proxyPortBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil, errors.New("sandbox: Windows port reservation is closed")
	}
	if r.proxy != 0 {
		return nil, errors.New("sandbox: Windows proxy endpoint is already selected")
	}
	binding, ok := r.byPort[port]
	if !ok {
		return nil, errors.New("sandbox: proxy port is not reserved")
	}
	if err := binding.ActivateProxy(); err != nil {
		return nil, fmt.Errorf("activate Windows proxy port %d: %w", port, err)
	}
	r.proxy = port
	return binding, nil
}

func (r *proxyPortReservation) IsGuard(port uint16) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, reserved := r.byPort[port]
	return !r.closed && reserved && r.proxy != port
}

func (r *proxyPortReservation) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	var result error
	for i := len(r.bindings) - 1; i >= 0; i-- {
		result = errors.Join(result, r.bindings[i].Close())
	}
	if r.lock != nil {
		result = errors.Join(result, r.lock.Close())
	}
	return result
}

type installationLockFunc func() error

func (f installationLockFunc) Close() error { return f() }
