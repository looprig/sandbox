//go:build windows

package windows

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

func TestReserveProxyPortsBindsAllAndKeepsUnusedAsGuards(t *testing.T) {
	binder := &fakePortBinder{}
	locker := &fakeInstallationLocker{}
	reservation, err := reserveProxyPorts("installation", []uint16{9002, 9001}, binder, locker, fakePortOwner{})
	if err != nil {
		t.Fatal(err)
	}
	defer reservation.Close()
	if got, want := binder.bound, []uint16{9001, 9002}; !reflect.DeepEqual(got, want) {
		t.Fatalf("bound ports = %v, want %v", got, want)
	}
	proxy, err := reservation.ClaimProxy(9002)
	if err != nil {
		t.Fatal(err)
	}
	if proxy.Port() != 9002 || !reservation.IsGuard(9001) || reservation.IsGuard(9002) {
		t.Fatal("reservation did not preserve deny-only guard role")
	}
	if _, err := reservation.ClaimProxy(9001); err == nil {
		t.Fatal("second proxy claim accepted")
	}
}

func TestReserveProxyPortsRollsBackPartialBindInReverseOrder(t *testing.T) {
	binder := &fakePortBinder{failPort: 9003}
	locker := &fakeInstallationLocker{}
	_, err := reserveProxyPorts("installation", []uint16{9001, 9002, 9003}, binder, locker, fakePortOwner{pid: 42, owned: true})
	var inUse *proxyPortInUseError
	if !errors.As(err, &inUse) || inUse.Port != 9003 || inUse.PID != 42 {
		t.Fatalf("error = %#v, want port 9003 PID 42", err)
	}
	if got, want := binder.closed, []uint16{9002, 9001}; !reflect.DeepEqual(got, want) {
		t.Fatalf("closed ports = %v, want %v", got, want)
	}
	if !locker.released {
		t.Fatal("installation lock was not released")
	}
}

func TestInspectProxyPortOwnersPreservesUnknownPID(t *testing.T) {
	owners := mappedPortOwner{owners: map[uint16]uint32{9001: 42, 9002: 0}}
	got, err := inspectProxyPortOwners([]uint16{9001, 9002, 9003}, owners)
	if err != nil {
		t.Fatal(err)
	}
	want := map[uint16]uint32{9001: 42, 9002: 0}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("owners = %v, want %v", got, want)
	}
}

func TestReserveProxyPortsSerializesConstructors(t *testing.T) {
	locker := newMemoryInstallationLocker()
	first, err := reserveProxyPorts("installation", []uint16{9001}, &fakePortBinder{}, locker, fakePortOwner{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reserveProxyPorts("installation", []uint16{9001}, &fakePortBinder{}, locker, fakePortOwner{}); !errors.Is(err, errInstallationAlreadyActive) {
		t.Fatalf("concurrent constructor error = %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := reserveProxyPorts("installation", []uint16{9001}, &fakePortBinder{}, locker, fakePortOwner{})
	if err != nil {
		t.Fatalf("constructor after release: %v", err)
	}
	_ = second.Close()
}

func TestReserveProxyPortsAllowsOnlyOneConcurrentConstructor(t *testing.T) {
	const constructors = 12
	locker := newMemoryInstallationLocker()
	start := make(chan struct{})
	results := make(chan struct {
		reservation *proxyPortReservation
		err         error
	}, constructors)
	for range constructors {
		go func() {
			<-start
			reservation, err := reserveProxyPorts("installation", []uint16{9001}, &fakePortBinder{}, locker, fakePortOwner{})
			results <- struct {
				reservation *proxyPortReservation
				err         error
			}{reservation, err}
		}()
	}
	close(start)
	var winner *proxyPortReservation
	for range constructors {
		result := <-results
		if result.err == nil {
			if winner != nil {
				t.Fatal("multiple concurrent constructors acquired the installation")
			}
			winner = result.reservation
			continue
		}
		if !errors.Is(result.err, errInstallationAlreadyActive) {
			t.Fatalf("losing constructor error = %v", result.err)
		}
	}
	if winner == nil {
		t.Fatal("no concurrent constructor acquired the installation")
	}
	_ = winner.Close()
}

func TestReserveProxyPortsRejectsInvalidInputBeforeLockOrBind(t *testing.T) {
	binder := &fakePortBinder{}
	locker := &fakeInstallationLocker{}
	if _, err := reserveProxyPorts("", []uint16{9001}, binder, locker, fakePortOwner{}); err == nil {
		t.Fatal("empty installation accepted")
	}
	if _, err := reserveProxyPorts("installation", []uint16{9001, 9001}, binder, locker, fakePortOwner{}); err == nil {
		t.Fatal("duplicate port accepted")
	}
	if len(binder.bound) != 0 || locker.acquired {
		t.Fatal("invalid input caused side effects")
	}
}

type fakePortBinding struct {
	port   uint16
	parent *fakePortBinder
	once   sync.Once
}

func (b *fakePortBinding) Port() uint16         { return b.port }
func (b *fakePortBinding) ActivateProxy() error { return nil }
func (b *fakePortBinding) Close() error {
	b.once.Do(func() { b.parent.closed = append(b.parent.closed, b.port) })
	return nil
}

type fakePortBinder struct {
	bound, closed []uint16
	failPort      uint16
}

func (b *fakePortBinder) Bind(port uint16) (proxyPortBinding, error) {
	if port == b.failPort {
		return nil, errors.New("injected bind failure")
	}
	b.bound = append(b.bound, port)
	return &fakePortBinding{port: port, parent: b}, nil
}

type fakePortOwner struct {
	pid   uint32
	owned bool
}

func (o fakePortOwner) OwnerPID(uint16) (uint32, bool, error) { return o.pid, o.owned, nil }

type mappedPortOwner struct{ owners map[uint16]uint32 }

func (o mappedPortOwner) OwnerPID(port uint16) (uint32, bool, error) {
	pid, ok := o.owners[port]
	return pid, ok, nil
}

type fakeInstallationLocker struct{ acquired, released bool }

func (l *fakeInstallationLocker) Acquire(string) (installationLock, error) {
	l.acquired = true
	return installationLockFunc(func() error { l.released = true; return nil }), nil
}

type memoryInstallationLocker struct {
	mu     sync.Mutex
	active map[string]bool
}

func newMemoryInstallationLocker() *memoryInstallationLocker {
	return &memoryInstallationLocker{active: make(map[string]bool)}
}

func (l *memoryInstallationLocker) Acquire(id string) (installationLock, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.active[id] {
		return nil, errInstallationAlreadyActive
	}
	l.active[id] = true
	return installationLockFunc(func() error {
		l.mu.Lock()
		defer l.mu.Unlock()
		delete(l.active, id)
		return nil
	}), nil
}
