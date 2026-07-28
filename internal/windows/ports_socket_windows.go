//go:build windows

package windows

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"syscall"

	win "golang.org/x/sys/windows"
)

const windowsSOExclusiveAddrUse = 0x4

type loopbackSocketFactory interface {
	Listen(network, address string) (net.Listener, error)
}

type windowsLoopbackGuardBinder struct{ sockets loopbackSocketFactory }

func (b windowsLoopbackGuardBinder) Bind(port uint16) (proxyPortBinding, error) {
	if b.sockets == nil || port == 0 {
		return nil, errors.New("sandbox: invalid Windows loopback binder")
	}
	addresses := []struct{ network, address string }{
		{"tcp4", fmt.Sprintf("127.0.0.1:%d", port)},
		{"tcp6", fmt.Sprintf("[::1]:%d", port)},
	}
	listeners := make([]net.Listener, 0, len(addresses))
	for _, endpoint := range addresses {
		listener, err := b.sockets.Listen(endpoint.network, endpoint.address)
		if err != nil {
			var rollback error
			for index := len(listeners) - 1; index >= 0; index-- {
				rollback = errors.Join(rollback, listeners[index].Close())
			}
			return nil, errors.Join(fmt.Errorf("bind exclusive Windows %s loopback port %d: %w", endpoint.network, port, err), rollback)
		}
		listeners = append(listeners, listener)
	}
	binding := &dualStackGuardBinding{
		port: port, listeners: listeners, accepted: make(chan guardedAccept, 16), done: make(chan struct{}),
	}
	for _, listener := range listeners {
		binding.wait.Add(1)
		go binding.acceptAndDispatch(listener)
	}
	return binding, nil
}

type exclusiveLoopbackSocketFactory struct{}

func (exclusiveLoopbackSocketFactory) Listen(network, address string) (net.Listener, error) {
	config := net.ListenConfig{Control: func(controlNetwork, _ string, raw syscall.RawConn) error {
		var controlErr error
		err := raw.Control(func(fd uintptr) {
			controlErr = win.SetsockoptInt(win.Handle(fd), win.SOL_SOCKET, windowsSOExclusiveAddrUse, 1)
			if controlErr == nil && controlNetwork == "tcp6" {
				controlErr = win.SetsockoptInt(win.Handle(fd), win.IPPROTO_IPV6, win.IPV6_V6ONLY, 1)
			}
		})
		return errors.Join(err, controlErr)
	}}
	return config.Listen(context.Background(), network, address)
}

type guardedAccept struct {
	connection net.Conn
	err        error
}

type dualStackGuardBinding struct {
	port      uint16
	listeners []net.Listener
	accepted  chan guardedAccept
	done      chan struct{}
	active    atomic.Bool
	closeOnce sync.Once
	wait      sync.WaitGroup
	closeErr  error
}

func (b *dualStackGuardBinding) Port() uint16 { return b.port }

func (b *dualStackGuardBinding) Addr() net.Addr {
	if len(b.listeners) == 0 {
		return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(b.port)}
	}
	return b.listeners[0].Addr()
}

func (b *dualStackGuardBinding) ActivateProxy() error {
	select {
	case <-b.done:
		return errors.New("sandbox: Windows loopback guard is closed")
	default:
	}
	if !b.active.CompareAndSwap(false, true) {
		return errors.New("sandbox: Windows loopback guard is already active")
	}
	return nil
}

func (b *dualStackGuardBinding) Accept() (net.Conn, error) {
	if !b.active.Load() {
		return nil, errors.New("sandbox: Windows loopback endpoint remains deny-only")
	}
	select {
	case <-b.done:
		return nil, net.ErrClosed
	case accepted := <-b.accepted:
		return accepted.connection, accepted.err
	}
}

func (b *dualStackGuardBinding) Close() error {
	b.closeOnce.Do(func() {
		close(b.done)
		for index := len(b.listeners) - 1; index >= 0; index-- {
			b.closeErr = errors.Join(b.closeErr, b.listeners[index].Close())
		}
		b.wait.Wait()
		for {
			select {
			case accepted := <-b.accepted:
				if accepted.connection != nil {
					b.closeErr = errors.Join(b.closeErr, accepted.connection.Close())
				}
			default:
				return
			}
		}
	})
	return b.closeErr
}

func (b *dualStackGuardBinding) acceptAndDispatch(listener net.Listener) {
	defer b.wait.Done()
	for {
		connection, err := listener.Accept()
		if err != nil {
			select {
			case <-b.done:
				return
			default:
			}
			if b.active.Load() {
				select {
				case b.accepted <- guardedAccept{err: err}:
				case <-b.done:
				}
			}
			return
		}
		if !b.active.Load() {
			_ = connection.Close()
			continue
		}
		select {
		case b.accepted <- guardedAccept{connection: connection}:
		case <-b.done:
			_ = connection.Close()
			return
		}
	}
}
