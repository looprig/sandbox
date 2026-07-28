//go:build windows

package windows

import (
	"errors"
	"io"
	"net"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestLoopbackGuardBinderBindsBothFamiliesAndRollsBack(t *testing.T) {
	factory := &fakeLoopbackSocketFactory{failAt: 2}
	_, err := (windowsLoopbackGuardBinder{sockets: factory}).Bind(9001)
	if err == nil {
		t.Fatal("partial dual-stack bind succeeded")
	}
	wantCalls := []string{"tcp4|127.0.0.1:9001", "tcp6|[::1]:9001"}
	if !reflect.DeepEqual(factory.calls, wantCalls) {
		t.Fatalf("listen calls = %v, want %v", factory.calls, wantCalls)
	}
	if len(factory.listeners) != 1 || !factory.listeners[0].isClosed() {
		t.Fatal("IPv4 listener was not rolled back after IPv6 failure")
	}
}

func TestDualStackBindingRejectsBeforeActivationAndDispatchesAfter(t *testing.T) {
	factory := &fakeLoopbackSocketFactory{}
	binding, err := (windowsLoopbackGuardBinder{sockets: factory}).Bind(9001)
	if err != nil {
		t.Fatal(err)
	}
	defer binding.Close()

	guardServer, guardClient := net.Pipe()
	factory.listeners[0].inject(guardServer)
	_ = guardClient.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1)
	if _, err := guardClient.Read(buffer); !errors.Is(err, io.EOF) {
		t.Fatalf("deny-only guard read = %v, want EOF", err)
	}
	_ = guardClient.Close()

	if err := binding.ActivateProxy(); err != nil {
		t.Fatal(err)
	}
	proxyServer, proxyClient := net.Pipe()
	factory.listeners[1].inject(proxyServer)
	accepted, err := binding.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer accepted.Close()
	defer proxyClient.Close()
	writeDone := make(chan error, 1)
	go func() { _, err := proxyClient.Write([]byte{'x'}); writeDone <- err }()
	if _, err := io.ReadFull(accepted, buffer); err != nil || buffer[0] != 'x' {
		t.Fatalf("activated proxy read = %q, %v", buffer, err)
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
}

type fakeLoopbackSocketFactory struct {
	calls     []string
	listeners []*fakeChannelListener
	failAt    int
}

func (f *fakeLoopbackSocketFactory) Listen(network, address string) (net.Listener, error) {
	f.calls = append(f.calls, network+"|"+address)
	if f.failAt == len(f.calls) {
		return nil, errors.New("injected listen failure")
	}
	listener := &fakeChannelListener{accepts: make(chan net.Conn, 4), closed: make(chan struct{}), addr: fakeAddr(address)}
	f.listeners = append(f.listeners, listener)
	return listener, nil
}

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

type fakeChannelListener struct {
	accepts chan net.Conn
	closed  chan struct{}
	addr    net.Addr
	once    sync.Once
}

func (l *fakeChannelListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.accepts:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}
func (l *fakeChannelListener) Close() error               { l.once.Do(func() { close(l.closed) }); return nil }
func (l *fakeChannelListener) Addr() net.Addr             { return l.addr }
func (l *fakeChannelListener) inject(connection net.Conn) { l.accepts <- connection }
func (l *fakeChannelListener) isClosed() bool {
	select {
	case <-l.closed:
		return true
	default:
		return false
	}
}
