package sandbox

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

func TestProxyAuthenticationExactTargetAndPrivateDenial(t *testing.T) {
	origin := newHTTPOrigin(t)
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	route, _ := NewDirectEgressRoute()
	var dials atomic.Int32
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.10")}, nil }
	route.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
	}
	proxy := newTestProxy(t, route)
	credential, err := proxy.Authorize("exec-1", []NetworkTarget{mustTarget(t, "tcp:example.test:"+port)})
	if err != nil {
		t.Fatal(err)
	}

	client := proxyClient(t, proxy.URL("exec-1", credential))
	response, err := client.Get("http://example.test:" + port + "/ok")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "origin:/ok" || dials.Load() != 1 {
		t.Fatalf("allowed request = status %d body %q dials %d", response.StatusCode, body, dials.Load())
	}

	response, err = client.Get("http://other.test:" + port + "/denied")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || dials.Load() != 1 {
		t.Fatalf("different target = status %d dials %d", response.StatusCode, dials.Load())
	}
	if denial := proxy.Denial("exec-1"); !errors.Is(denial, ErrNetworkTargetDenied) {
		t.Fatalf("denial = %v, want ErrNetworkTargetDenied", denial)
	}

	wrong := proxyClient(t, proxy.URL("exec-1", "wrong"))
	response, err = wrong.Get("http://example.test:" + port + "/wrong-auth")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired || dials.Load() != 1 {
		t.Fatalf("wrong auth = status %d dials %d", response.StatusCode, dials.Load())
	}
	wrongExecution := proxyClient(t, proxy.URL("exec-other", credential))
	response, err = wrongExecution.Get("http://example.test:" + port + "/wrong-execution")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired || dials.Load() != 1 {
		t.Fatalf("wrong execution = status %d dials %d", response.StatusCode, dials.Load())
	}
	portNumber, _ := strconv.Atoi(port)
	response, err = client.Get(fmt.Sprintf("http://example.test:%d/wrong-port", portNumber+1))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusForbidden || dials.Load() != 1 {
		t.Fatalf("wrong port = status %d dials %d", response.StatusCode, dials.Load())
	}

	privateRoute, _ := NewDirectEgressRoute()
	privateRoute.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("169.254.169.254")}, nil }
	privateRoute.dial = func(context.Context, string, string) (net.Conn, error) {
		t.Fatal("private address reached dial")
		return nil, nil
	}
	privateProxy := newTestProxy(t, privateRoute)
	privateCredential, _ := privateProxy.Authorize("exec-private", []NetworkTarget{mustTarget(t, "tcp:metadata.test:80")})
	response, err = proxyClient(t, privateProxy.URL("exec-private", privateCredential)).Get("http://metadata.test/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("private target status = %d, want 502", response.StatusCode)
	}
	if denial := privateProxy.Denial("exec-private"); !errors.Is(denial, ErrNetworkTargetDenied) {
		t.Fatalf("private target denial = %v, want ErrNetworkTargetDenied", denial)
	}
}

func TestPublicDestinationRejectsSpecialUsePrefixes(t *testing.T) {
	for _, prefix := range deniedDestinationPrefixes {
		for _, address := range []netip.Addr{prefix.Addr(), lastPrefixAddress(prefix)} {
			raw := address.String()
			t.Run("table-boundary/"+prefix.String()+"/"+raw, func(t *testing.T) {
				if publicDestination(net.IP(address.AsSlice())) {
					t.Fatalf("publicDestination(%s) = true at boundary of denied %s", raw, prefix)
				}
			})
		}
	}

	denied := []struct {
		name string
		ips  []string
	}{
		{"IPv4 this network", []string{"0.0.0.0", "0.255.255.255"}},
		{"IPv4 private 10/8", []string{"10.0.0.0", "10.255.255.255"}},
		{"IPv4 shared CGNAT", []string{"100.64.0.0", "100.100.100.200", "100.127.255.255"}},
		{"IPv4 loopback", []string{"127.0.0.0", "127.255.255.255"}},
		{"IPv4 link local and metadata", []string{"169.254.0.0", "169.254.169.254", "169.254.255.255"}},
		{"IPv4 private 172.16/12", []string{"172.16.0.0", "172.31.255.255"}},
		{"IPv4 protocol assignments", []string{"192.0.0.0", "192.0.0.170", "192.0.0.255"}},
		{"IPv4 documentation TEST-NET-1", []string{"192.0.2.0", "192.0.2.255"}},
		{"IPv4 AS112", []string{"192.31.196.0", "192.31.196.255", "192.175.48.0", "192.175.48.255"}},
		{"IPv4 AMT", []string{"192.52.193.0", "192.52.193.255"}},
		{"IPv4 deprecated 6to4 relay", []string{"192.88.99.0", "192.88.99.255"}},
		{"IPv4 private 192.168/16", []string{"192.168.0.0", "192.168.255.255"}},
		{"IPv4 benchmarking", []string{"198.18.0.0", "198.19.255.255"}},
		{"IPv4 documentation TEST-NET-2", []string{"198.51.100.0", "198.51.100.255"}},
		{"IPv4 documentation TEST-NET-3", []string{"203.0.113.0", "203.0.113.255"}},
		{"IPv4 multicast", []string{"224.0.0.0", "239.255.255.255"}},
		{"IPv4 reserved", []string{"240.0.0.0", "255.255.255.255"}},
		{"IPv6 unspecified and compatible", []string{"::", "::192.0.2.1"}},
		{"IPv6 loopback", []string{"::1"}},
		{"IPv6 NAT64 well-known", []string{"64:ff9b::", "64:ff9b::ffff:ffff"}},
		{"IPv6 NAT64 local-use", []string{"64:ff9b:1::", "64:ff9b:1:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 discard-only", []string{"100::", "100::ffff:ffff:ffff:ffff"}},
		{"IPv6 IETF protocol assignments", []string{"2001::", "2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 Teredo", []string{"2001::", "2001:0:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 benchmarking", []string{"2001:2::", "2001:2:0:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 ORCHID", []string{"2001:10::", "2001:2f:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 documentation", []string{"2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 6to4", []string{"2002::", "2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 AS112", []string{"2620:4f:8000::", "2620:4f:8000:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 documentation 3fff", []string{"3fff::", "3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 segment-routing SIDs", []string{"5f00::", "5f00:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 unique-local", []string{"fc00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 link-local", []string{"fe80::", "febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 deprecated site-local", []string{"fec0::", "feff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv6 multicast", []string{"ff00::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"}},
		{"IPv4-mapped normalization", []string{"::ffff:10.0.0.1", "::ffff:100.100.100.200", "::ffff:203.0.113.1"}},
	}
	for _, family := range denied {
		for _, raw := range family.ips {
			t.Run(family.name+"/"+raw, func(t *testing.T) {
				if publicDestination(net.ParseIP(raw)) {
					t.Fatalf("publicDestination(%s) = true, want false", raw)
				}
			})
		}
	}

	for _, raw := range []string{"1.1.1.1", "8.8.8.8", "2001:4860:4860::8888", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		t.Run("public/"+raw, func(t *testing.T) {
			if !publicDestination(net.ParseIP(raw)) {
				t.Fatalf("publicDestination(%s) = false, want true", raw)
			}
		})
	}
}

func lastPrefixAddress(prefix netip.Prefix) netip.Addr {
	bytes := prefix.Masked().Addr().AsSlice()
	for bit := prefix.Bits(); bit < len(bytes)*8; bit++ {
		bytes[bit/8] |= byte(1 << (7 - bit%8))
	}
	address, _ := netip.AddrFromSlice(bytes)
	return address
}

func TestDirectRouteRefusesSpecialUseBeforeDial(t *testing.T) {
	route, err := NewDirectEgressRoute()
	if err != nil {
		t.Fatal(err)
	}
	if !route.AddressGuarantee() {
		t.Fatal("direct route does not claim its address guarantee")
	}
	route.lookup = func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("100.100.100.200")}, nil
	}
	var dials atomic.Int32
	route.dial = func(context.Context, string, string) (net.Conn, error) {
		dials.Add(1)
		return nil, errors.New("unexpected dial")
	}
	if _, err := route.dialTarget(context.Background(), mustTarget(t, "tcp:metadata.example:80")); !errors.Is(err, errNetworkAddressDenied) {
		t.Fatalf("dialTarget error = %v, want errNetworkAddressDenied", err)
	}
	if got := dials.Load(); got != 0 {
		t.Fatalf("special-use target reached dial %d times", got)
	}
}

func TestProxyCONNECTIsByteTunnelWithoutTLSTermination(t *testing.T) {
	echo := newEchoServer(t)
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	route, _ := NewDirectEgressRoute()
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.8")}, nil }
	route.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, echo.Addr().String())
	}
	proxy := newTestProxy(t, route)
	credential, _ := proxy.Authorize("exec-connect", []NetworkTarget{mustTarget(t, "tcp:secure.test:"+port)})

	conn, err := net.Dial("tcp", proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("exec-connect:" + credential))
	_, _ = fmt.Fprintf(conn, "CONNECT secure.test:%s HTTP/1.1\r\nHost: secure.test:%s\r\nProxy-Authorization: Basic %s\r\n\r\n", port, port, auth)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", response.StatusCode)
	}
	payload := []byte{0x16, 0x03, 0x03, 0, 4, 1, 2, 3, 4}
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(reader, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(payload) {
		t.Fatalf("tunnel changed bytes: %x != %x", got, payload)
	}
}

func TestProxyCloseTerminatesActiveTunnel(t *testing.T) {
	echo := newEchoServer(t)
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	route, _ := NewDirectEgressRoute()
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.9")}, nil }
	route.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, echo.Addr().String())
	}
	proxy, err := newEgressProxy(route)
	if err != nil {
		t.Fatal(err)
	}
	credential, _ := proxy.Authorize("exec-close", []NetworkTarget{mustTarget(t, "tcp:close.test:"+port)})
	conn, err := net.Dial("tcp", proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte("exec-close:" + credential))
	_, _ = fmt.Fprintf(conn, "CONNECT close.test:%s HTTP/1.1\r\nHost: close.test:%s\r\nProxy-Authorization: Basic %s\r\n\r\n", port, port, auth)
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT = %#v, %v", response, err)
	}
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := conn.Write([]byte("after-close")); err == nil {
		one := make([]byte, 1)
		if _, err := conn.Read(one); err == nil {
			t.Fatal("active tunnel survived proxy Close")
		}
	}
	_ = conn.Close()
}

func TestProxyReleaseTerminatesOnlyMatchingCONNECTTunnel(t *testing.T) {
	echo := newEchoServer(t)
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	route, _ := NewDirectEgressRoute()
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.10")}, nil }
	route.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, echo.Addr().String())
	}
	proxy := newTestProxy(t, route)
	target := mustTarget(t, "tcp:release-connect.test:"+port)
	credentialA, _ := proxy.Authorize("exec-a", []NetworkTarget{target})
	credentialB, _ := proxy.Authorize("exec-b", []NetworkTarget{target})
	connA, readerA := openProxyTunnel(t, proxy, "exec-a", credentialA, "release-connect.test", port)
	defer connA.Close()
	connB, readerB := openProxyTunnel(t, proxy, "exec-b", credentialB, "release-connect.test", port)
	defer connB.Close()

	proxy.Release("exec-a")
	_ = connA.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := connA.Write([]byte("revoked")); err == nil {
		one := make([]byte, 1)
		if _, err := readerA.Read(one); err == nil {
			t.Fatal("released execution's CONNECT tunnel remained active")
		}
	}

	_ = connB.SetDeadline(time.Now().Add(time.Second))
	payload := []byte("still-authorized")
	if _, err := connB.Write(payload); err != nil {
		t.Fatalf("unrelated execution tunnel write: %v", err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(readerB, got); err != nil {
		t.Fatalf("unrelated execution tunnel read: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("unrelated tunnel payload = %q, want %q", got, payload)
	}
}

func TestProxyReleaseWinsCONNECTAuthorizationRegisterRace(t *testing.T) {
	echo := newEchoServer(t)
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	route, _ := NewDirectEgressRoute()
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.11")}, nil }
	route.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, echo.Addr().String())
	}
	proxy := newTestProxy(t, route)
	reached := make(chan struct{})
	resume := make(chan struct{})
	proxy.beforeTunnelRegister = func() {
		close(reached)
		<-resume
	}
	credential, _ := proxy.Authorize("exec-register-race", []NetworkTarget{mustTarget(t, "tcp:register-race.test:"+port)})
	connection, reader := openProxyTunnel(t, proxy, "exec-register-race", credential, "register-race.test", port)
	defer connection.Close()
	<-reached
	proxy.Release("exec-register-race")
	close(resume)
	_ = connection.SetDeadline(time.Now().Add(time.Second))
	if _, err := connection.Write([]byte("revoked")); err == nil {
		one := make([]byte, 1)
		if _, err := reader.Read(one); err == nil {
			t.Fatal("CONNECT registered after Release and survived revocation")
		}
	}
}

func TestProxyIgnoresNOProxyAndCleansUp(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	origin := newHTTPOrigin(t)
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	route, _ := NewDirectEgressRoute()
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.12")}, nil }
	route.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, origin.Listener.Addr().String())
	}
	proxy := newTestProxy(t, route)
	credential, _ := proxy.Authorize("exec-no-proxy", []NetworkTarget{mustTarget(t, "tcp:no-proxy.test:"+port)})
	response, err := proxyClient(t, proxy.URL("exec-no-proxy", credential)).Get("http://no-proxy.test:" + port + "/proxied")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.Header.Get("X-Through-Proxy") != "yes" {
		t.Fatal("NO_PROXY bypassed the enforcement proxy")
	}
	addr := proxy.Addr()
	if err := proxy.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr); err == nil {
		_ = conn.Close()
		t.Fatal("proxy still accepted connections after Close")
	}
}

func TestProxyRequestCancellation(t *testing.T) {
	route, _ := NewDirectEgressRoute()
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.13")}, nil }
	started := make(chan struct{})
	route.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	proxy := newTestProxy(t, route)
	credential, _ := proxy.Authorize("exec-cancel", []NetworkTarget{mustTarget(t, "tcp:cancel.test:80")})
	request, _ := http.NewRequest(http.MethodGet, "http://cancel.test/", nil)
	ctx, cancel := context.WithCancel(request.Context())
	request = request.WithContext(ctx)
	done := make(chan error, 1)
	go func() {
		response, err := proxyClient(t, proxy.URL("exec-cancel", credential)).Do(request)
		if response != nil {
			_ = response.Body.Close()
		}
		done <- err
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled proxy request error = %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled proxy request did not terminate")
	}
}

func TestUpstreamCONNECTHandshakeCancellationClosesBlockedConnection(t *testing.T) {
	for _, test := range []struct {
		name string
		peer func(net.Conn, chan<- struct{})
	}{
		{
			name: "request write",
			peer: func(connection net.Conn, ready chan<- struct{}) {
				close(ready)
				_, _ = io.Copy(io.Discard, connection)
			},
		},
		{
			name: "silent response",
			peer: func(connection net.Conn, ready chan<- struct{}) {
				request, err := http.ReadRequest(bufio.NewReader(connection))
				if err == nil {
					_ = request.Body.Close()
				}
				close(ready)
				_, _ = io.Copy(io.Discard, connection)
			},
		},
		{
			name: "partial response",
			peer: func(connection net.Conn, ready chan<- struct{}) {
				request, err := http.ReadRequest(bufio.NewReader(connection))
				if err == nil {
					_ = request.Body.Close()
				}
				_, _ = io.WriteString(connection, "HTTP/1.1 200")
				close(ready)
				_, _ = io.Copy(io.Discard, connection)
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, peer := net.Pipe()
			defer peer.Close()
			route, err := NewUpstreamEgressRoute("http://proxy.example:8080", false)
			if err != nil {
				t.Fatal(err)
			}
			route.dial = func(context.Context, string, string) (net.Conn, error) {
				return client, nil
			}
			proxy := &egressProxy{route: route}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ready := make(chan struct{})
			peerDone := make(chan struct{})
			go func() {
				defer close(peerDone)
				test.peer(peer, ready)
			}()
			done := make(chan error, 1)
			go func() {
				connection, err := proxy.dialTunnel(ctx, mustTarget(t, "tcp:service.example:443"))
				if connection != nil {
					_ = connection.Close()
				}
				done <- err
			}()
			<-ready
			cancel()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("canceled upstream CONNECT handshake succeeded")
				}
			case <-time.After(300 * time.Millisecond):
				_ = peer.Close()
				err := <-done
				t.Fatalf("cancellation did not unblock upstream CONNECT handshake (cleanup error %v)", err)
			}
			_ = peer.Close()
			select {
			case <-peerDone:
			case <-time.After(time.Second):
				t.Fatal("upstream peer goroutine survived canceled handshake")
			}
		})
	}
}

func TestUpstreamCONNECTHandshakeTimeoutAndSuccessfulDeadlineClear(t *testing.T) {
	t.Run("silent upstream times out and closes socket", func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()
		route, err := NewUpstreamEgressRoute("http://proxy.example:8080", false)
		if err != nil {
			t.Fatal(err)
		}
		route.dial = func(context.Context, string, string) (net.Conn, error) { return client, nil }
		proxy := &egressProxy{route: route, connectHandshakeTimeout: 30 * time.Millisecond}
		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			request, readErr := http.ReadRequest(bufio.NewReader(peer))
			if readErr == nil {
				_ = request.Body.Close()
			}
			_, _ = io.Copy(io.Discard, peer)
		}()
		started := time.Now()
		connection, err := proxy.dialTunnel(context.Background(), mustTarget(t, "tcp:timeout.example:443"))
		if connection != nil {
			_ = connection.Close()
		}
		if err == nil {
			t.Fatal("silent upstream CONNECT handshake succeeded")
		}
		if elapsed := time.Since(started); elapsed > time.Second {
			t.Fatalf("upstream CONNECT timeout took %v", elapsed)
		}
		select {
		case <-peerDone:
		case <-time.After(time.Second):
			t.Fatal("timed-out upstream socket remained open")
		}
	})

	t.Run("complete 200 clears deadline and cancellation retains ownership", func(t *testing.T) {
		client, peer := net.Pipe()
		defer peer.Close()
		route, err := NewUpstreamEgressRoute("http://proxy.example:8080", false)
		if err != nil {
			t.Fatal(err)
		}
		route.dial = func(context.Context, string, string) (net.Conn, error) { return client, nil }
		const handshakeTimeout = 25 * time.Millisecond
		proxy := &egressProxy{route: route, connectHandshakeTimeout: handshakeTimeout}
		peerDone := make(chan struct{})
		go func() {
			defer close(peerDone)
			request, readErr := http.ReadRequest(bufio.NewReader(peer))
			if readErr != nil {
				return
			}
			_ = request.Body.Close()
			if _, writeErr := io.WriteString(peer, "HTTP/1.1 200 Connection Established\r\n\r\n"); writeErr != nil {
				return
			}
			buffer := make([]byte, 4)
			if _, readErr := io.ReadFull(peer, buffer); readErr != nil {
				return
			}
			_, _ = peer.Write([]byte("pong"))
			_, _ = io.Copy(io.Discard, peer)
		}()
		ctx, cancel := context.WithCancel(context.Background())
		connection, err := proxy.dialTunnel(ctx, mustTarget(t, "tcp:success.example:443"))
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		time.Sleep(2 * handshakeTimeout)
		if _, err := connection.Write([]byte("ping")); err != nil {
			cancel()
			t.Fatalf("post-handshake write retained deadline: %v", err)
		}
		response := make([]byte, 4)
		if _, err := io.ReadFull(connection, response); err != nil || string(response) != "pong" {
			cancel()
			t.Fatalf("post-handshake response = %q, %v", response, err)
		}
		cancel()
		_ = connection.SetDeadline(time.Now().Add(time.Second))
		if _, err := connection.Read(make([]byte, 1)); err == nil {
			t.Fatal("successful upstream connection survived context cancellation")
		}
		_ = connection.Close()
		select {
		case <-peerDone:
		case <-time.After(time.Second):
			t.Fatal("successful upstream peer survived tunnel teardown")
		}
	})
}

func TestExecutorSetCloseUnblocksSilentUpstreamCONNECT(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var activeSockets atomic.Int32
	upstreamReady := make(chan struct{})
	upstreamDone := make(chan struct{})
	go func() {
		defer close(upstreamDone)
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		activeSockets.Add(1)
		defer func() {
			activeSockets.Add(-1)
			_ = connection.Close()
		}()
		request, readErr := http.ReadRequest(bufio.NewReader(connection))
		if readErr == nil {
			_ = request.Body.Close()
		}
		close(upstreamReady)
		_, _ = io.Copy(io.Discard, connection)
	}()

	route, err := NewUpstreamEgressRoute("http://"+listener.Addr().String(), false)
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	route.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}
	workspace := t.TempDir()
	profile := mustProfile(t, ProfileConfig{
		WorkspaceRoot: workspace, WorkspaceRead: Allow, WorkspaceWrite: Allow,
		HostRead: Allow, HostWrite: Deny, Network: Gated, Command: Allow,
	})
	set, err := NewExecutorSet(profile, WithScratchRoot(t.TempDir()), WithMaxExecutors(1), WithEgressRoute(route),
		withExecutorSetConfig(withBackend(&captureBackend{
			bits: GuaranteeWriteBoundary | GuaranteeNetworkBoundary | GuaranteeTargetNetwork | GuaranteeEnvScrub,
		})))
	if err != nil {
		t.Fatal(err)
	}
	executor, err := set.For("silent-upstream")
	if err != nil {
		t.Fatal(err)
	}
	credential, err := executor.proxy.Authorize("silent-handshake", []NetworkTarget{mustTarget(t, "tcp:service.example:443")})
	if err != nil {
		t.Fatal(err)
	}
	child, err := net.Dial("tcp", executor.proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer child.Close()
	auth := base64.StdEncoding.EncodeToString([]byte("silent-handshake:" + credential))
	_, _ = fmt.Fprintf(child, "CONNECT service.example:443 HTTP/1.1\r\nHost: service.example:443\r\nProxy-Authorization: Basic %s\r\n\r\n", auth)
	<-upstreamReady
	if got := activeSockets.Load(); got != 1 {
		t.Fatalf("active upstream sockets = %d, want 1", got)
	}
	closeDone := make(chan error, 1)
	go func() { closeDone <- set.Close() }()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("ExecutorSet.Close: %v", err)
		}
	case <-time.After(time.Second):
		_ = listener.Close()
		t.Fatal("ExecutorSet.Close did not unblock silent upstream CONNECT")
	}
	select {
	case <-upstreamDone:
	case <-time.After(time.Second):
		t.Fatal("upstream handler/socket survived ExecutorSet.Close")
	}
	if got := activeSockets.Load(); got != 0 {
		t.Fatalf("active upstream sockets after Close = %d, want 0", got)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("upstream dial count = %d, want exactly 1 and no fallback", got)
	}
	_ = child.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.Copy(io.Discard, child); err != nil {
		t.Fatalf("child proxy socket did not reach EOF after ExecutorSet.Close: %v", err)
	}
}

func TestProxyReleaseCancelsActiveForwardRequest(t *testing.T) {
	route, _ := NewDirectEgressRoute()
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("8.8.8.14")}, nil }
	started := make(chan struct{})
	route.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	proxy := newTestProxy(t, route)
	credential, _ := proxy.Authorize("exec-release-http", []NetworkTarget{mustTarget(t, "tcp:release.test:80")})
	done := make(chan struct{}, 1)
	go func() {
		response, _ := proxyClient(t, proxy.URL("exec-release-http", credential)).Get("http://release.test/")
		if response != nil {
			_ = response.Body.Close()
		}
		done <- struct{}{}
	}()
	<-started
	proxy.Release("exec-release-http")
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Release did not cancel active forward request")
	}
}

func TestProxyUpstreamAuthSuccessAndFailureNeverFallsBack(t *testing.T) {
	const username, password = "corp-user", "corp-secret"
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		upstreamHits.Add(1)
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
		if request.Header.Get("Proxy-Authorization") != want {
			http.Error(writer, "auth required", http.StatusProxyAuthRequired)
			return
		}
		_, _ = io.WriteString(writer, "through-upstream")
	}))
	t.Cleanup(upstream.Close)
	upstreamURL, _ := url.Parse(upstream.URL)
	upstreamURL.User = url.UserPassword(username, password)
	route, err := NewUpstreamEgressRoute(upstreamURL.String(), false)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newTestProxy(t, route)
	credential, _ := proxy.Authorize("exec-upstream", []NetworkTarget{mustTarget(t, "tcp:service.test:80")})
	response, err := proxyClient(t, proxy.URL("exec-upstream", credential)).Get("http://service.test/resource")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "through-upstream" || upstreamHits.Load() != 1 {
		t.Fatalf("upstream response = status %d body %q hits %d", response.StatusCode, body, upstreamHits.Load())
	}
	badAuthURL := *upstreamURL
	badAuthURL.User = url.UserPassword(username, "wrong-secret")
	badAuthRoute, _ := NewUpstreamEgressRoute(badAuthURL.String(), false)
	badAuthProxy := newTestProxy(t, badAuthRoute)
	badCredential, _ := badAuthProxy.Authorize("exec-bad-auth", []NetworkTarget{mustTarget(t, "tcp:service.test:80")})
	response, err = proxyClient(t, badAuthProxy.URL("exec-bad-auth", badCredential)).Get("http://service.test/resource")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("upstream auth failure status = %d, want 407 with no direct fallback", response.StatusCode)
	}

	closedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := closedListener.Addr().String()
	_ = closedListener.Close()
	failingRoute, _ := NewUpstreamEgressRoute("http://"+closedAddress, false)
	failing := newTestProxy(t, failingRoute)
	failingCredential, _ := failing.Authorize("exec-fail", []NetworkTarget{mustTarget(t, "tcp:127.0.0.1:80")})
	response, err = proxyClient(t, failing.URL("exec-fail", failingCredential)).Get("http://127.0.0.1/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("failed upstream status = %d, want 502 with no direct fallback", response.StatusCode)
	}
}

func newTestProxy(t *testing.T, route EgressRoute) *egressProxy {
	t.Helper()
	proxy, err := newEgressProxy(route)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = proxy.Close() })
	return proxy
}

func openProxyTunnel(t *testing.T, proxy *egressProxy, executionID, credential, host, port string) (net.Conn, *bufio.Reader) {
	t.Helper()
	connection, err := net.Dial("tcp", proxy.Addr())
	if err != nil {
		t.Fatal(err)
	}
	auth := base64.StdEncoding.EncodeToString([]byte(executionID + ":" + credential))
	_, _ = fmt.Fprintf(connection, "CONNECT %s:%s HTTP/1.1\r\nHost: %s:%s\r\nProxy-Authorization: Basic %s\r\n\r\n", host, port, host, port, auth)
	reader := bufio.NewReader(connection)
	response, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || response.StatusCode != http.StatusOK {
		_ = connection.Close()
		t.Fatalf("CONNECT = %#v, %v", response, err)
	}
	return connection, reader
}

func proxyClient(t *testing.T, rawProxy string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse(rawProxy)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func mustTarget(t *testing.T, raw string) NetworkTarget {
	t.Helper()
	target, err := ParseNetworkTarget(raw)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func newHTTPOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Through-Proxy", "yes")
		_, _ = io.WriteString(w, "origin:"+r.URL.Path)
	}))
	t.Cleanup(server.Close)
	return server
}

func newEchoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	return listener
}
