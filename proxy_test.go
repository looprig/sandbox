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
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.10")}, nil }
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

func TestProxyCONNECTIsByteTunnelWithoutTLSTermination(t *testing.T) {
	echo := newEchoServer(t)
	_, port, _ := net.SplitHostPort(echo.Addr().String())
	route, _ := NewDirectEgressRoute()
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.8")}, nil }
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
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("198.51.100.9")}, nil }
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

func TestProxyIgnoresNOProxyAndCleansUp(t *testing.T) {
	t.Setenv("NO_PROXY", "*")
	origin := newHTTPOrigin(t)
	_, port, _ := net.SplitHostPort(origin.Listener.Addr().String())
	route, _ := NewDirectEgressRoute()
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.11")}, nil }
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
	route.lookup = func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.12")}, nil }
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
