package sandbox

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

var ErrNetworkTargetDenied = errors.New("sandbox: network target denied")

var errNetworkAddressDenied = errors.New("sandbox: resolved network address denied")

// NetworkTargetDeniedError preserves the completed process result while making
// an authenticated proxy denial the primary typed error.
type NetworkTargetDeniedError struct {
	ExitCode     int
	ProcessError error
	denial       error
}

func (err *NetworkTargetDeniedError) Error() string {
	if err == nil {
		return ErrNetworkTargetDenied.Error()
	}
	return fmt.Sprintf("%v (process exit %d)", err.denial, err.ExitCode)
}

func (err *NetworkTargetDeniedError) Unwrap() error { return ErrNetworkTargetDenied }

const (
	proxyHeaderTimeout = 10 * time.Second
	proxyIdleTimeout   = 30 * time.Second
	proxyMaxHeader     = 64 << 10
)

type proxyAuthorization struct {
	credentialHash [32]byte
	targets        map[string]struct{}
	allowAll       bool
	denial         error
}

type egressProxy struct {
	route      EgressRoute
	listener   net.Listener
	server     *http.Server
	mu         sync.Mutex
	executions map[string]*proxyAuthorization
	tunnels    map[*proxyTunnel]struct{}
	closing    bool
	closeOnce  sync.Once
	closeErr   error
}

type proxyTunnel struct {
	child    net.Conn
	upstream net.Conn
}

func newEgressProxy(route EgressRoute) (*egressProxy, error) {
	if err := route.validate(); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("sandbox: listen for egress proxy: %w", err)
	}
	proxy := &egressProxy{route: route, listener: listener, executions: make(map[string]*proxyAuthorization), tunnels: make(map[*proxyTunnel]struct{})}
	proxy.server = &http.Server{
		Handler: proxy, ReadHeaderTimeout: proxyHeaderTimeout,
		IdleTimeout: proxyIdleTimeout, MaxHeaderBytes: proxyMaxHeader,
	}
	go func() { _ = proxy.server.Serve(listener) }()
	return proxy, nil
}

func (proxy *egressProxy) Addr() string {
	if proxy == nil || proxy.listener == nil {
		return ""
	}
	return proxy.listener.Addr().String()
}

func (proxy *egressProxy) Authorize(executionID string, targets []NetworkTarget) (string, error) {
	if proxy == nil || !validGrantText(executionID) || len(targets) == 0 {
		return "", errors.New("sandbox: invalid proxy authorization")
	}
	return proxy.authorize(executionID, targets, false)
}

func (proxy *egressProxy) authorizeAll(executionID string) (string, error) {
	return proxy.authorize(executionID, nil, true)
}

func (proxy *egressProxy) authorize(executionID string, targets []NetworkTarget, allowAll bool) (string, error) {
	if proxy == nil || !validGrantText(executionID) || (!allowAll && len(targets) == 0) {
		return "", errors.New("sandbox: invalid proxy authorization")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("sandbox: proxy credential: %w", err)
	}
	credential := base64.RawURLEncoding.EncodeToString(secret)
	authorization := &proxyAuthorization{credentialHash: sha256.Sum256([]byte(credential)), targets: make(map[string]struct{}, len(targets)), allowAll: allowAll}
	for _, target := range targets {
		if target.String() == "" {
			return "", errors.New("sandbox: invalid proxy target")
		}
		authorization.targets[target.String()] = struct{}{}
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if proxy.closing || proxy.executions == nil {
		return "", ErrExecutorClosed
	}
	if _, exists := proxy.executions[executionID]; exists {
		return "", errors.New("sandbox: execution already authorized")
	}
	proxy.executions[executionID] = authorization
	return credential, nil
}

func (proxy *egressProxy) URL(executionID, credential string) string {
	if proxy == nil || !validGrantText(executionID) || credential == "" {
		return ""
	}
	return (&url.URL{Scheme: "http", Host: proxy.Addr(), User: url.UserPassword(executionID, credential)}).String()
}

func (proxy *egressProxy) Release(executionID string) {
	if proxy == nil {
		return
	}
	proxy.mu.Lock()
	delete(proxy.executions, executionID)
	proxy.mu.Unlock()
}

func (proxy *egressProxy) Denial(executionID string) error {
	if proxy == nil {
		return nil
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if authorization := proxy.executions[executionID]; authorization != nil {
		return authorization.denial
	}
	return nil
}

func (proxy *egressProxy) authenticate(request *http.Request) (string, *proxyAuthorization, bool) {
	header := request.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if !strings.HasPrefix(header, prefix) {
		return "", nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return "", nil, false
	}
	executionID, credential, ok := strings.Cut(string(decoded), ":")
	if !ok || executionID == "" || credential == "" {
		return "", nil, false
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	authorization := proxy.executions[executionID]
	gotHash := sha256.Sum256([]byte(credential))
	if authorization == nil || subtle.ConstantTimeCompare(authorization.credentialHash[:], gotHash[:]) != 1 {
		return "", nil, false
	}
	return executionID, authorization, true
}

func (proxy *egressProxy) recordDenial(executionID string, target NetworkTarget) {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if authorization := proxy.executions[executionID]; authorization != nil && authorization.denial == nil {
		authorization.denial = fmt.Errorf("%w: %s", ErrNetworkTargetDenied, target.String())
	}
}

func (proxy *egressProxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	executionID, authorization, authenticated := proxy.authenticate(request)
	if !authenticated {
		writer.Header().Set("Proxy-Authenticate", `Basic realm="sandbox"`)
		http.Error(writer, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	target, err := targetForRequest(request)
	if err != nil {
		proxy.recordDenial(executionID, NetworkTarget{transport: "tcp", host: "invalid", port: 1})
		http.Error(writer, "network target denied", http.StatusForbidden)
		return
	}
	if _, allowed := authorization.targets[target.String()]; !allowed && !authorization.allowAll {
		proxy.recordDenial(executionID, target)
		http.Error(writer, "network target denied", http.StatusForbidden)
		return
	}
	request.Header.Del("Proxy-Authorization")
	if request.Method == http.MethodConnect {
		proxy.serveConnect(writer, request, executionID, target)
		return
	}
	proxy.serveHTTP(writer, request, executionID, target)
}

func targetForRequest(request *http.Request) (NetworkTarget, error) {
	address := request.Host
	if request.Method != http.MethodConnect {
		if request.URL == nil || !request.URL.IsAbs() || request.URL.Scheme != "http" {
			return NetworkTarget{}, errors.New("sandbox: proxy requires an absolute HTTP URL")
		}
		address = request.URL.Host
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		if request.Method != http.MethodConnect && !strings.Contains(address, ":") {
			host, port = address, "80"
		} else {
			return NetworkTarget{}, err
		}
	}
	return ParseNetworkTarget("tcp:" + net.JoinHostPort(host, port))
}

func (proxy *egressProxy) serveHTTP(writer http.ResponseWriter, request *http.Request, executionID string, target NetworkTarget) {
	outbound := request.Clone(request.Context())
	outbound.RequestURI = ""
	outbound.Header = request.Header.Clone()
	removeHopHeaders(outbound.Header)
	transport := &http.Transport{DisableKeepAlives: false, IdleConnTimeout: proxyIdleTimeout}
	if proxy.route.kind == routeDirect {
		transport.Proxy = nil
		transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
			return proxy.route.dialTarget(ctx, target)
		}
	} else {
		transport.Proxy = http.ProxyURL(proxy.route.upstream)
		transport.DialContext = proxy.route.dial
	}
	defer transport.CloseIdleConnections()
	response, err := transport.RoundTrip(outbound)
	if err != nil {
		if errors.Is(err, errNetworkAddressDenied) {
			proxy.recordDenial(executionID, target)
		}
		http.Error(writer, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer response.Body.Close()
	removeHopHeaders(response.Header)
	for key, values := range response.Header {
		for _, value := range values {
			writer.Header().Add(key, value)
		}
	}
	writer.WriteHeader(response.StatusCode)
	_, _ = io.Copy(writer, response.Body)
}

func (proxy *egressProxy) serveConnect(writer http.ResponseWriter, request *http.Request, executionID string, target NetworkTarget) {
	upstream, err := proxy.dialTunnel(request.Context(), target)
	if err != nil {
		if errors.Is(err, errNetworkAddressDenied) {
			proxy.recordDenial(executionID, target)
		}
		http.Error(writer, "upstream unavailable", http.StatusBadGateway)
		return
	}
	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = upstream.Close()
		http.Error(writer, "tunneling unsupported", http.StatusInternalServerError)
		return
	}
	child, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil || buffered.Flush() != nil {
		_ = child.Close()
		_ = upstream.Close()
		return
	}
	pair := &proxyTunnel{child: &idleTimeoutConn{Conn: child, timeout: proxyIdleTimeout}, upstream: &idleTimeoutConn{Conn: upstream, timeout: proxyIdleTimeout}}
	proxy.mu.Lock()
	if proxy.closing {
		proxy.mu.Unlock()
		_ = pair.child.Close()
		_ = pair.upstream.Close()
		return
	}
	proxy.tunnels[pair] = struct{}{}
	proxy.mu.Unlock()
	tunnel(pair.child, pair.upstream)
	proxy.mu.Lock()
	delete(proxy.tunnels, pair)
	proxy.mu.Unlock()
}

func (proxy *egressProxy) dialTunnel(ctx context.Context, target NetworkTarget) (net.Conn, error) {
	if proxy.route.kind == routeDirect {
		return proxy.route.dialTarget(ctx, target)
	}
	upstream, err := proxy.route.dialUpstream(ctx)
	if err != nil {
		return nil, err
	}
	request := &http.Request{Method: http.MethodConnect, URL: &url.URL{Opaque: target.address()}, Host: target.address(), Header: make(http.Header)}
	if proxy.route.upstream.User != nil {
		username := proxy.route.upstream.User.Username()
		password, _ := proxy.route.upstream.User.Password()
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(username+":"+password)))
	}
	if err := request.Write(upstream); err != nil {
		_ = upstream.Close()
		return nil, err
	}
	response, err := http.ReadResponse(bufio.NewReader(upstream), request)
	if err != nil {
		_ = upstream.Close()
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		_ = upstream.Close()
		return nil, errors.New("sandbox: upstream proxy rejected CONNECT")
	}
	return upstream, nil
}

type idleTimeoutConn struct {
	net.Conn
	timeout time.Duration
}

func (connection *idleTimeoutConn) Read(buffer []byte) (int, error) {
	_ = connection.SetReadDeadline(time.Now().Add(connection.timeout))
	return connection.Conn.Read(buffer)
}

func (connection *idleTimeoutConn) Write(buffer []byte) (int, error) {
	_ = connection.SetWriteDeadline(time.Now().Add(connection.timeout))
	return connection.Conn.Write(buffer)
}

func (route EgressRoute) dialTarget(ctx context.Context, target NetworkTarget) (net.Conn, error) {
	addresses, err := route.lookup(ctx, target.host)
	if err != nil || len(addresses) == 0 {
		return nil, errors.New("sandbox: target resolution failed")
	}
	for _, address := range addresses {
		if !publicDestination(address) {
			return nil, errNetworkAddressDenied
		}
	}
	var lastErr error
	for _, address := range addresses {
		connection, err := route.dial(ctx, "tcp", net.JoinHostPort(address.String(), fmt.Sprint(target.port)))
		if err == nil {
			return connection, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("sandbox: target connection failed: %w", lastErr)
}

func publicDestination(ip net.IP) bool {
	return ip != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsPrivate() &&
		!ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast() && !ip.IsMulticast()
}

func (route EgressRoute) dialUpstream(ctx context.Context) (net.Conn, error) {
	connection, err := route.dial(ctx, "tcp", route.upstream.Host)
	if err != nil {
		return nil, errors.New("sandbox: upstream proxy unavailable")
	}
	if route.upstream.Scheme == "https" {
		tlsConnection := tls.Client(connection, &tls.Config{ServerName: route.upstream.Hostname(), MinVersion: tls.VersionTLS12})
		if err := tlsConnection.HandshakeContext(ctx); err != nil {
			_ = connection.Close()
			return nil, errors.New("sandbox: upstream proxy TLS failed")
		}
		return tlsConnection, nil
	}
	return connection, nil
}

func removeHopHeaders(header http.Header) {
	for _, value := range header.Values("Connection") {
		for _, token := range strings.Split(value, ",") {
			header.Del(strings.TrimSpace(token))
		}
	}
	for _, name := range []string{"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
		header.Del(name)
	}
}

func tunnel(left, right net.Conn) {
	var wait sync.WaitGroup
	wait.Add(2)
	copyHalf := func(dst, src net.Conn) {
		defer wait.Done()
		_, _ = io.Copy(dst, src)
		if closer, ok := dst.(interface{ CloseWrite() error }); ok {
			_ = closer.CloseWrite()
		}
	}
	go copyHalf(right, left)
	go copyHalf(left, right)
	wait.Wait()
	_ = left.Close()
	_ = right.Close()
}

func (proxy *egressProxy) Close() error {
	if proxy == nil {
		return nil
	}
	proxy.closeOnce.Do(func() {
		proxy.mu.Lock()
		proxy.closing = true
		for pair := range proxy.tunnels {
			_ = pair.child.Close()
			_ = pair.upstream.Close()
		}
		proxy.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), proxyHeaderTimeout)
		defer cancel()
		proxy.closeErr = proxy.server.Shutdown(ctx)
		if proxy.closeErr == nil {
			proxy.closeErr = proxy.listener.Close()
			if errors.Is(proxy.closeErr, net.ErrClosed) {
				proxy.closeErr = nil
			}
		}
		proxy.mu.Lock()
		proxy.executions = nil
		proxy.mu.Unlock()
	})
	return proxy.closeErr
}
